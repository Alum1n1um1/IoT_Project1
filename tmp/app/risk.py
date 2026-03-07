from dataclasses import dataclass
from statistics import mean
from typing import List, Tuple

from db import Database


@dataclass
class VulnerabilityRisk:
    cve_id: str
    summary: str | None
    cvss_score: float | None
    cvss_severity: str | None
    epss: float | None
    epss_percentile: float | None
    in_kev: bool
    kev_date_added: str | None
    kev_ransomware: bool
    cwe_ids: List[str]
    risk_score: float
    risk_level: str


@dataclass
class CameraRisk:
    user_camera_id: int
    vendor: str
    product: str
    version: str | None
    nickname: str | None
    vulnerabilities: List[VulnerabilityRisk]
    device_risk_score: float
    device_risk_level: str


@dataclass
class OverallRiskSummary:
    total_devices: int
    total_vulnerabilities: int
    total_kev: int
    avg_device_risk: float
    max_device_risk: float


def _risk_level(score: float) -> str:
    if score >= 80:
        return "CRITIQUE"
    if score >= 60:
        return "ÉLEVÉ"
    if score >= 40:
        return "MOYEN"
    if score > 0:
        return "FAIBLE"
    return "NÉGLIGEABLE"


def compute_cve_risk_from_row(row) -> VulnerabilityRisk:
    cvss_score = row["cvss_score"]
    cvss_norm = float(cvss_score) / 10.0 if cvss_score is not None else 0.0
    epss = float(row["epss_score"]) if row["epss_score"] is not None else 0.0
    percentile = (
        float(row["epss_percentile"]) if row["epss_percentile"] is not None else None
    )

    in_kev = row["kev_date_added"] is not None
    kev_ransomware = bool(row["kev_ransomware"]) if row["kev_ransomware"] else False

    # Pondération simple CVSS / EPSS / KEV
    base = 0.6 * cvss_norm + 0.3 * epss + 0.1 * (1.0 if in_kev else 0.0)
    # Légère majoration si lié à des campagnes ransomwares connues
    if kev_ransomware:
        base *= 1.1

    risk_score = max(0.0, min(100.0, base * 100.0))
    level = _risk_level(risk_score)

    cwe_ids = (
        [c.strip() for c in (row["cwe_ids"] or "").split(",") if c.strip()]
        if row["cwe_ids"] is not None
        else []
    )

    return VulnerabilityRisk(
        cve_id=row["cve_id"],
        summary=row["summary"],
        cvss_score=cvss_score,
        cvss_severity=row["cvss_severity"],
        epss=epss if epss != 0.0 else None,
        epss_percentile=percentile,
        in_kev=in_kev,
        kev_date_added=row["kev_date_added"],
        kev_ransomware=kev_ransomware,
        cwe_ids=cwe_ids,
        risk_score=risk_score,
        risk_level=level,
    )


def _aggregate_device_risk(vulns: List[VulnerabilityRisk]) -> Tuple[float, str]:
    if not vulns:
        return 0.0, _risk_level(0.0)

    scores = sorted((v.risk_score for v in vulns), reverse=True)
    top = scores[:5]
    max_score = top[0]
    avg_top = mean(top)
    device_score = 0.6 * max_score + 0.4 * avg_top
    return device_score, _risk_level(device_score)


def compute_all_risks(db: Database) -> Tuple[List[CameraRisk], OverallRiskSummary]:
    """
    Calcule les risques pour toutes les caméras sélectionnées par l'utilisateur.
    """
    user_cams = db.list_user_cameras()
    camera_risks: List[CameraRisk] = []

    total_vulns = 0
    total_kev = 0

    for row in user_cams:
        cam_id = row["id"]
        vendor = row["vendor"]
        product = row["product"]
        version = row["version"]
        nickname = row["user_nickname"]
        user_camera_id = row["user_camera_id"]

        vuln_rows = db.get_camera_vulnerabilities(cam_id)
        vulns: List[VulnerabilityRisk] = []
        for v in vuln_rows:
            vr = compute_cve_risk_from_row(v)
            vulns.append(vr)
            if vr.in_kev:
                total_kev += 1

        total_vulns += len(vulns)
        device_score, device_level = _aggregate_device_risk(vulns)

        camera_risks.append(
            CameraRisk(
                user_camera_id=user_camera_id,
                vendor=vendor,
                product=product,
                version=version,
                nickname=nickname,
                vulnerabilities=vulns,
                device_risk_score=device_score,
                device_risk_level=device_level,
            )
        )

    if camera_risks:
        avg_device_risk = mean(c.device_risk_score for c in camera_risks)
        max_device_risk = max(c.device_risk_score for c in camera_risks)
    else:
        avg_device_risk = 0.0
        max_device_risk = 0.0

    summary = OverallRiskSummary(
        total_devices=len(camera_risks),
        total_vulnerabilities=total_vulns,
        total_kev=total_kev,
        avg_device_risk=avg_device_risk,
        max_device_risk=max_device_risk,
    )

    return camera_risks, summary


__all__ = [
    "VulnerabilityRisk",
    "CameraRisk",
    "OverallRiskSummary",
    "compute_all_risks",
]

