import os
import time
from typing import Iterable, List, Tuple

import requests

from db import Database


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


# ----------------------------------------------------------------------
# Utilitaires CPE / détection de caméras
# ----------------------------------------------------------------------


def parse_cpe23_uri(cpe_uri: str) -> Tuple[str, str, str, str] | None:
    """
    Parse une URI CPE 2.3 et renvoie (part, vendor, product, version).
    Retourne None si le format n'est pas reconnu.
    """
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return None
    if parts[0] != "cpe" or parts[1] != "2.3":
        return None
    part, vendor, product, version = parts[2], parts[3], parts[4], parts[5]
    return part, vendor, product, version


CAMERA_KEYWORDS = [
    "camera",
    "cam",
    "ipcam",
    "ip-camera",
    "webcam",
]

CAMERA_VENDORS = [
    "hikvision",
    "dahua",
    "axis",
    "reolink",
    "ubiquiti",
    "unifi",
    "tp-link",
    "tp_link",
    "netgear",
]


def looks_like_camera(vendor: str, product: str) -> bool:
    v = vendor.lower()
    p = product.lower()

    if any(vk in v for vk in CAMERA_VENDORS):
        return True
    if any(kw in p for kw in CAMERA_KEYWORDS):
        return True
    if "cam" in p and "camera" not in p:
        return True
    return False


# ----------------------------------------------------------------------
# NVD
# ----------------------------------------------------------------------


def _build_nvd_headers() -> dict:
    headers: dict = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def update_from_nvd(
    db: Database,
    keyword: str = "camera",
    max_pages: int = 3,
    delay_seconds: float = 1.2,
) -> None:
    """
    Récupère des CVE depuis NVD (filtrés par mot-clé) et peupler la base :
    - table cves
    - table cameras (pour les CPE « hardware » identifiés comme caméras)
    - table camera_cves (liaison caméras ↔ CVE)
    """
    headers = _build_nvd_headers()
    start_index = 0
    results_per_page = 200

    for page in range(max_pages):
        params = {
            "keywordSearch": keyword,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        resp = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        vulns: List[dict] = data.get("vulnerabilities", [])
        if not vulns:
            break

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", []) or []
            summary = None
            for d in descriptions:
                if d.get("lang") == "en":
                    summary = d.get("value")
                    break
            if summary is None and descriptions:
                summary = descriptions[0].get("value")

            published = cve.get("published")
            last_modified = cve.get("lastModified")

            metrics = cve.get("metrics", {}) or {}
            cvss_version = None
            cvss_score = None
            cvss_severity = None

            # CVSS v3.1 / v3.0 en priorité
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key)
                if arr:
                    first = arr[0]
                    data_cvss = first.get("cvssData", {})
                    cvss_version = data_cvss.get("version")
                    cvss_score = data_cvss.get("baseScore")
                    cvss_severity = data_cvss.get("baseSeverity") or data_cvss.get(
                        "severity"
                    )
                    break

            weaknesses = cve.get("weaknesses", []) or []
            cwe_ids: List[str] = []
            for w in weaknesses:
                descs = w.get("description", []) or []
                for d in descs:
                    if d.get("lang") == "en":
                        val = d.get("value") or ""
                        if "CWE-" in val:
                            cwe_ids.append(val.strip())

            db.upsert_cve(
                cve_id=cve_id,
                summary=summary,
                published=published,
                last_modified=last_modified,
                cvss_version=cvss_version,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cwe_ids=cwe_ids,
            )

            # CPE → caméras
            configurations = cve.get("configurations", []) or []
            for conf in configurations:
                nodes = conf.get("nodes", []) or []
                for node in nodes:
                    matches = node.get("cpeMatch", []) or []
                    for m in matches:
                        if not m.get("vulnerable", False):
                            continue
                        cpe_uri = m.get("criteria") or m.get("cpe23Uri")
                        if not cpe_uri:
                            continue
                        parsed = parse_cpe23_uri(cpe_uri)
                        if not parsed:
                            continue
                        part, vendor, product, version = parsed
                        if part != "h":
                            # on se concentre sur les équipements (hardware)
                            continue
                        is_cam = looks_like_camera(vendor, product)
                        camera_id = db.upsert_camera(
                            vendor=vendor,
                            product=product,
                            version=version if version != "*" else None,
                            cpe_uri=cpe_uri,
                            is_camera=is_cam,
                        )
                        db.link_camera_cve(camera_id=camera_id, cve_id=cve_id)

        total_results = data.get("totalResults", 0)
        start_index += results_per_page
        if start_index >= total_results:
            break

        time.sleep(delay_seconds)


# ----------------------------------------------------------------------
# CISA KEV
# ----------------------------------------------------------------------


def update_from_kev(db: Database) -> None:
    """
    Récupère le catalogue KEV (CISA) et met à jour la table kev.
    Si un CVE du KEV n'existe pas encore dans cves, on crée une entrée minimale.
    """
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", []) or []

    for v in vulns:
        cve_id = v.get("cveID")
        if not cve_id:
            continue

        # S'assurer qu'une entrée CVE existe
        db.upsert_cve(
            cve_id=cve_id,
            summary=None,
            published=None,
            last_modified=None,
            cvss_version=None,
            cvss_score=None,
            cvss_severity=None,
            cwe_ids=None,
        )

        db.upsert_kev(
            cve_id=cve_id,
            date_added=v.get("dateAdded"),
            due_date=v.get("dueDate"),
            known_ransomware_campaign_use=str(
                v.get("knownRansomwareCampaignUse", "")
            ).lower()
            in {"yes", "true", "1"},
            notes=v.get("notes"),
        )


# ----------------------------------------------------------------------
# FIRST EPSS
# ----------------------------------------------------------------------


def _batched(iterable: Iterable[str], n: int) -> Iterable[List[str]]:
    batch: List[str] = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= n:
            yield batch
            batch = []
    if batch:
        yield batch


def update_epss_for_all_cves(db: Database, batch_size: int = 100) -> None:
    """
    Interroge l'API EPSS pour tous les CVE présents dans la base (par lots).
    """
    # 1. On crée un curseur pour pouvoir exécuter la requête
    with db.conn.cursor() as cur:
        cur.execute("SELECT id FROM cves")
        # 2. On récupère le premier élément de chaque ligne (row[0]) 
        # car cur.fetchall() renvoie une liste de tuples comme [('CVE-2023-123',), ...]
        cve_ids = [row[0] for row in cur.fetchall()]

    if not cve_ids:
        return

    for batch in _batched(cve_ids, batch_size):
        params = {"cve": ",".join(batch)}
        try:
            resp = requests.get(EPSS_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            entries = data.get("data", []) or []
            for e in entries:
                cve_id = e.get("cve")
                if not cve_id:
                    continue
                epss_score = float(e.get("epss")) if e.get("epss") is not None else None
                percentile = (
                    float(e.get("percentile")) if e.get("percentile") is not None else None
                )
                date = e.get("date")
                db.upsert_epss(
                    cve_id=cve_id,
                    epss=epss_score,
                    percentile=percentile,
                    date=date,
                )
        except Exception as err:
            print(f"[ERROR] Failed to fetch EPSS for batch: {err}")

__all__ = [
    "update_from_nvd",
    "update_from_kev",
    "update_epss_for_all_cves",
]


if __name__ == "__main__":
    # Initialize database schema
    db = Database()

    # Load data from NVD, KEV, and EPSS
    print("[NVD] Loading CVEs from NVD v2.0...")
    update_from_nvd(db, keyword="camera", max_pages=3)

    print("[KEV] Loading Known Exploited Vulnerabilities from CISA...")
    update_from_kev(db)

    print("[EPSS] Loading EPSS scores...")
    update_epss_for_all_cves(db)

    print("[OK] Data loading complete!")


