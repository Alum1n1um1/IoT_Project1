import os
from typing import Any, Dict, List, Optional, Set

import requests

from db import Database


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _build_nvd_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _extract_cwe_ids(cve_payload: Dict[str, Any]) -> List[str]:
    cwe_ids: Set[str] = set()
    for weakness in cve_payload.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = (desc.get("value") or "").strip()
            if value.startswith("CWE-"):
                cwe_ids.add(value)
    return sorted(cwe_ids)


def _parse_cve(cve_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cve_id = cve_payload.get("id")
    if not cve_id:
        return None

    descriptions = cve_payload.get("descriptions", []) or []
    summary = None
    for desc in descriptions:
        if desc.get("lang") == "en":
            summary = desc.get("value")
            break
    if summary is None and descriptions:
        summary = descriptions[0].get("value")

    published = cve_payload.get("published")
    last_modified = cve_payload.get("lastModified")

    cvss_version = None
    cvss_score = None
    cvss_severity = None
    metrics = cve_payload.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_rows = metrics.get(key)
        if metric_rows:
            data_cvss = metric_rows[0].get("cvssData", {})
            cvss_version = data_cvss.get("version")
            cvss_score = data_cvss.get("baseScore")
            cvss_severity = data_cvss.get("baseSeverity") or data_cvss.get("severity")
            break

    return {
        "cve_id": cve_id,
        "summary": summary,
        "published": published,
        "last_modified": last_modified,
        "cvss_version": cvss_version,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe_ids": _extract_cwe_ids(cve_payload),
    }


def search_cves_for_camera(vendor: str, product: str, max_results: int = 100) -> List[Dict[str, Any]]:
    headers = _build_nvd_headers()
    strategies = [
        f'"{vendor}" "{product}"',
        f"{vendor} {product}",
        vendor,
    ]

    parsed_results: Dict[str, Dict[str, Any]] = {}

    for keyword in strategies:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 200),
        }
        resp = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("vulnerabilities", []) or []:
            parsed = _parse_cve(item.get("cve", {}))
            if parsed:
                parsed_results[parsed["cve_id"]] = parsed

        if len(parsed_results) >= max_results:
            break

    return list(parsed_results.values())[:max_results]


def _load_kev_index() -> Dict[str, Dict[str, Any]]:
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    by_cve: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("vulnerabilities", []) or []:
        cve_id = entry.get("cveID")
        if cve_id:
            by_cve[cve_id] = entry
    return by_cve


def _update_epss_for_cves(db: Database, cve_ids: List[str], batch_size: int = 100) -> int:
    if not cve_ids:
        return 0

    updated = 0
    for start in range(0, len(cve_ids), batch_size):
        batch = cve_ids[start : start + batch_size]
        params = {"cve": ",".join(batch)}
        resp = requests.get(EPSS_URL, params=params, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        for entry in payload.get("data", []) or []:
            cve_id = entry.get("cve")
            if not cve_id:
                continue
            epss_value = float(entry.get("epss")) if entry.get("epss") is not None else None
            percentile = (
                float(entry.get("percentile")) if entry.get("percentile") is not None else None
            )
            db.upsert_epss(cve_id=cve_id, epss=epss_value, percentile=percentile, date=entry.get("date"))
            updated += 1

    return updated


def sync_camera_intel(
    db: Database,
    camera_id: int,
    max_results: int = 100,
    kev_index: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    camera = db.get_camera_by_id(camera_id)
    if not camera:
        return {
            "camera_id": camera_id,
            "success": False,
            "error": "camera-not-found",
        }

    cves = search_cves_for_camera(camera["vendor"], camera["product"], max_results=max_results)

    linked_cves = 0
    linked_cwes = 0
    cve_ids: List[str] = []

    for cve in cves:
        cve_id = cve["cve_id"]
        cve_ids.append(cve_id)

        db.upsert_cve(
            cve_id=cve_id,
            summary=cve.get("summary"),
            published=cve.get("published"),
            last_modified=cve.get("last_modified"),
            cvss_version=cve.get("cvss_version"),
            cvss_score=cve.get("cvss_score"),
            cvss_severity=cve.get("cvss_severity"),
            cwe_ids=cve.get("cwe_ids") or [],
        )
        db.link_camera_cve(camera_id=camera_id, cve_id=cve_id)
        linked_cves += 1

        for cwe_id in cve.get("cwe_ids") or []:
            db.upsert_cwe(cwe_id)
            db.link_camera_cwe(camera_id=camera_id, cwe_id=cwe_id, cve_id=cve_id)
            linked_cwes += 1

    kev_data = kev_index if kev_index is not None else _load_kev_index()
    linked_kev = 0
    for cve_id in cve_ids:
        kev_entry = kev_data.get(cve_id)
        if not kev_entry:
            continue

        db.upsert_kev(
            cve_id=cve_id,
            date_added=kev_entry.get("dateAdded"),
            due_date=kev_entry.get("dueDate"),
            known_ransomware_campaign_use=str(kev_entry.get("knownRansomwareCampaignUse", "")).lower()
            in {"yes", "true", "1"},
            notes=kev_entry.get("notes"),
        )
        db.link_camera_kev(camera_id=camera_id, cve_id=cve_id)
        linked_kev += 1

    epss_updated = _update_epss_for_cves(db, cve_ids)

    return {
        "camera_id": camera_id,
        "success": True,
        "camera": {
            "vendor": camera["vendor"],
            "product": camera["product"],
        },
        "stats": {
            "cves_found": len(cves),
            "camera_cves_linked": linked_cves,
            "camera_cwes_linked": linked_cwes,
            "camera_kev_linked": linked_kev,
            "epss_updated": epss_updated,
        },
    }


def sync_cameras_intel(db: Database, camera_ids: List[int], max_results: int = 100) -> Dict[str, Any]:
    kev_index = _load_kev_index()
    results: List[Dict[str, Any]] = []

    for camera_id in camera_ids:
        results.append(
            sync_camera_intel(
                db=db,
                camera_id=camera_id,
                max_results=max_results,
                kev_index=kev_index,
            )
        )

    success_count = sum(1 for result in results if result.get("success"))
    return {
        "requested": len(camera_ids),
        "succeeded": success_count,
        "failed": len(camera_ids) - success_count,
        "results": results,
    }
