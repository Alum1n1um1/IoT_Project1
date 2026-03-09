import os
from datetime import datetime
from typing import Any, Dict, List

from flask import Flask, jsonify, request

from camera_sync import sync_cameras_intel
from db import Database


app = Flask(__name__)


def _severity_from_cvss(cvss_score: float | None) -> str:
    score = float(cvss_score or 0.0)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _get_criticality_multiplier(criticity: str) -> float:
    criticity = criticity.lower()
    if criticity == "low":
        return 0.5
    elif criticity == "medium":
        return 1.0
    elif criticity == "high":
        return 1.5
    elif criticity == "critical":
        return 2.0
    return 1.0


def _extract_description(descriptions: Any) -> str:
    if isinstance(descriptions, list) and descriptions:
        first = descriptions[0]
        if isinstance(first, dict):
            value = first.get("value")
            if isinstance(value, str):
                return value
    return "No description"


def _normalize_camera_ids(payload: Dict[str, Any], db: Database, user_id: int) -> List[int]:
    raw_ids = payload.get("camera_ids")

    if raw_ids is None:
        user_cameras = db.list_user_cameras(user_id=user_id)
        return [int(c["id"]) for c in user_cameras if c.get("id") is not None]

    if not isinstance(raw_ids, list) or not raw_ids:
        raise ValueError("camera_ids must be a non-empty list")

    camera_ids: List[int] = []
    for raw_id in raw_ids:
        camera_id = int(raw_id)
        if camera_id <= 0:
            raise ValueError("camera_ids must contain positive integers")
        camera_ids.append(camera_id)

    # Keep order but remove duplicates.
    seen = set()
    deduped: List[int] = []
    for camera_id in camera_ids:
        if camera_id not in seen:
            deduped.append(camera_id)
            seen.add(camera_id)

    return deduped


@app.get("/health")
def healthcheck():
    return jsonify({"status": "ok"})


@app.post("/api/v1/sync")
def sync_camera_intelligence():
    db = None
    try:
        payload = request.get_json(silent=True) or {}
        user_id = int(payload.get("user_id", 1))
        max_results = int(payload.get("max_results", 100))
        if max_results <= 0:
            return jsonify({"success": False, "error": "max_results must be > 0"}), 400

        db = Database()
        camera_ids = _normalize_camera_ids(payload, db=db, user_id=user_id)
        if not camera_ids:
            return jsonify({
                "success": True,
                "requested": 0,
                "succeeded": 0,
                "failed": 0,
                "results": [],
                "message": "No cameras found for the requested user",
            })

        result = sync_cameras_intel(db, camera_ids=camera_ids, max_results=max_results)

        return jsonify({"success": True, **result})
    except ValueError as error:
        return jsonify({"success": False, "error": str(error)}), 400
    except Exception as error:  # pragma: no cover
        return jsonify({"success": False, "error": str(error)}), 500
    finally:
        if db is not None:
            db.close()


@app.get("/api/v1/threats/summary")
def get_threats_summary():
    db = None
    try:
        user_id = int(request.args.get("user_id", "1"))
        db = Database()
        rows = db.query(
            """
            SELECT
                cve_id,
                published,
                descriptions,
                cvss_score,
                criticity
            FROM (
                SELECT DISTINCT ON (c.id)
                    c.id AS cve_id,
                    c.published,
                    c.descriptions,
                    cam.criticity,
                    COALESCE(
                        NULLIF(c.metrics->'cvssV3'->>'baseScore', '')::float,
                        NULLIF(c.metrics->'cvssV2'->>'baseScore', '')::float,
                        NULLIF(c.metrics->>'cvssScore', '')::float,
                        0
                    ) AS cvss_score
                FROM user_cameras uc
                INNER JOIN cameras cam ON cam.id = uc.camera_id
                INNER JOIN camera_cves cc ON cc.camera_id = uc.camera_id
                INNER JOIN cves c ON c.id = cc.cve_id
                WHERE uc.user_id = %s
                ORDER BY c.id, c.published DESC NULLS LAST
            ) q
            ORDER BY published DESC NULLS LAST
            """,
            (user_id,),
        )

        # Calculate adjusted scores
        adjusted_scores = []
        for row in rows:
            cvss = float(row.get("cvss_score") or 0.0)
            if cvss > 0:
                criticity = row.get("criticity", "medium")
                multiplier = _get_criticality_multiplier(criticity)
                adjusted_scores.append(cvss * multiplier)
        
        vulnerability_score = int(round((sum(adjusted_scores) / len(adjusted_scores)) * 10)) if adjusted_scores else 0

        recent = []
        for row in rows[:4]:
            cve_id = row.get("cve_id")
            if not cve_id:
                continue
            desc = _extract_description(row.get("descriptions"))[:120]
            recent.append({
                "id": cve_id,
                "type": "CVE",
                "description": f"{cve_id}: {desc}",
                "severity": _severity_from_cvss(row.get("cvss_score")),
                "timestamp": row.get("published") or "",
                "source": "NVD",
            })

        active_threats = sum(1 for r in rows if float(r.get("cvss_score") or 0.0) >= 9.0)
        return jsonify(
            {
                "activeThreats": active_threats,
                "vulnerabilityScore": max(0, min(100, vulnerability_score)),
                "recentThreats": recent,
            }
        )
    except Exception as error:  # pragma: no cover
        return jsonify({"error": str(error)}), 500
    finally:
        if db is not None:
            db.close()


@app.get("/api/v1/devices/status")
def get_devices_status():
    db = None
    try:
        user_id = int(request.args.get("user_id", "1"))
        db = Database()
        cameras = db.list_user_cameras(user_id=user_id)

        devices = []
        for cam in cameras:
            camera_id = int(cam["id"])
            vulns = db.get_camera_vulnerabilities(camera_id)

            scores = [float(v.get("cvss_score") or 0.0) for v in vulns if float(v.get("cvss_score") or 0.0) > 0]
            avg_cvss = (sum(scores) / len(scores)) if scores else 0.0
            
            # Apply criticality coefficient
            criticity = cam.get("criticity", "medium")
            multiplier = _get_criticality_multiplier(criticity)
            adjusted_avg_cvss = avg_cvss * multiplier
            
            critical_count = sum(1 for v in vulns if float(v.get("cvss_score") or 0.0) >= 9.0)
            high_count = sum(1 for v in vulns if 7.0 <= float(v.get("cvss_score") or 0.0) < 9.0)
            medium_count = sum(1 for v in vulns if 4.0 <= float(v.get("cvss_score") or 0.0) < 7.0)

            if adjusted_avg_cvss >= 9.0:
                status = "vulnerable"
            elif adjusted_avg_cvss >= 7.0 or criticity == "critical":
                status = "warning"
            else:
                status = "secure"

            devices.append(
                {
                    "id": str(camera_id),
                    "name": cam.get("user_nickname") or f"{cam.get('vendor', '')} {cam.get('product', '')}".strip(),
                    "type": "Caméra de Sécurité",
                    "status": status,
                    "lastSeen": "2 minutes",
                    "ipAddress": f"192.168.1.{camera_id + 100}",
                    "manufacturer": cam.get("vendor") or "Unknown",
                    "vulnerabilities": {
                        "cves": vulns,
                        "cwes": [],
                        "kves": [
                            {
                                "cveId": v.get("cve_id"),
                                "source": "CISA KEV",
                                "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cve_id')}",
                                "title": f"Known Exploit: {v.get('cve_id')}",
                            }
                            for v in vulns
                            if bool(v.get("kev_ransomware"))
                        ],
                        "cvssScore": round(avg_cvss, 2),  # Keep original CVSS score (0-10)
                        "criticalCount": critical_count,
                        "highCount": high_count,
                        "mediumCount": medium_count,
                        "lastUpdated": datetime.utcnow().isoformat() + "Z",
                    },
                }
            )

        return jsonify(
            {
                "totalDevices": len(devices),
                "secureDevices": sum(1 for d in devices if d["status"] == "secure"),
                "vulnerableDevices": sum(1 for d in devices if d["status"] == "vulnerable"),
                "devices": devices,
            }
        )
    except Exception as error:  # pragma: no cover
        return jsonify({"error": str(error)}), 500
    finally:
        if db is not None:
            db.close()


@app.get("/api/v1/threats")
def get_all_threats():
    db = None
    try:
        user_id = int(request.args.get("user_id", "1"))
        db = Database()
        rows = db.query(
            """
            SELECT
                cve_id,
                published,
                descriptions,
                cvss_score
            FROM (
                SELECT DISTINCT ON (c.id)
                    c.id AS cve_id,
                    c.published,
                    c.descriptions,
                    COALESCE(
                        NULLIF(c.metrics->'cvssV3'->>'baseScore', '')::float,
                        NULLIF(c.metrics->'cvssV2'->>'baseScore', '')::float,
                        NULLIF(c.metrics->>'cvssScore', '')::float,
                        0
                    ) AS cvss_score
                FROM user_cameras uc
                INNER JOIN camera_cves cc ON cc.camera_id = uc.camera_id
                INNER JOIN cves c ON c.id = cc.cve_id
                WHERE uc.user_id = %s
                ORDER BY c.id, c.published DESC NULLS LAST
            ) q
            ORDER BY published DESC NULLS LAST
            LIMIT 100
            """,
            (user_id,),
        )

        threats = []
        for row in rows:
            cve_id = row.get("cve_id")
            if not cve_id:
                continue
            desc = _extract_description(row.get("descriptions"))[:200]
            threats.append(
                {
                    "id": cve_id,
                    "type": "CVE",
                    "description": f"{cve_id}: {desc}",
                    "severity": _severity_from_cvss(row.get("cvss_score")),
                    "timestamp": row.get("published") or "",
                    "source": "NVD",
                }
            )

        return jsonify(threats)
    except Exception as error:  # pragma: no cover
        return jsonify({"error": str(error)}), 500
    finally:
        if db is not None:
            db.close()


@app.get("/api/v1/alerts")
def get_security_alerts():
    db = None
    try:
        user_id = int(request.args.get("user_id", "1"))
        db = Database()
        rows = db.query(
            """
            SELECT
                uc.camera_id,
                c.id AS cve_id,
                c.published,
                c.descriptions,
                COALESCE(
                    NULLIF(c.metrics->'cvssV3'->>'baseScore', '')::float,
                    NULLIF(c.metrics->'cvssV2'->>'baseScore', '')::float,
                    NULLIF(c.metrics->>'cvssScore', '')::float,
                    0
                ) AS cvss_score
            FROM user_cameras uc
            INNER JOIN camera_cves cc ON cc.camera_id = uc.camera_id
            INNER JOIN cves c ON c.id = cc.cve_id
            WHERE uc.user_id = %s
              AND COALESCE(
                    NULLIF(c.metrics->'cvssV3'->>'baseScore', '')::float,
                    NULLIF(c.metrics->'cvssV2'->>'baseScore', '')::float,
                    NULLIF(c.metrics->>'cvssScore', '')::float,
                    0
                ) >= 7
            ORDER BY cvss_score DESC, c.published DESC NULLS LAST
            LIMIT 20
            """,
            (user_id,),
        )

        alerts = []
        for idx, row in enumerate(rows):
            cve_id = row.get("cve_id")
            camera_id = row.get("camera_id")
            if not cve_id or camera_id is None:
                continue

            severity = _severity_from_cvss(row.get("cvss_score"))
            description = _extract_description(row.get("descriptions"))[:180]
            alerts.append(
                {
                    "id": f"alert-{idx + 1:03d}",
                    "title": f"{severity.upper()} vulnerability detected ({cve_id})",
                    "description": description,
                    "severity": severity,
                    "category": "device",
                    "affectedDevices": [str(camera_id)],
                    "timestamp": row.get("published") or "",
                    "resolved": False,
                }
            )

        return jsonify(alerts)
    except Exception as error:  # pragma: no cover
        return jsonify({"error": str(error)}), 500
    finally:
        if db is not None:
            db.close()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
