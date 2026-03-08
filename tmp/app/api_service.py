import os
from typing import Any, Dict, List

from flask import Flask, jsonify, request

from camera_sync import sync_cameras_intel
from db import Database


app = Flask(__name__)


def _normalize_camera_ids(payload: Dict[str, Any]) -> List[int]:
    raw_ids = payload.get("camera_ids")
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
    try:
        payload = request.get_json(silent=True) or {}
        camera_ids = _normalize_camera_ids(payload)
        max_results = int(payload.get("max_results", 100))
        if max_results <= 0:
            return jsonify({"success": False, "error": "max_results must be > 0"}), 400

        db = Database()
        try:
            result = sync_cameras_intel(db, camera_ids=camera_ids, max_results=max_results)
        finally:
            db.close()

        return jsonify({"success": True, **result})
    except ValueError as error:
        return jsonify({"success": False, "error": str(error)}), 400
    except Exception as error:  # pragma: no cover
        return jsonify({"success": False, "error": str(error)}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
