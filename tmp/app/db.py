import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Any, Iterable, List, Optional


class Database:
    """PostgreSQL database wrapper para NVD data loader."""

    def __init__(self, connection_string: str | None = None) -> None:
        if connection_string is None:
            connection_string = os.getenv(
                "DATABASE_URL",
                "postgresql://postgres:password@postgres:5432/iot_security"
            )
        self.conn = psycopg2.connect(connection_string)
        self.conn.autocommit = False

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def init_schema(self) -> None:
        cur = self.conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                source_identifier TEXT,
                published TEXT,
                last_modified TEXT,
                vuln_status TEXT,
                descriptions JSONB,
                metrics JSONB
            );

            CREATE TABLE IF NOT EXISTS cameras (
                id SERIAL PRIMARY KEY,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT,
                cpe_uri TEXT NOT NULL UNIQUE,
                is_camera INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS camera_cves (
                camera_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                PRIMARY KEY (camera_id, cve_id),
                FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE,
                FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS kev (
                cve_id TEXT PRIMARY KEY,
                date_added TEXT,
                due_date TEXT,
                known_ransomware_campaign_use INTEGER,
                notes TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS epss (
                cve_id TEXT PRIMARY KEY,
                epss REAL,
                percentile REAL,
                date TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_cameras_vendor_product
                ON cameras (vendor, product);

            CREATE INDEX IF NOT EXISTS idx_camera_cves_camera
                ON camera_cves (camera_id);
        """)

        self.conn.commit()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def upsert_camera(
        self,
        vendor: str,
        product: str,
        version: Optional[str],
        cpe_uri: str,
        is_camera: bool,
    ) -> int:
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO cameras (vendor, product, version, cpe_uri, is_camera)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT(cpe_uri) DO UPDATE SET
                vendor=EXCLUDED.vendor,
                product=EXCLUDED.product,
                version=EXCLUDED.version,
                is_camera=EXCLUDED.is_camera
            RETURNING id
        """, (vendor, product, version, cpe_uri, int(is_camera)))
        row = cur.fetchone()
        self.conn.commit()
        return int(row[0]) if row else -1

    def upsert_cve(
        self,
        cve_id: str,
        summary: str | None,
        published: str | None,
        last_modified: str | None,
        cvss_version: str | None,
        cvss_score: float | None,
        cvss_severity: str | None,
        cwe_ids: Iterable[str] | None,
    ) -> None:
        import json
        cwe_str = ",".join(sorted(set(cwe_ids))) if cwe_ids else None
        descriptions = json.dumps([{"lang": "en", "value": summary or ""}])
        metrics = json.dumps({
            "cvssVersion": cvss_version,
            "cvssScore": cvss_score,
            "cssseverity": cvss_severity
        })

        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO cves (id, source_identifier, published, last_modified, vuln_status, descriptions, metrics)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(id) DO UPDATE SET
                source_identifier=EXCLUDED.source_identifier,
                published=EXCLUDED.published,
                last_modified=EXCLUDED.last_modified,
                vuln_status=EXCLUDED.vuln_status,
                descriptions=EXCLUDED.descriptions,
                metrics=EXCLUDED.metrics
        """, (cve_id, "NVD", published, last_modified, "Analyzed", descriptions, metrics))
        self.conn.commit()

    def link_camera_cve(self, camera_id: int, cve_id: str) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO camera_cves (camera_id, cve_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (camera_id, cve_id))
        self.conn.commit()

    def upsert_kev(
        self,
        cve_id: str,
        date_added: str | None,
        due_date: str | None,
        known_ransomware_campaign_use: bool | None,
        notes: str | None,
    ) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO kev (cve_id, date_added, due_date, known_ransomware_campaign_use, notes)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT(cve_id) DO UPDATE SET
                date_added=EXCLUDED.date_added,
                due_date=EXCLUDED.due_date,
                known_ransomware_campaign_use=EXCLUDED.known_ransomware_campaign_use,
                notes=EXCLUDED.notes
        """, (cve_id, date_added, due_date, int(known_ransomware_campaign_use or False), notes))
        self.conn.commit()

    def upsert_epss(
        self,
        cve_id: str,
        epss: float | None,
        percentile: float | None,
        date: str | None,
    ) -> None:
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO epss (cve_id, epss, percentile, date)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT(cve_id) DO UPDATE SET
                epss=EXCLUDED.epss,
                percentile=EXCLUDED.percentile,
                date=EXCLUDED.date
        """, (cve_id, epss, percentile, date))
        self.conn.commit()

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def query(self, sql: str, params: tuple = ()) -> List[dict]:
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(sql, params)
        return cur.fetchall()

    def close(self) -> None:
        self.conn.close()


__all__ = ["Database"]


