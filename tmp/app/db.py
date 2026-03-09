import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Iterable, List, Optional


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
        self.default_user_id = self._ensure_default_user()

    def _ensure_default_user(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", ("jules",))
        row = cur.fetchone()
        if row:
            self.conn.commit()
            return int(row[0])

        cur.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (%s, %s)
            RETURNING id
            """,
            (
                "jules",
                "$2a$10$OvkJCURzl0kmZ021bT2sHe.Xw.b.K./mc/porUEOU3vrGAYMsUm3S",
            ),
        )
        created = cur.fetchone()
        self.conn.commit()
        return int(created[0])


    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def upsert_camera(
        self,
        vendor: str,
        product: str,
        version: Optional[str],
        cpe_uri: Optional[str],
        is_camera: bool,
        user_id: Optional[int] = None,
        criticity: str = "medium",
    ) -> int:
        effective_user_id = user_id or self.default_user_id
        name = f"{vendor} {product}".strip()

        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO cameras (user_id, name, vendor, product, criticity, version, cpe_uri, is_camera)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cpe_uri) DO UPDATE SET
                name = EXCLUDED.name,
                vendor = EXCLUDED.vendor,
                product = EXCLUDED.product,
                criticity = EXCLUDED.criticity,
                version = EXCLUDED.version,
                is_camera = EXCLUDED.is_camera
            RETURNING id
            """,
            (
                effective_user_id,
                name,
                vendor,
                product,
                criticity,
                version,
                cpe_uri,
                int(is_camera),
            ),
        )
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
        unique_cwe_ids = sorted(set(cwe_ids)) if cwe_ids else []
        descriptions = json.dumps([{"lang": "en", "value": summary or ""}])
        metrics = json.dumps({
            "cvssScore": cvss_score,
            "cvssSeverity": cvss_severity,
            "cvssVersion": cvss_version,
            "cweIds": unique_cwe_ids,
            "cvssV3": {
                "version": cvss_version,
                "baseScore": cvss_score,
                "baseSeverity": cvss_severity,
            } if (cvss_version or "").startswith("3") else None,
            "cvssV2": {
                "version": cvss_version,
                "baseScore": cvss_score,
                "baseSeverity": cvss_severity,
            } if (cvss_version or "").startswith("2") else None,
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

    def upsert_cwe(self, cwe_id: str, name: Optional[str] = None, description: Optional[str] = None) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO cwes (id, name, description)
            VALUES (%s, %s, %s)
            ON CONFLICT(id) DO UPDATE SET
                name = COALESCE(EXCLUDED.name, cwes.name),
                description = COALESCE(EXCLUDED.description, cwes.description)
            """,
            (cwe_id, name, description),
        )
        self.conn.commit()

    def link_camera_cwe(self, camera_id: int, cwe_id: str, cve_id: Optional[str]) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO camera_cwes (camera_id, cwe_id, cve_id)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (camera_id, cwe_id, cve_id),
        )
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

    def link_camera_kev(self, camera_id: int, cve_id: str) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO camera_kev (camera_id, cve_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (camera_id, cve_id),
        )
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

    def get_camera_by_id(self, camera_id: int) -> Optional[dict]:
        rows = self.query(
            """
            SELECT id, user_id, name, vendor, product, version, criticity, cpe_uri, is_camera
            FROM cameras
            WHERE id = %s
            """,
            (camera_id,),
        )
        return rows[0] if rows else None

    def get_cameras_by_ids(self, camera_ids: List[int]) -> List[dict]:
        if not camera_ids:
            return []
        return self.query(
            """
            SELECT id, user_id, name, vendor, product, version, criticity, cpe_uri, is_camera
            FROM cameras
            WHERE id = ANY(%s)
            ORDER BY id ASC
            """,
            (camera_ids,),
        )

    def list_cameras(
        self,
        search: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> List[dict]:
        sql = """
            SELECT id, vendor, product, version, is_camera
            FROM cameras
            WHERE is_camera = 1
        """
        params: List[object] = []

        if search:
            sql += """
                AND (
                    vendor ILIKE %s
                    OR product ILIKE %s
                    OR name ILIKE %s
                )
            """
            like = f"%{search}%"
            params.extend([like, like, like])

        sql += " ORDER BY vendor ASC, product ASC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        return self.query(sql, tuple(params))

    def add_user_camera(
        self,
        camera_id: int,
        nickname: Optional[str] = None,
        user_id: Optional[int] = 1,
    ) -> None:
        effective_user_id = user_id or self.default_user_id
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO user_cameras (user_id, camera_id, nickname)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id, camera_id)
            DO UPDATE SET nickname = EXCLUDED.nickname
            """,
            (effective_user_id, camera_id, nickname),
        )
        self.conn.commit()

    def remove_user_camera(self, user_camera_id: int, user_id: Optional[int] = 1) -> None:
        effective_user_id = user_id or self.default_user_id
        cur = self.conn.cursor()
        cur.execute(
            "DELETE FROM user_cameras WHERE id = %s AND user_id = %s",
            (user_camera_id, effective_user_id),
        )
        self.conn.commit()

    def list_user_cameras(self, user_id: Optional[int] = 1) -> List[dict]:
        effective_user_id = user_id or self.default_user_id
        return self.query(
            """
            SELECT
                c.id,
                uc.id AS user_camera_id,
                c.vendor,
                c.product,
                c.criticity,
                c.version,
                uc.nickname AS user_nickname
            FROM user_cameras uc
            INNER JOIN cameras c ON c.id = uc.camera_id
            WHERE uc.user_id = %s
            ORDER BY uc.created_at DESC
            """,
            (effective_user_id,),
        )

    def get_camera_vulnerabilities(self, camera_id: int) -> List[dict]:
        return self.query(
            """
            SELECT
                c.id AS cve_id,
                COALESCE(c.descriptions->0->>'value', '') AS summary,
                COALESCE(
                    NULLIF(c.metrics->'cvssV3'->>'baseScore', '')::float,
                    NULLIF(c.metrics->'cvssV2'->>'baseScore', '')::float,
                    NULLIF(c.metrics->>'cvssScore', '')::float
                ) AS cvss_score,
                COALESCE(
                    c.metrics->'cvssV3'->>'baseSeverity',
                    c.metrics->'cvssV2'->>'baseSeverity',
                    c.metrics->>'cvssSeverity'
                ) AS cvss_severity,
                e.epss AS epss_score,
                e.percentile AS epss_percentile,
                k.date_added AS kev_date_added,
                k.known_ransomware_campaign_use AS kev_ransomware,
                COALESCE(
                    string_agg(DISTINCT ccw.cwe_id, ','),
                    ''
                ) AS cwe_ids
            FROM camera_cves cc
            INNER JOIN cves c ON c.id = cc.cve_id
            LEFT JOIN kev k ON k.cve_id = c.id
            LEFT JOIN epss e ON e.cve_id = c.id
            LEFT JOIN camera_cwes ccw ON ccw.camera_id = cc.camera_id AND ccw.cve_id = c.id
            WHERE cc.camera_id = %s
            GROUP BY
                c.id,
                c.descriptions,
                c.metrics,
                e.epss,
                e.percentile,
                k.date_added,
                k.known_ransomware_campaign_use
            ORDER BY cvss_score DESC NULLS LAST, c.id ASC
            """,
            (camera_id,),
        )

    def query(self, sql: str, params: tuple = ()) -> List[dict]:
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(sql, params)
        return cur.fetchall()

    def close(self) -> None:
        self.conn.close()


__all__ = ["Database"]


