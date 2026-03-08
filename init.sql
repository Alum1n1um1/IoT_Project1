CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY,
    source_identifier TEXT,
    published TEXT,
    last_modified TEXT,
    vuln_status TEXT,
    descriptions JSONB,
    metrics JSONB
);

-- Unified camera model used by both Next.js and Python services.
CREATE TABLE IF NOT EXISTS cameras (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    vendor VARCHAR(50) NOT NULL,
    product VARCHAR(100) NOT NULL,
    criticity VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (criticity IN ('low', 'medium', 'high', 'critical')),
    version TEXT,
    cpe_uri TEXT UNIQUE,
    is_camera INTEGER NOT NULL DEFAULT 1 CHECK (is_camera IN (0, 1)),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_cameras (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    camera_id INTEGER NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
    nickname TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, camera_id)
);

CREATE TABLE IF NOT EXISTS camera_cves (
    camera_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (camera_id, cve_id),
    FOREIGN KEY (camera_id) REFERENCES cameras (id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES cves (id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY,
    date_added TEXT,
    due_date TEXT,
    known_ransomware_campaign_use INTEGER,
    notes TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cwes (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id TEXT PRIMARY KEY,
    epss REAL,
    percentile REAL,
    date TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS camera_kev (
    camera_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (camera_id, cve_id),
    FOREIGN KEY (camera_id) REFERENCES cameras (id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES kev (cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS camera_cwes (
    camera_id INTEGER NOT NULL,
    cwe_id TEXT NOT NULL,
    cve_id TEXT,
    PRIMARY KEY (camera_id, cwe_id, cve_id),
    FOREIGN KEY (camera_id) REFERENCES cameras (id) ON DELETE CASCADE,
    FOREIGN KEY (cwe_id) REFERENCES cwes (id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES cves (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cameras_user_id ON cameras (user_id);
CREATE INDEX IF NOT EXISTS idx_cameras_vendor_product ON cameras (vendor, product);
CREATE INDEX IF NOT EXISTS idx_user_cameras_user_id ON user_cameras (user_id);
CREATE INDEX IF NOT EXISTS idx_camera_cves_camera ON camera_cves (camera_id);
CREATE INDEX IF NOT EXISTS idx_camera_kev_camera ON camera_kev (camera_id);
CREATE INDEX IF NOT EXISTS idx_camera_cwes_camera ON camera_cwes (camera_id);

INSERT INTO users (username, password_hash)
VALUES (
        'jules',
        '$2a$10$OvkJCURzl0kmZ021bT2sHe.Xw.b.K./mc/porUEOU3vrGAYMsUm3S'
    );

INSERT INTO cameras (user_id, name, vendor, product, criticity)
VALUES (
        1,
        'Caméra Entrée',
        'Hikvision',
        'DS-2CD2085FWD-I',
        'critical'
    ),
    (
        1,
        'Caméra Salon',
        'Hikvision',
        'DS-2CD2142FWD-I',
        'high'
    ),
    (
        1,
        'Caméra Garage',
        'Dahua',
        'IPC-HDBW4431R-ZS',
        'medium'
    ),
    (
        1,
        'Caméra Jardin',
        'Dahua',
        'IPC-HFW4431R-Z',
        'low'
    ),
    (1, 'Caméra Bureau', 'Axis', 'M3045-V', 'high');

INSERT INTO user_cameras (user_id, camera_id, nickname)
SELECT 1, id, name
FROM cameras
WHERE user_id = 1
ON CONFLICT (user_id, camera_id) DO NOTHING;