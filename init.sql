-- Database schema for IoT Security Analyzer

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cameras table
CREATE TABLE cameras (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    brand VARCHAR(50) NOT NULL,
    model VARCHAR(50) NOT NULL,
    criticity VARCHAR(20) NOT NULL CHECK (criticity IN ('low', 'medium', 'high', 'critical')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default user (password is 'martial' hashed with bcrypt)
INSERT INTO users (username, password_hash) VALUES 
('jules', '$2a$10$OvkJCURzl0kmZ021bT2sHe.Xw.b.K./mc/porUEOU3vrGAYMsUm3S');

-- Insert default cameras for the user
INSERT INTO cameras (user_id, name, brand, model, criticity) VALUES 
(1, 'Caméra Entrée', 'Hikvision', 'DS-2CD2085FWD-I', 'critical'),
(1, 'Caméra Salon', 'Hikvision', 'DS-2CD2142FWD-I', 'high'),
(1, 'Caméra Garage', 'Dahua', 'IPC-HDBW4431R-ZS', 'medium'),
(1, 'Caméra Jardin', 'Dahua', 'IPC-HFW4431R-Z', 'low'),
(1, 'Caméra Bureau', 'Axis', 'M3045-V', 'high');
