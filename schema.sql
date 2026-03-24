-- Email Threat Analysis Hub
-- SQLite Database Schema Definition

-- 1. Users Table
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Scan History Table
CREATE TABLE scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email_subject VARCHAR(255),
    email_sender VARCHAR(255),
    anomaly_score FLOAT NOT NULL,
    status VARCHAR(50) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
);

-- Note: The FLask SQLAlchemy ORM manages this schema automatically in database.db,
-- but this file is provided for raw SQL reference and examiner review.
