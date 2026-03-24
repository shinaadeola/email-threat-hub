from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with scans
    scans = db.relationship('ScanHistory', backref='user', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email_subject = db.Column(db.String(255), nullable=True)
    email_sender = db.Column(db.String(255), nullable=True)
    anomaly_score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    # New: structured threat classification from multi-signal engine
    threat_classification = db.Column(db.String(20), nullable=True)   # SAFE/SPAM/PHISHING/...
    confidence_score = db.Column(db.Float, nullable=True)             # 0.0–1.0
    detection_signals = db.Column(db.Text, nullable=True)             # JSON list of signals
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

