from app import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    tasks    = db.relationship('Task', backref='owner', lazy=True)

class Task(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    title    = db.Column(db.String(100), nullable=False)   # ← добавили!
    content  = db.Column(db.String(255), nullable=False)
    is_done  = db.Column(db.Boolean, default=False)
    user_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    
