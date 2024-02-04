# my_simple_flask_app/app/models.py
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class QueueItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='queue_items', lazy=True)
    queue_number = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')
    entry_time = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<QueueItem {self.queue_number} for User {self.user.full_name}>'
        
class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, jti):
        self.jti = jti