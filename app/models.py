from .extensions import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    deadline = db.Column(db.DateTime)
    status = db.Column(db.String(30), default='Pending')
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=True)  # NEW COLUMN
    


