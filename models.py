from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates
import re

metadata = MetaData()
db = SQLAlchemy(metadata=metadata)

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(50), default='user')  # Default role
    password = db.Column(db.String(129))
    reset_token = db.Column(db.String(100), nullable=True)  # For password reset
    created_at = db.Column(db.DateTime, default=db.func.now())

    @validates('email')
    def validate_email(self, key, email):
        regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if not re.match(regex, email):
            raise ValueError("Invalid email address")
        return email

    def __repr__(self):
        return f"<User {self.id}: {self.username}>"

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at,
            "role": self.role
        }
