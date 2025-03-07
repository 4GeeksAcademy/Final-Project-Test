from flask_sqlalchemy import SQLAlchemy
from dataclasses import dataclass

db = SQLAlchemy()


@dataclass
class Users(db.Model):
    __tablename__ = "users"
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    user_name: str = db.Column(db.String(50), nullable=False)
    password = db.Column(db.VARCHAR(60), nullable=False)
    email: str = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<User {self.user_name}>"
