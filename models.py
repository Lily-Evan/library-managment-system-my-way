from datetime import datetime
from app import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rentals = db.relationship('Rental', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat()
        }


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    isbn = db.Column(db.String(20), unique=True)
    publication_year = db.Column(db.Integer)
    description = db.Column(db.Text)
    quantity = db.Column(db.Integer, default=1)
    available = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rentals = db.relationship('Rental', backref='book', lazy=True)
    
    def __repr__(self):
        return f'<Book {self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author,
            'isbn': self.isbn,
            'publication_year': self.publication_year,
            'description': self.description,
            'quantity': self.quantity,
            'available': self.available,
            'created_at': self.created_at.isoformat()
        }


class Rental(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    rental_date = db.Column(db.DateTime, default=datetime.utcnow)
    return_date = db.Column(db.DateTime)
    due_date = db.Column(db.DateTime, nullable=False)
    is_returned = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Rental {self.id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'book_id': self.book_id,
            'rental_date': self.rental_date.isoformat(),
            'return_date': self.return_date.isoformat() if self.return_date else None,
            'due_date': self.due_date.isoformat(),
            'is_returned': self.is_returned
        }
