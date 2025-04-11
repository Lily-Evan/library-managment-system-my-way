import json
from datetime import datetime, timedelta
from functools import wraps

from flask import jsonify, request, render_template, redirect, url_for, flash
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token, 
    jwt_required, 
    get_jwt_identity,
    get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_

from app import app, db, jwt
from models import User, Book, Rental


# === JWT Configuration ===

# Create a function to check if the user is an admin
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or not user.is_admin:
                return jsonify({"msg": "Admin access required"}), 403
            
            return fn(*args, **kwargs)
        return decorator
    return wrapper


# === API ROUTES ===

# Authentication routes
@app.route('/api/register', methods=['POST'])
def register_user():
    """Register a new user"""
    data = request.get_json()
    
    # Validate input
    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({"msg": "Username, email, and password are required"}), 400
    
    # Check if user exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"msg": "Username already exists"}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"msg": "Email already exists"}), 409
    
    # Create new user
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password']),
        is_admin=False
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"msg": "User registered successfully"}), 201


@app.route('/api/login', methods=['POST'])
def login():
    """Login and get authentication tokens"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"msg": "Username and password are required"}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({"msg": "Invalid username or password"}), 401
    
    # Create tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict()
    }), 200


@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    
    return jsonify({"access_token": access_token}), 200


@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user's profile"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    return jsonify(user.to_dict()), 200


# Book routes
@app.route('/api/books', methods=['GET'])
def get_all_books():
    """Get all books with optional search"""
    search = request.args.get('search', '')
    
    if search:
        books = Book.query.filter(
            or_(
                Book.title.ilike(f"%{search}%"),
                Book.author.ilike(f"%{search}%")
            )
        ).all()
    else:
        books = Book.query.all()
    
    return jsonify({
        "books": [book.to_dict() for book in books]
    }), 200


@app.route('/api/books/<int:book_id>', methods=['GET'])
def get_book(book_id):
    """Get a specific book by ID"""
    book = Book.query.get(book_id)
    
    if not book:
        return jsonify({"msg": "Book not found"}), 404
    
    return jsonify(book.to_dict()), 200


@app.route('/api/books', methods=['POST'])
@admin_required()
def add_book():
    """Add a new book (admin only)"""
    data = request.get_json()
    
    # Validate input
    if not data or not data.get('title') or not data.get('author'):
        return jsonify({"msg": "Title and author are required"}), 400
    
    # Check if ISBN already exists
    if data.get('isbn') and Book.query.filter_by(isbn=data['isbn']).first():
        return jsonify({"msg": "Book with this ISBN already exists"}), 409
    
    # Create new book
    new_book = Book(
        title=data['title'],
        author=data['author'],
        isbn=data.get('isbn'),
        publication_year=data.get('publication_year'),
        description=data.get('description'),
        quantity=data.get('quantity', 1),
        available=data.get('quantity', 1)
    )
    
    db.session.add(new_book)
    db.session.commit()
    
    return jsonify(new_book.to_dict()), 201


@app.route('/api/books/<int:book_id>', methods=['PUT'])
@admin_required()
def update_book(book_id):
    """Update an existing book (admin only)"""
    book = Book.query.get(book_id)
    
    if not book:
        return jsonify({"msg": "Book not found"}), 404
    
    data = request.get_json()
    
    if not data:
        return jsonify({"msg": "No data provided"}), 400
    
    # Update book fields
    if 'title' in data:
        book.title = data['title']
    if 'author' in data:
        book.author = data['author']
    if 'isbn' in data:
        book.isbn = data['isbn']
    if 'publication_year' in data:
        book.publication_year = data['publication_year']
    if 'description' in data:
        book.description = data['description']
    if 'quantity' in data:
        # Update available count accordingly
        difference = data['quantity'] - book.quantity
        book.quantity = data['quantity']
        book.available += difference
    
    db.session.commit()
    
    return jsonify(book.to_dict()), 200


@app.route('/api/books/<int:book_id>', methods=['DELETE'])
@admin_required()
def delete_book(book_id):
    """Delete a book (admin only)"""
    book = Book.query.get(book_id)
    
    if not book:
        return jsonify({"msg": "Book not found"}), 404
    
    # Check if book is currently rented
    active_rentals = Rental.query.filter_by(book_id=book_id, is_returned=False).count()
    if active_rentals > 0:
        return jsonify({"msg": "Cannot delete book that is currently rented"}), 400
    
    db.session.delete(book)
    db.session.commit()
    
    return jsonify({"msg": "Book deleted successfully"}), 200


# Rental routes
@app.route('/api/rentals', methods=['GET'])
@jwt_required()
def get_rentals():
    """Get user's rentals or all rentals for admin"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    if user.is_admin:
        # Admins can see all rentals
        rentals = Rental.query.all()
    else:
        # Users can only see their own rentals
        rentals = Rental.query.filter_by(user_id=current_user_id).all()
    
    return jsonify({
        "rentals": [rental.to_dict() for rental in rentals]
    }), 200


@app.route('/api/rentals/<int:book_id>', methods=['POST'])
@jwt_required()
def rent_book(book_id):
    """Rent a book"""
    current_user_id = get_jwt_identity()
    
    # Check if book exists and is available
    book = Book.query.get(book_id)
    
    if not book:
        return jsonify({"msg": "Book not found"}), 404
    
    if book.available <= 0:
        return jsonify({"msg": "Book is not available for rent"}), 400
    
    # Check if user already has this book rented
    existing_rental = Rental.query.filter_by(
        user_id=current_user_id,
        book_id=book_id,
        is_returned=False
    ).first()
    
    if existing_rental:
        return jsonify({"msg": "You already have this book rented"}), 400
    
    # Create rental with 14-day due date
    due_date = datetime.utcnow() + timedelta(days=14)
    new_rental = Rental(
        user_id=current_user_id,
        book_id=book_id,
        due_date=due_date,
        is_returned=False
    )
    
    # Update book availability
    book.available -= 1
    
    db.session.add(new_rental)
    db.session.commit()
    
    return jsonify(new_rental.to_dict()), 201


@app.route('/api/rentals/<int:rental_id>/return', methods=['PUT'])
@jwt_required()
def return_book(rental_id):
    """Return a rented book"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    # Find the rental
    rental = Rental.query.get(rental_id)
    
    if not rental:
        return jsonify({"msg": "Rental not found"}), 404
    
    # Check if user owns this rental or is admin
    if rental.user_id != current_user_id and not user.is_admin:
        return jsonify({"msg": "Unauthorized to return this book"}), 403
    
    # Check if already returned
    if rental.is_returned:
        return jsonify({"msg": "Book already returned"}), 400
    
    # Update rental and book
    rental.is_returned = True
    rental.return_date = datetime.utcnow()
    
    book = Book.query.get(rental.book_id)
    book.available += 1
    
    db.session.commit()
    
    return jsonify(rental.to_dict()), 200


# === WEB ROUTES ===

@app.route('/')
def index():
    """Render the home page"""
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def web_login():
    """Handle web login form"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('web_login'))
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('web_login'))
        
        # Create tokens and store in cookies
        access_token = create_access_token(identity=user.id)
        
        response = redirect(url_for('dashboard'))
        response.set_cookie('access_token', access_token, httponly=True)
        response.set_cookie('user_id', str(user.id), httponly=True)
        response.set_cookie('is_admin', str(user.is_admin), httponly=True)
        response.set_cookie('username', user.username, httponly=True)
        
        return response
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def web_register():
    """Handle web registration form"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('web_register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('web_register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('web_register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('web_register'))
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=False
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('web_login'))
    
    return render_template('register.html')


@app.route('/logout')
def logout():
    """Handle logout"""
    response = redirect(url_for('index'))
    response.delete_cookie('access_token')
    response.delete_cookie('user_id')
    response.delete_cookie('is_admin')
    response.delete_cookie('username')
    
    flash('You have been logged out', 'success')
    return response


@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    return render_template('dashboard.html')


@app.route('/admin')
def admin_dashboard():
    """Admin dashboard"""
    return render_template('admin.html')
