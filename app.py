import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_jwt_extended import JWTManager
from werkzeug.middleware.proxy_fix import ProxyFix


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "super-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# Configure application
app.config.from_pyfile("config.py")

# Configure JWT
app.config["JWT_SECRET_KEY"] = app.config["JWT_SECRET_KEY"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = app.config["JWT_ACCESS_TOKEN_EXPIRES"]
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = app.config["JWT_REFRESH_TOKEN_EXPIRES"]
jwt = JWTManager(app)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = app.config["DATABASE_URL"]
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

with app.app_context():
    # Make sure to import the models here or their tables won't be created
    from models import User, Book, Rental  # noqa: F401
    
    db.create_all()
    
    # Create admin user if not exists
    from models import User
    from werkzeug.security import generate_password_hash
    
    admin = User.query.filter_by(username=app.config["ADMIN_USERNAME"]).first()
    if not admin:
        logging.info("Creating admin user")
        admin = User(
            username=app.config["ADMIN_USERNAME"],
            email=app.config["ADMIN_EMAIL"],
            password_hash=generate_password_hash(app.config["ADMIN_PASSWORD"]),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
