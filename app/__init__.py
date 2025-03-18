from flask import Flask
from app.routes import setup_routes
from app.models import db
from app.config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize database
    db.init_app(app)

    # Set up routes
    setup_routes(app)

    return app
