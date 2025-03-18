from flask import Flask
from flask_login import LoginManager
from .models import db, bcrypt, Voter, Nominee, Votes, Admin
from .config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)

    # Setup Flask-Login
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        # Check both Voter and Admin tables
        return Voter.query.get(int(user_id)) or Admin.query.get(int(user_id))

    # Initialize routes (see next step)
    from . import routes
    routes.init_routes(app)

    return app

