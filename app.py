from flask import Flask, jsonify
from flask_cors import CORS
from flask_migrate import Migrate
from models import db
from routes import api_bp, Users 
import logging
from flask_bcrypt import Bcrypt
from flask_mail import Mail

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    CORS(app, supports_credentials=True)
    db.init_app(app)
    bcrypt = Bcrypt(app)
    migrate = Migrate(app, db)
    mail = Mail(app)
    
    # Register the API blueprint
    app.register_blueprint(api_bp, url_prefix='/api')

    # Add a simple homepage route
    @app.route('/')
    def home():
        return "Welcome to the Note Taking App! The app is currently running."

    return app

def setup_database(app):
    with app.app_context():
        db.create_all()

def run_app(app):
    app.run() 

if __name__ == '__main__':
    app = create_app()
    setup_database(app)
    run_app(app)
