from flask import Flask, Blueprint, request, session, jsonify
from flask_restful import Api, Resource
from flask_mail import Mail, Message
from models import db, User, Note, ContactMessage
from schemas import UserSchema, NoteSchema, ContactMessageSchema
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_cors import CORS, cross_origin
import os

# Enhanced logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True)  # Enable CORS with credentials

# Configure application
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_SECURE=True,  # For HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Ensure secret key is set
if 'SECRET_KEY' not in os.environ:
    logger.warning('SECRET_KEY not found in environment, using default key (not recommended for production)')
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key_for_development')

# Initialize extensions
mail = Mail(app)
db.init_app(app)

# Create Blueprint
api_bp = Blueprint('api', __name__)
api = Api(api_bp)

# Initialize schemas
user_schema = UserSchema()
note_schema = NoteSchema()
notes_schema = NoteSchema(many=True)
contact_message_schema = ContactMessageSchema()

def respond_with_error(message, status_code):
    logger.error(f"Error response: {message} (Status: {status_code})")
    response = {'error': message}
    return jsonify(response), status_code

def get_current_user():
    user_id = session.get('user_id')
    if user_id:
        logger.debug(f"Current user ID from session: {user_id}")
        return User.query.get(user_id)
    logger.debug("No user ID found in session")
    return None

class Signup(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        try:
            data = request.get_json()
            logger.info(f"Signup attempt for email: {data.get('email')}")

            if not data or 'email' not in data or 'password' not in data:
                return respond_with_error('Email and password required', 400)

            if User.query.filter_by(email=data['email']).first():
                return respond_with_error('User already exists', 400)

            hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
            new_user = User(
                email=data['email'],
                password=hashed_password
            )
            
            db.session.add(new_user)
            db.session.commit()
            logger.info(f"User created successfully: {new_user.email}")
            
            # Automatically log in the user after signup
            session['user_id'] = new_user.id
            
            return {
                "message": "Signup successful",
                "user": user_schema.dump(new_user)
            }, 201

        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            db.session.rollback()
            return respond_with_error('Signup failed', 500)

class Login(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        try:
            data = request.get_json()
            logger.info(f"Login attempt for email: {data.get('email')}")

            if not data or 'email' not in data or 'password' not in data:
                return respond_with_error('Email and password required', 400)

            user = User.query.filter_by(email=data['email']).first()
            
            if not user:
                logger.warning(f"Login failed - user not found: {data.get('email')}")
                return respond_with_error('Invalid email or password', 401)

            if check_password_hash(user.password, data['password']):
                session['user_id'] = user.id
                logger.info(f"Login successful for user: {user.email}")
                return {
                    "message": "Login successful",
                    "user": {"id": user.id, "email": user.email}
                }, 200
            
            logger.warning(f"Login failed - invalid password for user: {data.get('email')}")
            return respond_with_error('Invalid email or password', 401)

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return respond_with_error('Login failed', 500)

class ForgotPassword(Resource):
    @cross_origin(supports_credentials=True)
    def post(self):
        try:
            data = request.get_json()
            logger.info(f"Password reset request for email: {data.get('email')}")

            if not data or 'email' not in data:
                return respond_with_error('Email required', 400)

            user = User.query.filter_by(email=data['email']).first()
            if not user:
                return respond_with_error('Email not found', 404)

            # TODO: Implement proper token generation
            reset_token = "placeholder_token"
            reset_link = f'http://localhost:5000/reset-password/{reset_token}'

            msg = Message(
                'Password Reset Request',
                sender='your_email@gmail.com',
                recipients=[data['email']]
            )
            msg.body = f'Use this link to reset your password: {reset_link}'
            mail.send(msg)
            
            logger.info(f"Password reset email sent to: {data['email']}")
            return {"message": "Password reset instructions sent"}, 200

        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            return respond_with_error('Password reset failed', 500)

class Logout(Resource):
    @cross_origin(supports_credentials=True)
    def delete(self):
        try:
            user_id = session.pop('user_id', None)
            logger.info(f"Logout successful for user ID: {user_id}")
            return {"message": "Logged out successfully"}, 200
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return respond_with_error('Logout failed', 500)

class CheckSession(Resource):
    @cross_origin(supports_credentials=True)
    def get(self):
        try:
            user = get_current_user()
            if user:
                logger.debug(f"Session check - user found: {user.email}")
                return user_schema.dump(user), 200
            logger.debug("Session check - no user found")
            return respond_with_error('Not authenticated', 401)
        except Exception as e:
            logger.error(f"Session check error: {str(e)}")
            return respond_with_error('Session check failed', 500)

class Notes(Resource):
    @cross_origin(supports_credentials=True)
    def get(self):
        try:
            user = get_current_user()
            if not user:
                return respond_with_error('Unauthorized', 401)

            notes = Note.query.filter_by(user_id=user.id).all()
            return notes_schema.dump(notes), 200
        except Exception as e:
            logger.error(f"Error fetching notes: {str(e)}")
            return respond_with_error('Failed to fetch notes', 500)

    @cross_origin(supports_credentials=True)
    def post(self):
        try:
            user = get_current_user()
            if not user:
                return respond_with_error('Unauthorized', 401)

            data = request.get_json()
            if not data or 'title' not in data or 'content' not in data:
                return respond_with_error('Title and content required', 400)

            new_note = Note(
                title=data['title'],
                content=data['content'],
                user_id=user.id
            )
            db.session.add(new_note)
            db.session.commit()
            
            logger.info(f"Note created for user: {user.email}")
            return note_schema.dump(new_note), 201

        except Exception as e:
            logger.error(f"Error creating note: {str(e)}")
            db.session.rollback()
            return respond_with_error('Failed to create note', 500)

class NoteResource(Resource):
    @cross_origin(supports_credentials=True)
    def get(self, note_id):
        try:
            user = get_current_user()
            if not user:
                return respond_with_error('Unauthorized', 401)

            note = Note.query.get(note_id)
            if note and note.user_id == user.id:
                return note_schema.dump(note), 200
            return respond_with_error('Note not found', 404)
        except Exception as e:
            logger.error(f"Error fetching note: {str(e)}")
            return respond_with_error('Failed to fetch note', 500)

    @cross_origin(supports_credentials=True)
    def patch(self, note_id):
        try:
            user = get_current_user()
            if not user:
                return respond_with_error('Unauthorized', 401)

            note = Note.query.get(note_id)
            if not note or note.user_id != user.id:
                return respond_with_error('Note not found', 404)

            data = request.get_json()
            if 'title' in data:
                note.title = data['title']
            if 'content' in data:
                note.content = data['content']

            db.session.commit()
            logger.info(f"Note {note_id} updated by user: {user.email}")
            return note_schema.dump(note), 200

        except Exception as e:
            logger.error(f"Error updating note: {str(e)}")
            db.session.rollback()
            return respond_with_error('Failed to update note', 500)

    @cross_origin(supports_credentials=True)
    def delete(self, note_id):
        try:
            user = get_current_user()
            if not user:
                return respond_with_error('Unauthorized', 401)

            note = Note.query.get(note_id)
            if note and note.user_id == user.id:
                db.session.delete(note)
                db.session.commit()
                logger.info(f"Note {note_id} deleted by user: {user.email}")
                return {"message": "Note deleted"}, 200
            return respond_with_error('Note not found', 404)

        except Exception as e:
            logger.error(f"Error deleting note: {str(e)}")
            db.session.rollback()
            return respond_with_error('Failed to delete note', 500)

# API routes
api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')
api.add_resource(ForgotPassword, '/forgot-password')
api.add_resource(Logout, '/logout')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Notes, '/notes')
api.add_resource(NoteResource, '/notes/<int:note_id>')

# Error handler
@api_bp.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {str(error)}")
    return respond_with_error('Internal server error', 500)

# Register blueprint
app.register_blueprint(api_bp, url_prefix='/api')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)