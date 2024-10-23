# from flask import Flask, Blueprint, request, session, jsonify
# from flask_restful import Api, Resource
# from flask_mail import Mail, Message
# from models import db, User, Note, ContactMessage
# from schemas import UserSchema, NoteSchema, ContactMessageSchema
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)

# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True

# import logging
# from flask_cors import cross_origin
# mail = Mail(app)

# # Set up logging
# logging.basicConfig(level=logging.INFO)

# # Create a Blueprint
# api_bp = Blueprint('api', __name__)
# api = Api(api_bp)

# user_schema = UserSchema()
# note_schema = NoteSchema()
# notes_schema = NoteSchema(many=True)
# contact_message_schema = ContactMessageSchema()

# def respond_with_error(message, status_code):
#     response = {'error': message}
#     return jsonify(response), status_code

# def get_current_user():
#     user_id = session.get('user_id')
#     return User.query.get(user_id) if user_id else None

# class Signup(Resource):
#     @cross_origin()
#     def post(self):
#         data = request.get_json()
#         if not data or 'email' not in data or 'password' not in data:
#             return respond_with_error('Email and password required', 400)

#         # Check if user already exists
#         if User.query.filter_by(email=data['email']).first():
#             return respond_with_error('User already exists', 400)

#         # Create new user with hashed password
#         new_user = User(email=data['email'])
#         new_user.password = generate_password_hash(data['password'])  # Hash the password
#         db.session.add(new_user)
#         db.session.commit()
        
#         return user_schema.dump(new_user), 201

#     @cross_origin()
#     def get(self):
#         users = User.query.all()
#         return user_schema.dump(users, many=True), 200


# class Login(Resource):
#     @cross_origin()
#     def post(self):
#         data = request.get_json()
        
#         # Check if the required data is provided
#         if not data or 'email' not in data or 'password' not in data:
#             return respond_with_error('Email and password required', 400)

#         # Fetch the user by email
#         user = User.query.filter_by(email=data['email']).first()
        
#         # Check if user exists
#         if not user:
#             return respond_with_error('User not found', 404)

#         # Use the custom check_password method to verify the password
#         if User.check_password(user,data['password']):
#             session['user_id'] = user.id
#             return {
#                 "message": "Login successful",
#                 "user": {"id": user.id, "email": user.email}
#             }, 200

#         return respond_with_error('Invalid password', 401)
# class ForgotPassword(Resource):
#     def post(self):
#         data = request.get_json()
#         logging.info(f'Received forgot password request: {data}')

#         if not data or 'email' not in data:
#             logging.warning('Email required for password reset')
#             return {"error": "Email required"}, 400

#         user = User.query.filter_by(email=data['email']).first()
#         if not user:
#             logging.warning('User not found for password reset')
#             return {"error": "User not found"}, 404

#         # Generate a reset token (placeholder for real implementation)
#         reset_token = "placeholder_for_reset_token"  # You should implement actual token generation
#         reset_link = f'http://localhost:5000/reset-password/{reset_token}'  # Create your reset link

#         msg = Message('Password Reset Request', sender='your_email@gmail.com', recipients=[data['email']])
#         msg.body = f'Please use the following link to reset your password: {reset_link}'
#         try:
#             mail.send(msg)
#             logging.info(f'Password reset link sent to {data["email"]}')
#             return {"message": "Password reset link sent"}, 200
#         except Exception as e:
#             logging.error(f'Error sending email: {e}')
#             return {"error": "Failed to send password reset link"}, 500

# class Logout(Resource):
#     @cross_origin()
#     def delete(self):
#         session.pop('user_id', None)
#         return {}, 204

# class CheckSession(Resource):
#     @cross_origin()
#     def get(self):
#         user = get_current_user()
#         if user:
#             return user_schema.dump(user), 200
#         return respond_with_error('Unauthorized', 401)

# class Notes(Resource):
#     @cross_origin()
#     def get(self):
#         user = get_current_user()
#         if not user:
#             return respond_with_error('Unauthorized', 401)

#         notes = Note.query.filter_by(user_id=user.id).all()
#         return notes_schema.dump(notes), 200

#     @cross_origin()
#     def post(self):
#         user = get_current_user()
#         if not user:
#             return respond_with_error('Unauthorized', 401)

#         data = request.get_json()
#         if not data or 'title' not in data or 'content' not in data:
#             return respond_with_error('Title and content required', 400)

#         new_note = Note(title=data['title'], content=data['content'], user_id=user.id)
#         db.session.add(new_note)

#         try:
#             db.session.commit()
#             return note_schema.dump(new_note), 201
#         except Exception as e:
#             db.session.rollback()
#             logging.error(f'Error creating note: {e}')
#             return respond_with_error('Failed to create note', 500)

# class NoteResource(Resource):
#     @cross_origin()
#     def get(self, note_id):
#         user = get_current_user()
#         if not user:
#             return respond_with_error('Unauthorized', 401)

#         note = Note.query.get(note_id)
#         if note and note.user_id == user.id:
#             return note_schema.dump(note), 200
#         return respond_with_error('Note not found or forbidden', 404)

#     @cross_origin()
#     def patch(self, note_id):
#         user = get_current_user()
#         if not user:
#             return respond_with_error('Unauthorized', 401)

#         note = Note.query.get(note_id)
#         if not note or note.user_id != user.id:
#             return respond_with_error('Note not found or forbidden', 404)

#         data = request.get_json()
#         note.title = data.get('title', note.title)
#         note.content = data.get('content', note.content)

#         try:
#             db.session.commit()
#             return note_schema.dump(note), 200
#         except Exception as e:
#             db.session.rollback()
#             logging.error(f'Error updating note: {e}')
#             return respond_with_error('Failed to update note', 500)

#     @cross_origin()
#     def delete(self, note_id):
#         user = get_current_user()
#         if not user:
#             return respond_with_error('Unauthorized', 401)

#         note = Note.query.get(note_id)
#         if note and note.user_id == user.id:
#             db.session.delete(note)
#             db.session.commit()
#             return {}, 204
#         return respond_with_error('Note not found or forbidden', 404)

# class NoteByTitle(Resource):
#     @cross_origin()
#     def get(self, title):
#         user = get_current_user()
#         if not user:
#             return respond_with_error('Unauthorized', 401)

#         note = Note.query.filter_by(title=title, user_id=user.id).first()  # Adjust query
#         if note:
#             return note_schema.dump(note), 200
#         return respond_with_error('Note not found or forbidden', 404)

# class Contact(Resource):
#     @cross_origin()
#     def post(self):
#         data = request.get_json()
#         if not data or 'name' not in data or 'email' not in data or 'subject' not in data or 'message' not in data:
#             return respond_with_error('All fields are required', 400)

#         contact_message = ContactMessage(
#             name=data['name'],
#             email=data['email'],
#             subject=data['subject'],
#             message=data['message']
#         )

#         db.session.add(contact_message)

#         try:
#             db.session.commit()
#             return contact_message_schema.dump(contact_message), 201
#         except Exception as e:
#             db.session.rollback()
#             logging.error(f'Error saving contact message: {e}')
#             return respond_with_error('Failed to send message', 500)

# class Users(Resource):
#     @cross_origin()
#     def get(self):
#         users = User.query.all()  
#         return user_schema.dump(users, many=True), 200  

# api.add_resource(Signup, '/signup')
# api.add_resource(Login, '/login')
# api.add_resource(ForgotPassword, '/api/forgot-password')
# api.add_resource(Logout, '/logout')
# api.add_resource(CheckSession, '/check_session')
# api.add_resource(Notes, '/notes')
# api.add_resource(NoteResource, '/notes/<int:note_id>')
# api.add_resource(NoteByTitle, '/notes/title/<string:title>')  
# api.add_resource(Contact, '/contact')
# api.add_resource(Users, '/users')  

# @api_bp.errorhandler(Exception)
# def handle_exception(e):
#     logging.error(f'Unhandled exception: {str(e)}')
#     return respond_with_error('Internal Server Error', 500)

# # from flask import Flask, Blueprint, request, session, jsonify
# # from flask_restful import Api, Resource
# # from flask_cors import CORS
# # from flask_mail import Mail, Message
# # from models import db, User, Note, ContactMessage
# # from schemas import UserSchema, NoteSchema, ContactMessageSchema
# # from werkzeug.security import generate_password_hash, check_password_hash
# # import logging
# # import os

# # # Initialize Flask app
# # app = Flask(__name__)
# # CORS(app)

# # # Configure application
# # app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# # app.config['MAIL_PORT'] = 587
# # app.config['MAIL_USE_TLS'] = True
# # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'  # Adjust database URI
# # app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')  # Set secret key for session management

# # # Initialize mail
# # mail = Mail(app)

# # # Set up logging
# # logging.basicConfig(level=logging.INFO)

# # # Create a Blueprint
# # api_bp = Blueprint('api', __name__)
# # api = Api(api_bp)

# # # Schemas
# # user_schema = UserSchema()
# # note_schema = NoteSchema()
# # notes_schema = NoteSchema(many=True)
# # contact_message_schema = ContactMessageSchema()

# # def respond_with_error(message, status_code):
# #     response = {'error': message}
# #     return jsonify(response), status_code

# # def get_current_user():
# #     user_id = session.get('user_id')
# #     return User.query.get(user_id) if user_id else None

# # class Signup(Resource):
# #     def post(self):
# #         data = request.get_json()
# #         if not data or 'email' not in data or 'password' not in data:
# #             logging.warning("Signup attempt with missing data.")
# #             return {'error': 'Email and password required'}, 400

# #         if User.query.filter_by(email=data['email']).first():
# #             logging.warning(f"User already exists: {data['email']}")
# #             return {'error': 'User already exists'}, 400

# #         new_user = User(email=data['email'])
# #         new_user.password = generate_password_hash(data['password'])
# #         db.session.add(new_user)
# #         db.session.commit()

# #         logging.info(f"New user created: {data['email']}")
# #         return user_schema.dump(new_user), 201

# # class Login(Resource):
# #     def post(self):
# #         data = request.get_json()
# #         if not data or 'email' not in data or 'password' not in data:
# #             logging.warning("Login attempt with missing data.")
# #             return {'error': 'Email and password required'}, 400

# #         user = User.query.filter_by(email=data['email']).first()
# #         if not user:
# #             logging.warning(f"User not found: {data['email']}")
# #             return {'error': 'User not found'}, 404

# #         if check_password_hash(user.password, data['password']):
# #             session['user_id'] = user.id
# #             logging.info(f"User logged in: {user.email}")
# #             return {"message": "Login successful", "user": {"id": user.id, "email": user.email}}, 200

# #         logging.warning(f"Invalid password for user: {data['email']}")
# #         return {'error': 'Invalid password'}, 401
    
# # class ForgotPassword(Resource):
# #     def post(self):
# #         data = request.get_json()
# #         logging.info(f'Received forgot password request: {data}')

# #         if not data or 'email' not in data:
# #             return respond_with_error('Email required for password reset', 400)

# #         user = User.query.filter_by(email=data['email']).first()
# #         if not user:
# #             return respond_with_error('User not found', 404)

# #         reset_token = "placeholder_for_reset_token"  # TODO: Implement actual token generation
# #         reset_link = f'http://localhost:5000/reset-password/{reset_token}'

# #         msg = Message('Password Reset Request', sender='your_email@gmail.com', recipients=[data['email']])
# #         msg.body = f'Please use the following link to reset your password: {reset_link}'
        
# #         try:
# #             mail.send(msg)
# #             logging.info(f'Password reset link sent to {data["email"]}')
# #             return {"message": "Password reset link sent"}, 200
# #         except Exception as e:
# #             logging.error(f'Error sending email: {e}')
# #             return respond_with_error('Failed to send password reset link', 500)

# # class Logout(Resource):
# #     def delete(self):
# #         session.pop('user_id', None)
# #         return {}, 204

# # class CheckSession(Resource):
# #     def get(self):
# #         user = get_current_user()
# #         if user:
# #             return user_schema.dump(user), 200
# #         return respond_with_error('Unauthorized', 401)

# # class Notes(Resource):
# #     def get(self):
# #         user = get_current_user()
# #         if not user:
# #             return respond_with_error('Unauthorized', 401)

# #         notes = Note.query.filter_by(user_id=user.id).all()
# #         return notes_schema.dump(notes), 200

# #     def post(self):
# #         user = get_current_user()
# #         if not user:
# #             return respond_with_error('Unauthorized', 401)

# #         data = request.get_json()
# #         if not data or 'title' not in data or 'content' not in data:
# #             return respond_with_error('Title and content required', 400)

# #         new_note = Note(title=data['title'], content=data['content'], user_id=user.id)
# #         db.session.add(new_note)

# #         try:
# #             db.session.commit()
# #             return note_schema.dump(new_note), 201
# #         except Exception as e:
# #             db.session.rollback()
# #             logging.error(f'Error creating note: {e}')
# #             return respond_with_error('Failed to create note', 500)

# # class NoteResource(Resource):
# #     def get(self, note_id):
# #         user = get_current_user()
# #         if not user:
# #             return respond_with_error('Unauthorized', 401)

# #         note = Note.query.get(note_id)
# #         if note and note.user_id == user.id:
# #             return note_schema.dump(note), 200
# #         return respond_with_error('Note not found or forbidden', 404)

# #     def patch(self, note_id):
# #         user = get_current_user()
# #         if not user:
# #             return respond_with_error('Unauthorized', 401)

# #         note = Note.query.get(note_id)
# #         if not note or note.user_id != user.id:
# #             return respond_with_error('Note not found or forbidden', 404)

# #         data = request.get_json()
# #         note.title = data.get('title', note.title)
# #         note.content = data.get('content', note.content)

# #         try:
# #             db.session.commit()
# #             return note_schema.dump(note), 200
# #         except Exception as e:
# #             db.session.rollback()
# #             logging.error(f'Error updating note: {e}')
# #             return respond_with_error('Failed to update note', 500)

# #     def delete(self, note_id):
# #         user = get_current_user()
# #         if not user:
# #             return respond_with_error('Unauthorized', 401)

# #         note = Note.query.get(note_id)
# #         if note and note.user_id == user.id:
# #             db.session.delete(note)
# #             db.session.commit()
# #             return {}, 204
# #         return respond_with_error('Note not found or forbidden', 404)

# # class NoteByTitle(Resource):
# #     def get(self, title):
# #         user = get_current_user()
# #         if not user:
# #             return respond_with_error('Unauthorized', 401)

# #         note = Note.query.filter_by(title=title, user_id=user.id).first()
# #         if note:
# #             return note_schema.dump(note), 200
# #         return respond_with_error('Note not found or forbidden', 404)

# # class Contact(Resource):
# #     def post(self):
# #         data = request.get_json()
# #         if not data or 'name' not in data or 'email' not in data or 'subject' not in data or 'message' not in data:
# #             return respond_with_error('All fields are required', 400)

# #         contact_message = ContactMessage(
# #             name=data['name'],
# #             email=data['email'],
# #             subject=data['subject'],
# #             message=data['message']
# #         )

# #         db.session.add(contact_message)

# #         try:
# #             db.session.commit()
# #             return contact_message_schema.dump(contact_message), 201
# #         except Exception as e:
# #             db.session.rollback()
# #             logging.error(f'Error saving contact message: {e}')
# #             return respond_with_error('Failed to send message', 500)

# # class Users(Resource):
# #     def get(self):
# #         users = User.query.all()
# #         return user_schema.dump(users, many=True), 200  

# # # Registering Resources
# # api.add_resource(Signup, '/signup')
# # api.add_resource(Login, '/login')
# # api.add_resource(ForgotPassword, '/forgot-password')
# # api.add_resource(Logout, '/logout')
# # api.add_resource(CheckSession, '/check_session')
# # api.add_resource(Notes, '/notes')
# # api.add_resource(NoteResource, '/notes/<int:note_id>')
# # api.add_resource(NoteByTitle, '/notes/title/<string:title>')  
# # api.add_resource(Contact, '/contact')
# # api.add_resource(Users, '/users')  

# # @api_bp.errorhandler(Exception)
# # def handle_exception(e):
# #     logging.error(f'Unhandled exception: {str(e)}')
# #     return respond_with_error('Internal Server Error', 500)

# # # Register the Blueprint
# # app.register_blueprint(api_bp, url_prefix='/api')

# # if __name__ == '__main__':
# #     app.run(debug=True)
from flask import Flask, Blueprint, request, session, jsonify
from flask_restful import Api, Resource
from flask_mail import Mail, Message
from models import db, User, Note, ContactMessage
from schemas import UserSchema, NoteSchema, ContactMessageSchema
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_cors import CORS, cross_origin
import os

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure application
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')  # Set secret key for session management

# Initialize mail
mail = Mail(app)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Create a Blueprint
api_bp = Blueprint('api', __name__)
api = Api(api_bp)

# Schemas
user_schema = UserSchema()
note_schema = NoteSchema()
notes_schema = NoteSchema(many=True)
contact_message_schema = ContactMessageSchema()

def respond_with_error(message, status_code):
    response = {'error': message}
    return jsonify(response), status_code

def get_current_user():
    user_id = session.get('user_id')
    return User.query.get(user_id) if user_id else None

class Signup(Resource):
    @cross_origin()
    def post(self):
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return respond_with_error('Email and password required', 400)

        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return respond_with_error('User already exists', 400)

        # Create new user with hashed password
        new_user = User(email=data['email'])
        new_user.password = generate_password_hash(data['password'])  # Hash the password
        db.session.add(new_user)
        db.session.commit()
        
        return user_schema.dump(new_user), 201

    @cross_origin()
    def get(self):
        users = User.query.all()
        return user_schema.dump(users, many=True), 200

class Login(Resource):
    @cross_origin()
    def post(self):
        data = request.get_json()
        
        # Check if the required data is provided
        if not data or 'email' not in data or 'password' not in data:
            return respond_with_error('Email and password required', 400)

        # Fetch the user by email
        user = User.query.filter_by(email=data['email']).first()
        
        # Check if user exists
        if not user:
            return respond_with_error('User not found', 404)

        # Verify the password
        if check_password_hash(user.password, data['password']):
            session['user_id'] = user.id
            return {
                "message": "Login successful",
                "user": {"id": user.id, "email": user.email}
            }, 200

        return respond_with_error('Invalid password', 401)

class ForgotPassword(Resource):
    def post(self):
        data = request.get_json()
        logging.info(f'Received forgot password request: {data}')

        if not data or 'email' not in data:
            logging.warning('Email required for password reset')
            return respond_with_error('Email required for password reset', 400)

        user = User.query.filter_by(email=data['email']).first()
        if not user:
            logging.warning('User not found for password reset')
            return respond_with_error('User not found', 404)

        # Generate a reset token (placeholder for real implementation)
        reset_token = "placeholder_for_reset_token"  # TODO: Implement actual token generation
        reset_link = f'http://localhost:5000/reset-password/{reset_token}'  # Create your reset link

        msg = Message('Password Reset Request', sender='your_email@gmail.com', recipients=[data['email']])
        msg.body = f'Please use the following link to reset your password: {reset_link}'
        try:
            mail.send(msg)
            logging.info(f'Password reset link sent to {data["email"]}')
            return {"message": "Password reset link sent"}, 200
        except Exception as e:
            logging.error(f'Error sending email: {e}')
            return respond_with_error('Failed to send password reset link', 500)

class Logout(Resource):
    @cross_origin()
    def delete(self):
        session.pop('user_id', None)
        return {}, 204

class CheckSession(Resource):
    @cross_origin()
    def get(self):
        user = get_current_user()
        if user:
            return user_schema.dump(user), 200
        return respond_with_error('Unauthorized', 401)

class Notes(Resource):
    @cross_origin()
    def get(self):
        user = get_current_user()
        if not user:
            return respond_with_error('Unauthorized', 401)

        notes = Note.query.filter_by(user_id=user.id).all()
        return notes_schema.dump(notes), 200

    @cross_origin()
    def post(self):
        user = get_current_user()
        if not user:
            return respond_with_error('Unauthorized', 401)

        data = request.get_json()
        if not data or 'title' not in data or 'content' not in data:
            return respond_with_error('Title and content required', 400)

        new_note = Note(title=data['title'], content=data['content'], user_id=user.id)
        db.session.add(new_note)

        try:
            db.session.commit()
            return note_schema.dump(new_note), 201
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error creating note: {e}')
            return respond_with_error('Failed to create note', 500)

class NoteResource(Resource):
    @cross_origin()
    def get(self, note_id):
        user = get_current_user()
        if not user:
            return respond_with_error('Unauthorized', 401)

        note = Note.query.get(note_id)
        if note and note.user_id == user.id:
            return note_schema.dump(note), 200
        return respond_with_error('Note not found or forbidden', 404)

    @cross_origin()
    def patch(self, note_id):
        user = get_current_user()
        if not user:
            return respond_with_error('Unauthorized', 401)

        note = Note.query.get(note_id)
        if not note or note.user_id != user.id:
            return respond_with_error('Note not found or forbidden', 404)

        data = request.get_json()
        note.title = data.get('title', note.title)
        note.content = data.get('content', note.content)

        try:
            db.session.commit()
            return note_schema.dump(note), 200
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error updating note: {e}')
            return respond_with_error('Failed to update note', 500)

    @cross_origin()
    def delete(self, note_id):
        user = get_current_user()
        if not user:
            return respond_with_error('Unauthorized', 401)

        note = Note.query.get(note_id)
        if note and note.user_id == user.id:
            db.session.delete(note)
            db.session.commit()
            return {}, 204
        return respond_with_error('Note not found or forbidden', 404)

class NoteByTitle(Resource):
    @cross_origin()
    def get(self, title):
        user = get_current_user()
        if not user:
            return respond_with_error('Unauthorized', 401)

        note = Note.query.filter_by(title=title, user_id=user.id).first()
        if note:
            return note_schema.dump(note), 200
        return respond_with_error('Note not found or forbidden', 404)

class Contact(Resource):
    @cross_origin()
    def post(self):
        data = request.get_json()
        if not data or 'name' not in data or 'email' not in data or 'subject' not in data or 'message' not in data:
            return respond_with_error('All fields are required', 400)

        contact_message = ContactMessage(
            name=data['name'],
            email=data['email'],
            subject=data['subject'],
            message=data['message']
        )

        db.session.add(contact_message)

        try:
            db.session.commit()
            return contact_message_schema.dump(contact_message), 201
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error saving contact message: {e}')
            return respond_with_error('Failed to send message', 500)

class Users(Resource):
    @cross_origin()
    def get(self):
        users = User.query.all()  
        return user_schema.dump(users, many=True), 200  

# Add resources to the API
api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')
api.add_resource(ForgotPassword, '/api/forgot-password')
api.add_resource(Logout, '/logout')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Notes, '/notes')
api.add_resource(NoteResource, '/notes/<int:note_id>')
api.add_resource(NoteByTitle, '/notes/title/<string:title>')  
api.add_resource(Contact, '/contact')
api.add_resource(Users, '/users')  

@api_bp.errorhandler(Exception)
def handle_exception(e):
    logging.error(f'Unhandled exception: {str(e)}')
    return respond_with_error('Internal Server Error', 500)

# Register the blueprint with the app
app.register_blueprint(api_bp, url_prefix='/api')

if __name__ == '__main__':
    app.run(debug=True)