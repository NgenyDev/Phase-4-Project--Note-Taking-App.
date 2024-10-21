from app import create_app
from models import User, Note, EditorContent, ContactMessage
from models import db

def seed_db():
    user1 = User(email='user1', password='password123')
    user2 = User(email='user2', password='password456')

    db.session.add(user1)
    db.session.add(user2)
    db.session.commit()

    note1 = Note(title='First Note', content='hey this is my first content', tags='tag1,tag2', user_id=user1.id)
    note2 = Note(title='Second Note', content='hey this is my first content', tags='tag1,tag2', user_id=user2.id)

    db.session.add(note1)
    db.session.add(note2)
    db.session.commit()

    editor_content1 = EditorContent(note_id=note1.id, content='This is the content of the first note.')
    editor_content2 = EditorContent(note_id=note2.id, content='This is the content of the second note.')

    db.session.add(editor_content1)
    db.session.add(editor_content2)

    contact_message1 = ContactMessage(name='John Doe', email='john@example.com', 
                                       subject='Hello', message='This is a test message.')
    contact_message2 = ContactMessage(name='Jane Smith', email='jane@example.com', 
                                       subject='Inquiry', message='I would like to know more.')

    db.session.add(contact_message1)
    db.session.add(contact_message2)

    db.session.commit()
    print("Database seeded!")

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()  
        seed_db()
