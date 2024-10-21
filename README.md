# Note Taking App Backend

## Overview

The **Note Taking App Backend** is a RESTful API built with Flask, designed to manage and store user notes efficiently. This backend serves as the core component of a note-taking application, allowing users to create, retrieve, update, and delete their notes seamlessly.

## Features

- **User Authentication**: Secure user registration and login with JWT token-based authentication.
- **CRUD Operations**: Create, Read, Update, and Delete notes.
- **Categorization**: Organize notes with tags and categories.
- **Search Functionality**: Search notes by title, content, or tags.
- **Data Persistence**: Store notes in a SQLite database (or another database of your choice)

## Technologies Used

- **Flask**: A lightweight WSGI web application framework.
- **Flask-RESTful**: An extension for building REST APIs easily.
- **SQLAlchemy**: ORM for database interactions.
- ****: Default database for local development.

## Installation

### Prerequisites

- Python **3.7** or higher
- **pip** (Python package installer)

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/NgenyDev/note-taking-app-backend.git
   cd note-taking-app-backend

2. **Create a Virtual Environment (optional but recommended)**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt

4. **Set Up the Database**:
   ```bash
   python -c "from app import db; db.create_all()"

5. **Run the Application**:
   ```bash
   flask run

## API Endpoints

### Authentication

- **POST /api/auth/register**: Register a new user.
- **POST /api/auth/login**: Authenticate a user and retrieve a JWT.

### Notes

- **GET /api/notes**: Retrieve all notes.
- **POST /api/notes**: Create a new note.
- **GET /api/notes/<id>**: Retrieve a specific note by ID.
- **PUT /api/notes/<id>**: Update a specific note by ID.
- **DELETE /api/notes/<id>**: Delete a specific note by ID.

## Usage

After starting the server, you can interact with the API using tools like **Postman** or **Curl**. Make sure to include the JWT token in the headers for any requests that require authentication.
<<<<<<< HEAD
=======

>>>>>>> manuh
## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.

1. **Fork the project**
2. **Create your feature branch**:
   ```bash
   git checkout -b feature-branch

3. ### Commit your changes:
   ```bash
   git commit -m 'Add new feature'

4. ### Push to the branch:
   ```bash
   git push origin feature-branch

5. ### Open a Pull Request:
    Go to the original repository and click on the "Pull Requests" tab. Then click "New Pull Request" and select your branch to submit your changes for review.
<<<<<<< HEAD


5. ### Open a Pull Request:
Go to the original repository and click on the "Pull Requests" tab. Then click "New Pull Request" and select your branch to submit your changes for review.

=======
>>>>>>> manuh
