# TutorApp API

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Django](https://img.shields.io/badge/Django-4.x-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Welcome to the **TutorApp API**, the backend for a platform connecting students with tutors for academic sessions. This API handles user authentication, session management, messaging, payments, and more.

---

## Overview

The **TutorApp API** powers a seamless experience for students and tutors, enabling features like tutor browsing, session scheduling, feedback, and secure payments. Built with Django, it’s designed for scalability and ease of use.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Cloning the Repository](#cloning-the-repository)
- [Setting Up the Environment](#setting-up-the-environment)
- [Running the Project](#running-the-project)
- [API Endpoints](#api-endpoints)
- [Contributing](#contributing)
- [License](#license)

---

## Prerequisites

Ensure the following are installed on your system:

| Requirement       | Version   | Download Link                          |
|-------------------|-----------|----------------------------------------|
| Python            | 3.8+      | [python.org](https://www.python.org/downloads/) |
| pip               | Latest    | Included with Python                  |
| virtualenv (opt.) | Latest    | `pip install virtualenv`              |
| Git               | Latest    | [git-scm.com](https://git-scm.com/)   |

---

## Cloning the Repository

Clone the repository to your local machine:

```bash
git clone https://github.com/SaadAlsuabie/TutorAppAPI.git
cd TutorAppAPI
Setting Up the Environment
Follow these steps to configure the project:
Create a Virtual Environment
Isolate dependencies with a virtual environment:
Linux/Mac:
bash
python -m venv env
source env/bin/activate
Windows:
bash
python -m venv env
env\Scripts\activate
ℹ️ Tip: On Windows, use run_django_server.bat to automate this (see Running the Project (#running-the-project)).
Install Dependencies
Install required packages:
bash
pip install -r requirements.txt
ℹ️ Note: Automated by run_django_server.bat on Windows.
Set Environment Variables
Create a .env file in the root directory:
env
SECRET_KEY=your_django_secret_key
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
DATABASE_URL=sqlite:///db.sqlite3
JWT_SECRET_KEY=your_jwt_secret_key
🔑 Security: Generate secure keys with python -c "import secrets; print(secrets.token_urlsafe(50))".
Database Setup
SQLite is the default database. Update DATABASE_URL in .env for other databases.Apply migrations:
bash
python manage.py migrate
ℹ️ Note: Handled automatically by run_django_server.bat on Windows.
Create a Superuser (Optional)
Access the admin panel:
bash
python manage.py createsuperuser
Running the Project
Launch the development server with one of these methods:
Option 1: Batch File (Windows)
Use the provided run_django_server.bat for automation:
Navigate to the TutorAppAPI directory.
Run:
cmd
run_django_server.bat
The script:
Creates/activates a venv virtual environment.
Installs dependencies from requirements.txt.
Runs makemigrations and migrate.
Starts the server at http://127.0.0.1:8000/.
Option 2: Manual Commands (All Platforms)
For manual control:
Activate the virtual environment:
Linux/Mac: source env/bin/activate
Windows: env\Scripts\activate
Install dependencies:
bash
pip install -r requirements.txt
Apply migrations:
bash
python manage.py makemigrations
python manage.py migrate
Start the server:
bash
python manage.py runserver
Access at: http://127.0.0.1:8000/.
Testing the API
Use tools like Postman, HTTPie, or cURL to interact with endpoints.
API Endpoints
The API requires JWT authentication for most endpoints. Obtain a token via /login/ and include it as Authorization: Bearer <your_access_token>.
Endpoint
Method
Description
Authentication
/register/
POST
Register a new user
No
/login/
POST
Login and get JWT token
No
/browse-tutors/
GET
Browse tutors by course
Yes
/request-session/
POST
Request a session with a tutor
Yes
/leave-feedback/
POST
Leave feedback for a tutor
Yes
/set-availability/
POST
Set tutor availability
Yes
/accept-decline-session/<id>/
PATCH
Accept/decline a session request
Yes
/upload-recording/
POST
Upload a session recording
Yes
/make-payment/
POST
Process a payment
Yes
/send-message/
POST
Send a message to another user
Yes
/get-messages/
GET
Retrieve user messages
Yes
/get-notifications/
GET
Retrieve user notifications
Yes
/search-tutors/
GET
Search tutors by query
Yes
Detailed Examples
Register a New User
http
POST http://127.0.0.1:8000/register/ HTTP/1.1
Content-Type: application/json

{
    "username": "testuser",
    "email": "testuser@student.example.com",
    "password": "StrongPassword123",
    "role": "student"
}
Login a User
http
POST http://127.0.0.1:8000/login/ HTTP/1.1
Content-Type: application/json

{
    "username_or_email": "testuser",
    "password": "StrongPassword123"
}
Browse Tutors for a Course
http
GET http://127.0.0.1:8000/browse-tutors/?course_id=1 HTTP/1.1
Authorization: Bearer <your_access_token>
Request a Session
http
POST http://127.0.0.1:8000/request-session/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your_access_token>

{
    "tutor": 2,
    "session_type": 1,
    "requested_time": "2023-10-15T14:00:00Z"
}
Leave Feedback
http
POST http://127.0.0.1:8000/leave-feedback/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your_access_token>

{
    "to_user": 2,
    "rating": 5,
    "comment": "Great session, very helpful!"
}
Set Tutor Availability
http
POST http://127.0.0.1:8000/set-availability/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your_access_token>

{
    "session_type": 1,
    "start_time": "2023-10-15T10:00:00Z",
    "end_time": "2023-10-15T12:00:00Z"
}
Accept/Decline a Session
Accept:
http
PATCH http://127.0.0.1:8000/accept-decline-session/1/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your_access_token>

{
    "status": "accepted"
}
Decline:
http
PATCH http://127.0.0.1:8000/accept-decline-session/1/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your_access_token>

{
    "status": "declined",
    "decline_reason": "I am not available at that time."
}
Upload a Recording
http
POST http://127.0.0.1:8000/upload-recording/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your_access_token>

{
    "course": 1,
    "title": "Introduction to Calculus",
    "description": "This recording covers the basics of calculus.",
    "file_url": "https://example.com/recording.mp4"
}
Make a Payment
http
POST http://127.0.0.1:8000/make-payment/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your_access_token>

{
    "scheduled_session": 1,
    "amount": "50.00",
    "platform_fee": "5.00",
    "transaction_id": "txn_1234567890"
}
Send a Message
http
POST http://127.0.0.1:8000/send-message/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <your_access_token>

{
    "receiver": 2,
    "content": "Hi, can we schedule a session tomorrow?"
}
Get Messages
http
GET http://127.0.0.1:8000/get-messages/ HTTP/1.1
Authorization: Bearer <your_access_token>
Get Notifications
http
GET http://127.0.0.1:8000/get-notifications/ HTTP/1.1
Authorization: Bearer <your_access_token>
Search Tutors
http
GET http://127.0.0.1:8000/search-tutors/?query=math HTTP/1.1
Authorization: Bearer <your_access_token>
Contributing
We welcome contributions! To get started:
Fork the repository.
Create a feature branch (git checkout -b feature/YourFeature).
Commit your changes (git commit -m "Add YourFeature").
Push to the branch (git push origin feature/YourFeature).
Open a pull request.
License
This project is licensed under the MIT License (LICENSE).

### Enhancements
1. **Visual Appeal**:
   - Added badges for Python, Django, and license at the top using Shields.io.
   - Used emojis (ℹ️, 🔑) for notes and tips to draw attention.
   - Included a table for prerequisites to make requirements scannable.

2. **Professional Structure**:
   - Added an "Overview" section for a concise project summary.
   - Organized "API Endpoints" with a summary table followed by detailed examples.
   - Separated endpoint examples with clear headers and consistent formatting.

3. **Readability**:
   - Used consistent Markdown headers and code blocks.
