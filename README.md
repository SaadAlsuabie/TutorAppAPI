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
git clone git@github.com:SaadAlsuabie/TutorAppAPI.git
cd TutorAppAPI
```
### Setting Up the Environment
Follow these steps to configure the project:
Create a Virtual Environment
Isolate dependencies with a virtual environment:

Linux/Mac:
```bash
python -m venv env
source env/bin/activate
```
Windows:
```bash
python -m venv env
env\Scripts\activate
```

ℹ️ Tip: On Windows, use run_django_server.bat to automate this (see Running the Project 
(#running-the-project)).
- Install Dependencies
Install required packages:
```bash
pip install -r requirements.txt
```
ℹ️ Note: Automated by run_django_server.bat on Windows.
- Set Environment Variables
Create a .env file in the root directory:
env
```bash
SECRET_KEY=your_django_secret_key
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
DATABASE_URL=sqlite:///db.sqlite3
JWT_SECRET_KEY=your_jwt_secret_key
```
- 🔑 Security: Generate secure keys with python -c "import secrets; print(secrets.token_urlsafe(50))".
- Database Setup
SQLite is the default database. Update DATABASE_URL in .env for other databases.Apply migrations:
```bash
python manage.py migrate
```
ℹ️ Note: Handled automatically by run_django_server.bat on Windows.
- Create a Superuser (Optional)
Access the admin panel:
```bash
python manage.py createsuperuser
```

- Running the Project

### Launch the development server with one of these methods:

## Option 1: Batch File (Windows)
Use the provided run_django_server.bat for automation:
- Navigate to the TutorAppAPI directory.
- Run:
   cmd
- run_django_server.bat

The script:
Creates/activates a venv virtual environment.
Installs dependencies from requirements.txt.
Runs makemigrations and migrate.
Starts the server at http://127.0.0.1:8000/.

## Option 2: Manual Commands (All Platforms)
For manual control:
Activate the virtual environment:

Linux/Mac: source env/bin/activate
Windows: env\Scripts\activate
Install dependencies:
```bash
pip install -r requirements.txt
```

Apply migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

Start the server:
```bash
python manage.py runserver
```

Access at: http://127.0.0.1:8000/.
Testing the API
Use tools like Postman, HTTPie, or cURL to interact with endpoints.
API Endpoints
The API requires JWT authentication for most endpoints. Obtain a token via /login/ and include it as Authorization: Bearer <your_access_token>.

----