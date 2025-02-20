# TutorAppAPI
--

# TutorApp API Documentation

This repository contains the backend API for the **TutorApp**, a platform that connects students with tutors for academic sessions. The API provides endpoints for user authentication, session management, messaging, payments, and more.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Cloning the Repository](#cloning-the-repository)
3. [Setting Up the Environment](#setting-up-the-environment)
4. [Running the Project](#running-the-project)
5. [API Endpoints](#api-endpoints)
6. [Contributing](#contributing)
7. [License](#license)

---

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- **Python 3.8+**: Download from [python.org](https://www.python.org/downloads/).
- **pip**: Python's package installer (comes with Python 3.8+).
- **virtualenv** (optional): For creating isolated Python environments.
- **Git**: To clone the repository.

---

## Cloning the Repository

To clone the repository, run the following command in your terminal:

```bash
git clone https://github.com/SaadAlsuabie/TutorAppAPI.git
cd TutorAppAPI
```

---

## Setting Up the Environment

1. **Create a Virtual Environment**:
   It's recommended to use a virtual environment to manage dependencies.

   ```bash
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```

2. **Install Dependencies**:
   Install the required packages using `pip`.

   ```bash
   pip install -r requirements.txt
   ```

3. **Set Environment Variables**:
   Create a `.env` file in the root directory and add the following variables:

   ```env
   SECRET_KEY=your_django_secret_key
   DEBUG=True
   ALLOWED_HOSTS=127.0.0.1,localhost
   DATABASE_URL=sqlite:///db.sqlite3  # Or your database URL
   JWT_SECRET_KEY=your_jwt_secret_key
   ```

   > **Note**: Replace `your_django_secret_key` and `your_jwt_secret_key` with secure random keys.

4. **Database Setup**:
   By default, the project uses SQLite. If you want to use a different database, update the `DATABASE_URL` in the `.env` file.

   Apply migrations to set up the database schema:

   ```bash
   python manage.py migrate
   ```

5. **Create a Superuser (Optional)**:
   To access the Django admin panel, create a superuser:

   ```bash
   python manage.py createsuperuser
   ```

---

## Running the Project

1. **Start the Development Server**:

   ```bash
   python manage.py runserver
   ```

   The server will start at `http://127.0.0.1:8000/`.

2. **Access the API**:
   Use tools like **Postman**, **HTTPie**, or **cURL** to interact with the API endpoints.

---
