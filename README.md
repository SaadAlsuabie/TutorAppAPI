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
- **virtualenv** (optional, but recommended): For creating isolated Python environments.
- **Git**: To clone the repository.

---

## Cloning the Repository

To clone the repository, run the following command in your terminal:

```bash
git clone git@github.com:SaadAlsuabie/TutorAppAPI.git
cd TutorAppAPI
Setting Up the Environment
Create a Virtual Environment:
It's recommended to use a virtual environment to manage dependencies.
On Linux/Mac:
bash
python -m venv env
source env/bin/activate
On Windows:
bash
python -m venv env
env\Scripts\activate
Note: The provided run_django_server.bat script (see Running the Project (#running-the-project)) can automate this step on Windows.
Install Dependencies:
Install the required packages using pip.
bash
pip install -r requirements.txt
Note: If using run_django_server.bat on Windows, this step is handled automatically.
Set Environment Variables:
Create a .env file in the root directory and add the following variables:
env
SECRET_KEY=your_django_secret_key
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
DATABASE_URL=sqlite:///db.sqlite3  # Or your database URL
JWT_SECRET_KEY=your_jwt_secret_key
Note: Replace your_django_secret_key and your_jwt_secret_key with secure random keys. Generate them using a tool like python -c "import secrets; print(secrets.token_urlsafe(50))".
Database Setup:
By default, the project uses SQLite. If you want to use a different database, update the DATABASE_URL in the .env file.Apply migrations to set up the database schema:
bash
python manage.py migrate
Note: On Windows, the run_django_server.bat script runs this automatically before starting the server.
Create a Superuser (Optional):
To access the Django admin panel, create a superuser:
bash
python manage.py createsuperuser
Running the Project
There are two ways to start the Django development server, depending on your operating system:
Option 1: Using the Batch File (Windows)
A convenient run_django_server.bat script is provided to automate the setup and running process on Windows.
Ensure you're in the TutorAppAPI directory (where manage.py is located).
Double-click run_django_server.bat, or run it from the command prompt:
cmd
run_django_server.bat
The script will:
Check for a virtual environment named venv in the project folder.
Create and activate it if it doesn’t exist.
Install dependencies from requirements.txt (if present).
Ensure Django is installed.
Run makemigrations and migrate to update the database.
Start the development server at http://127.0.0.1:8000/.
Option 2: Manual Commands (Linux/Mac or Windows)
If you prefer manual control or are on Linux/Mac:
Activate the virtual environment (if not already active):
On Linux/Mac:
bash
source env/bin/activate
On Windows:
cmd
env\Scripts\activate
Install dependencies (if not already done):
bash
pip install -r requirements.txt
Apply migrations:
bash
python manage.py makemigrations
python manage.py migrate
Start the development server:
bash
python manage.py runserver
The server will start at http://127.0.0.1:8000/.
Accessing the API
Use tools like Postman, HTTPie, or cURL to interact with the API endpoints once the server is running.
API Endpoints
[To be documented further. Example endpoints might include user registration, login, session booking, etc.]
Contributing
Contributions are welcome! Please fork the repository, create a feature branch, and submit a pull request.
License
[Specify your license here, e.g., MIT License]

### Key Updates
1. **Setting Up the Environment**:
   - Added notes indicating that `run_django_server.bat` automates virtual environment creation, dependency installation, and migrations on Windows.
   - Kept manual instructions for cross-platform compatibility.

2. **Running the Project**:
   - Split into two options:
     - **Option 1**: Detailed instructions for using the `run_django_server.bat` script, explaining its steps (virtual env setup, migrations, server start).
     - **Option 2**: Manual commands for those who prefer them or are on non-Windows systems.
   - Emphasized that `makemigrations` and `migrate` are included in the batch file.

3. **Consistency**:
   - Updated wording to clarify that the batch file handles steps automatically, reducing redundancy for Windows users.
   - Kept the original structure intact for users who don’t use the batch file.

### Usage
- Save this as `README.md` in your `TutorAppAPI` root directory.
- Ensure `run_django_server.bat` is in the same folder as `manage.py` for the Windows instructions to work.

Let me know if you’d like to add more details (e.g., specific API endpoints) or tweak anything else!