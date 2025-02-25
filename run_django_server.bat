@echo off
setlocal EnableDelayedExpansion

echo Starting Django development server setup...

:: Set the virtual environment name
set VENV_NAME=venv

:: Get the directory where this batch file (and manage.py) is located
set PROJECT_DIR=%~dp0
set VENV_DIR=%PROJECT_DIR%%VENV_NAME%

:: Check if manage.py exists in the current directory
if not exist "%PROJECT_DIR%manage.py" (
    echo ERROR: manage.py not found in the current directory: %PROJECT_DIR%
    pause
    exit /b 1
)

:: Check if the virtual environment exists
if exist "%VENV_DIR%\Scripts\activate.bat" (
    echo Virtual environment found at %VENV_DIR%. Activating...
    call "%VENV_DIR%\Scripts\activate.bat"
) else (
    echo Virtual environment not found. Creating one at %VENV_DIR%...
    python -m venv "%VENV_DIR%"
    
    :: Check if venv creation was successful
    if not exist "%VENV_DIR%\Scripts\activate.bat" (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
    
    echo Activating the new virtual environment...
    call "%VENV_DIR%\Scripts\activate.bat"
    
    :: Check if requirements.txt exists and install dependencies
    if exist "%PROJECT_DIR%requirements.txt" (
        echo Installing dependencies from requirements.txt...
        pip install -r "%PROJECT_DIR%requirements.txt"
    ) else (
        echo No requirements.txt found. Skipping dependency installation.
    )
)

:: Ensure Django is installed (in case requirements.txt was missing or empty)
echo Ensuring Django is installed...
pip install django

:: Run makemigrations to create migration files
echo Running makemigrations...
python "%PROJECT_DIR%manage.py" makemigrations

:: Run migrate to apply migrations to the database
echo Running migrate...
python "%PROJECT_DIR%manage.py" migrate

:: Run the Django development server
echo Starting Django development server...
python "%PROJECT_DIR%manage.py" runserver

:: Pause to keep the window open if there’s an error (optional)
pause