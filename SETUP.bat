@echo off
REM ================================================
REM Cybersec Assistant — Windows setup script
REM Usage: double-click or run from CMD in repo root
REM ================================================

setlocal enabledelayedexpansion

echo.
echo ================= Cybersec Assistant Setup (Windows) =================
echo.

REM 1) Check Python
python --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python not found in PATH. Please install Python 3.10+ and add to PATH.
  pause
  exit /b 1
) else (
  for /f "tokens=2 delims=[] " %%A in ('python --version 2^>^&1') do set PYVER=%%A
  echo Found Python: %PYVER%
)

REM 2) Check pip
pip --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] pip not found. Ensure Python was installed with pip.
  pause
  exit /b 1
)

REM 3) Create virtual environment if it doesn't exist
if not exist venv (
  echo Creating virtual environment (venv)...
  python -m venv venv
  if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
  )
) else (
  echo Virtual environment already exists (venv).
)

REM 4) Activate venv and upgrade pip
echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
  echo [ERROR] Failed to activate venv.
  pause
  exit /b 1
)

echo Upgrading pip...
python -m pip install --upgrade pip setuptools wheel

REM 5) Install requirements
if exist requirements.txt (
  echo Installing Python dependencies from requirements.txt ...
  pip install -r requirements.txt
  if errorlevel 1 (
    echo [WARNING] Some packages may have failed to install. Please inspect output.
  ) else (
    echo Dependencies installed.
  )
) else (
  echo [WARNING] requirements.txt not found. Please ensure it exists.
)

REM 6) Create .env from template if not present
if not exist .env (
  echo Creating .env from template...
  > .env (
    echo # === OpenAI / External APIs ===
    echo OPENAI_API_KEY=sk-REPLACE_WITH_YOUR_OPENAI_KEY
    echo VT_API_KEY=VT-REPLACE_WITH_YOUR_VT_KEY
    echo HIBP_API_KEY=
    echo.
    echo # === Optional local common passwords file ===
    echo COMMON_PASSWORDS_FILE=./data/common-10000.txt
    echo.
    echo # === n8n webhook (single canonical entry) ===
    echo N8N_WEBHOOK_URL=http://localhost:5678/webhook/cybersec-assistant-webhook
    echo.
    echo # === Slack (Incoming Webhook) ===
    echo SLACK_WEBHOOK_URL=https://hooks.slack.com/services/REPLACE/ME/URL
    echo.
    echo # === SMTP (for email alerts - optional) ===
    echo SMTP_HOST=smtp.gmail.com
    echo SMTP_PORT=587
    echo SMTP_USER=you@gmail.com
    echo SMTP_PASS=your_smtp_or_app_password
    echo EMAIL_FROM=you@gmail.com
    echo ALERT_EMAIL_TO=recipient@example.com
    echo.
    echo # === Database / runtime ===
    echo DATABASE_URL=sqlite:///./events.db
    echo ENVIRONMENT=development
    echo LOG_LEVEL=info
    echo.
    echo # === Server ===
    echo HOST=0.0.0.0
    echo PORT=8000
    echo.
    echo # === Memory path (optional) ===
    echo MEMORY_PATH=./memory_store.json
  )
  echo Created .env (please edit it and fill the API keys before running the services).
) else (
  echo .env already exists — leaving it in place.
)

REM 7) Optional: download common password list
if exist scripts\download_common_passwords.py (
  echo.
  set /p DO_DOWNLOAD="Do you want to download the common-passwords list (recommended)? [Y/n]: "
  if /i "%DO_DOWNLOAD%"=="n" (
    echo Skipping download.
  ) else (
    echo Running the downloader script...
    python scripts\download_common_passwords.py
    if errorlevel 1 (
      echo [WARNING] downloader script failed or was aborted.
    ) else (
      echo Download complete (check ./data/common-10000.txt).
    )
  )
) else (
  echo Downloader script not found at scripts\download_common_passwords.py — skipping.
)

REM 8) Create data and memory files if missing
if not exist data (
  mkdir data
)
if not exist %MEMORY_PATH% (
  if not defined MEMORY_PATH set MEMORY_PATH=memory_store.json
  if not exist "%MEMORY_PATH%" (
    echo {} > "%MEMORY_PATH%"
  )
)

echo.
echo Setup complete (virtualenv activated).
echo

:MENU
echo Choose an action:
echo 1) Start FastAPI backend (uvicorn)
echo 2) Start Streamlit UI
echo 3) Run tests (pytest)
echo 4) Open project folder
echo 5) Exit
set /p CHOICE=Enter number [1-5]:

if "%CHOICE%"=="1" goto RUN_BACKEND
if "%CHOICE%"=="2" goto RUN_UI
if "%CHOICE%"=="3" goto RUN_TESTS
if "%CHOICE%"=="4" goto OPEN_FOLDER
if "%CHOICE%"=="5" goto END

echo Invalid choice, try again.
goto MENU

:RUN_BACKEND
echo Starting FastAPI backend...
REM Starts uvicorn in a new window to keep this script interactive
start "Cybersec Backend" cmd /k "call venv\Scripts\activate.bat && uvicorn main:app --reload --host %HOST% --port %PORT%"
goto MENU

:RUN_UI
echo Starting Streamlit UI...
start "Cybersec UI" cmd /k "call venv\Scripts\activate.bat && streamlit run ui\app.py"
goto MENU

:RUN_TESTS
echo Running pytest...
call venv\Scripts\activate.bat
pytest -q
echo Tests finished.
pause
goto MENU

:OPEN_FOLDER
start .
goto MENU

:END
echo Exiting setup.
endlocal
exit /b 0
