@echo off
REM set "AEROFOIL_VERSION=dev"
REM set "AEROFOIL_TRUST_PROXY_HEADERS=1"
REM set "AEROFOIL_TRUSTED_PROXIES=127.0.0.1,192.168.1.0/24"

REM Keep backward compatibility with legacy OWNFOIL_SECRET_KEY while preferring AEROFOIL_SECRET_KEY.
set "PERSIST_AEROFOIL_SECRET_KEY=0"
if not defined AEROFOIL_SECRET_KEY (
    if defined OWNFOIL_SECRET_KEY (
        set "AEROFOIL_SECRET_KEY=%OWNFOIL_SECRET_KEY%"
        set "PERSIST_AEROFOIL_SECRET_KEY=1"
    )
)

REM Reuse an existing key if it is already set in the current environment or persisted registry.
if not defined AEROFOIL_SECRET_KEY (
    REM Fallback: try to read a persisted user-level key from the registry.
    for /f "tokens=2,*" %%A in ('reg query "HKCU\Environment" /v AEROFOIL_SECRET_KEY 2^>nul ^| findstr /I "AEROFOIL_SECRET_KEY"') do (
        set "AEROFOIL_SECRET_KEY=%%B"
    )
)

REM Legacy fallback: migrate persisted OWNFOIL_SECRET_KEY to AEROFOIL_SECRET_KEY.
if not defined AEROFOIL_SECRET_KEY (
    for /f "tokens=2,*" %%A in ('reg query "HKCU\Environment" /v OWNFOIL_SECRET_KEY 2^>nul ^| findstr /I "OWNFOIL_SECRET_KEY"') do (
        set "AEROFOIL_SECRET_KEY=%%B"
        set "PERSIST_AEROFOIL_SECRET_KEY=1"
    )
)

REM Generate and persist a secure key when it does not exist yet.
if not defined AEROFOIL_SECRET_KEY (
    for /f "usebackq delims=" %%K in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$b = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ($b | ForEach-Object { $_.ToString('x2') }) -join ''"`) do (
        set "AEROFOIL_SECRET_KEY=%%K"
    )

    if not defined AEROFOIL_SECRET_KEY (
        echo Failed to generate AEROFOIL_SECRET_KEY.
        exit /b 1
    )

    set "PERSIST_AEROFOIL_SECRET_KEY=1"
)

if "%PERSIST_AEROFOIL_SECRET_KEY%"=="1" (
    setx AEROFOIL_SECRET_KEY "%AEROFOIL_SECRET_KEY%" >nul 2>&1
    echo Persisted AEROFOIL_SECRET_KEY for this user.
)

set "AEROFOIL_WSGI_THREADS=32"
python.exe .\app\app.py
