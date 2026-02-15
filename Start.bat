@echo off
REM set "AEROFOIL_VERSION=dev"
REM set "AEROFOIL_TRUST_PROXY_HEADERS=1"
REM set "AEROFOIL_TRUSTED_PROXIES=127.0.0.1,192.168.1.0/24"

REM Reuse an existing key if it is already set in the current environment.
if not defined AEROFOIL_SECRET_KEY (
    REM Fallback: try to read a persisted user-level key from the registry.
    for /f "tokens=2,*" %%A in ('reg query "HKCU\Environment" /v AEROFOIL_SECRET_KEY 2^>nul ^| findstr /I "AEROFOIL_SECRET_KEY"') do (
        set "AEROFOIL_SECRET_KEY=%%B"
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

    setx AEROFOIL_SECRET_KEY "%AEROFOIL_SECRET_KEY%" >nul 2>&1
    echo Generated and persisted AEROFOIL_SECRET_KEY for this user.
)

set "AEROFOIL_WSGI_THREADS=32"
python.exe .\app\app.py
