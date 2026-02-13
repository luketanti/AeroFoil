@echo off
REM set "AEROFOIL_VERSION=dev"
REM set "AEROFOIL_TRUST_PROXY_HEADERS=1"
REM set "AEROFOIL_TRUSTED_PROXIES=127.0.0.1,192.168.1.0/24"
REM The below key is for development use only!! Do not use it for deployment
set "AEROFOIL_SECRET_KEY=MyyR9E6O9mAeJMUTtsBgLxbuY9OZdT742psExUsnPnT72veQ7rnPkAdhiDNihNR_KPvCj5K85DgL0Rmo4hUiSQ"
set "AEROFOIL_WSGI_THREADS=32"
python.exe .\app\app.py

