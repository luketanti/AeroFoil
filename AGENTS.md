# Repository Guidelines

## Project Structure & Module Organization
`app/` contains the Flask application, HTML templates, static assets, migrations, and feature modules such as `downloads/`, `library.py`, and `settings.py`. The main entrypoint is `app/app.py`. Tests live in `tests/` and follow focused module-based coverage such as `test_download_clients.py` and `test_library_helpers.py`. Deployment files are at the repo root (`Dockerfile`, `docker-compose.yml`, `docker-compose.dev.yml`), with helper scripts in `tools/`, `run.bat`, and `start.sh`.

## Build, Test, and Development Commands
Install dependencies with:

```bash
pip install -r requirements.txt
```

Run locally with:

```bash
python app/app.py
```

On Windows, `run.bat` bootstraps `.venv`, installs requirements, pulls latest changes, and starts the app. On Unix-like systems, `./start.sh` exports bootstrap credentials and runs `python app/app.py`.

Run all tests with:

```bash
python -m unittest discover -s tests
```

Run a focused suite while iterating:

```bash
python -m unittest tests.test_download_clients
```

Use Docker when validating container behavior:

```bash
docker compose -f docker-compose.dev.yml up --build
```

## Coding Style & Naming Conventions
Use 4-space indentation and keep Python code straightforward rather than overly abstract. Follow existing naming patterns: `snake_case` for functions and variables, `UPPER_CASE` for constants, and `CamelCase` for test classes. Prefer small helper functions in `app/` modules over duplicating logic in routes. Keep template JavaScript defensive around nullable API fields.

## Testing Guidelines
Tests use the standard library `unittest` framework with `unittest.mock.patch`. Add or update targeted tests for every behavioral fix, especially around downloads, library organization, and request handling. Name new files `tests/test_<area>.py` and keep tests deterministic and filesystem-light where possible. Use synthetic fixture data only: no real game names, personal directories, or production-like local paths in tests. Prefer placeholders such as `Example Title`, `Example Release NSW-GRP`, and `X:\fixture-root\...`.

## Commit & Pull Request Guidelines
Match the existing history: short imperative subjects, often Conventional Commit style such as `fix: improve downloads queue display and layout` or `feat: add SABnzbd support`. Keep commits scoped to one change. PRs should describe the user-visible impact, note any config or migration implications, link related issues, and include screenshots for UI/template changes.

## Security & Configuration Tips
Do not commit secrets, `keys.txt`, or real API credentials. Prefer `AEROFOIL_*` environment variables over legacy `OWNFOIL_*` names. For production, set a strong `AEROFOIL_SECRET_KEY` and validate proxy settings before enabling trusted forwarded headers.
