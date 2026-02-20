from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy import event
from sqlalchemy import func, or_, and_, text
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.dialects.sqlite import insert  # Use postgresql if using PostgreSQL
from flask_migrate import Migrate, upgrade
from alembic.runtime.migration import MigrationContext
from alembic.config import Config
from alembic.script import ScriptDirectory
from flask_login import UserMixin
from alembic import command
import os, sys
import shutil
import logging
import datetime
import threading
import time
import atexit
from app.constants import *

# Retrieve main logger
logger = logging.getLogger('main')

db = SQLAlchemy()
migrate = Migrate()

# Alembic functions
def get_alembic_cfg():
    cfg = Config(ALEMBIC_CONF)
    cfg.set_main_option("script_location", ALEMBIC_DIR)
    return cfg

def get_alembic_heads():
    alembic_cfg = get_alembic_cfg()
    script = ScriptDirectory.from_config(alembic_cfg)
    try:
        return script.get_heads()
    except Exception:
        return []

def get_current_db_version():
    engine = create_engine(AEROFOIL_DB)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        current_rev = context.get_current_revision()
        return current_rev or '0'
    
def create_db_backup():
    current_revision = get_current_db_version()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f".backup_v{current_revision}_{timestamp}.db"
    backup_path = os.path.join(CONFIG_DIR, backup_filename)
    shutil.copy2(DB_FILE, backup_path)
    logger.info(f"Database backup created: {backup_path}")
    
def is_migration_needed():
    alembic_cfg = get_alembic_cfg()
    script = ScriptDirectory.from_config(alembic_cfg)
    current_revision = get_current_db_version()
    heads = []
    latest_revision = None
    try:
        latest_revision = script.get_current_head()
        heads = [latest_revision] if latest_revision else []
    except Exception:
        heads = get_alembic_heads()
        if len(heads) > 1:
            logger.warning("Multiple alembic heads detected: %s", ", ".join(heads))

    if not heads:
        logger.info("Database version is up to date (%s)", current_revision)
        return False

    if current_revision not in heads:
        logger.info("Database migration needed, from %s to %s", current_revision, ", ".join(heads))
        return True

    logger.info("Database version is up to date (%s)", current_revision)
    return False

def to_dict(db_results):
    return {c.name: getattr(db_results, c.name) for c in db_results.__table__.columns}


def _coerce_app_version_num(raw_version):
    try:
        return int(raw_version or 0)
    except Exception:
        return 0

class Libraries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String, unique=True, nullable=False)
    last_scan = db.Column(db.DateTime)

class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    library_id = db.Column(db.Integer, db.ForeignKey('libraries.id', ondelete="CASCADE"), nullable=False)
    filepath = db.Column(db.String, unique=True, nullable=False)
    folder = db.Column(db.String)
    filename = db.Column(db.String, nullable=False)
    extension = db.Column(db.String)
    size = db.Column(db.Integer)
    compressed = db.Column(db.Boolean, default=False)
    multicontent = db.Column(db.Boolean, default=False)
    nb_content = db.Column(db.Integer, default=0)
    download_count = db.Column(db.Integer, default=0)
    identified = db.Column(db.Boolean, default=False)
    identification_type = db.Column(db.String)
    identification_error = db.Column(db.String)
    identification_attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime, default=datetime.datetime.now())

    library = db.relationship('Libraries', backref=db.backref('files', lazy=True, cascade="all, delete-orphan"))

    __table_args__ = (
        db.Index('idx_files_library_id', 'library_id'),
        db.Index('idx_files_filename', 'filename'),
        db.Index('idx_files_identified', 'identified'),
    )

class Titles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title_id = db.Column(db.String, unique=True)
    have_base = db.Column(db.Boolean, default=False)
    up_to_date = db.Column(db.Boolean, default=False)
    complete = db.Column(db.Boolean, default=False)

# Association table for many-to-many relationship between Apps and Files
app_files = db.Table('app_files',
    db.Column('app_id', db.Integer, db.ForeignKey('apps.id', ondelete="CASCADE"), primary_key=True),
    db.Column('file_id', db.Integer, db.ForeignKey('files.id', ondelete="CASCADE"), primary_key=True)
)
db.Index('idx_app_files_file_id', app_files.c.file_id)

class Apps(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title_id = db.Column(db.Integer, db.ForeignKey('titles.id', ondelete="CASCADE"), nullable=False)
    app_id = db.Column(db.String)
    app_version = db.Column(db.String)
    app_version_num = db.Column(db.Integer, default=0)
    app_type = db.Column(db.String)
    owned = db.Column(db.Boolean, default=False)

    title = db.relationship('Titles', backref=db.backref('apps', lazy=True, cascade="all, delete-orphan"))
    files = db.relationship('Files', secondary=app_files, backref=db.backref('apps', lazy='select'))

    __table_args__ = (
        db.UniqueConstraint('app_id', 'app_version', name='uq_apps_app_version'),
        db.Index('idx_apps_owned', 'owned'),
        db.Index('idx_apps_app_id', 'app_id'),
        db.Index('idx_apps_title_app_type', 'title_id', 'app_type'),
        db.Index('idx_apps_type_owned', 'app_type', 'owned'),
        db.Index('idx_apps_type_version_num', 'app_type', 'app_version_num'),
        db.Index('idx_apps_appid_type_version_num', 'app_id', 'app_type', 'app_version_num'),
    )


@event.listens_for(Apps, 'before_insert')
def _apps_before_insert(mapper, connection, target):
    target.app_version_num = _coerce_app_version_num(getattr(target, 'app_version', 0))


@event.listens_for(Apps, 'before_update')
def _apps_before_update(mapper, connection, target):
    target.app_version_num = _coerce_app_version_num(getattr(target, 'app_version', 0))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    admin_access = db.Column(db.Boolean)
    shop_access = db.Column(db.Boolean)
    backup_access = db.Column(db.Boolean)
    frozen = db.Column(db.Boolean, default=False)
    frozen_message = db.Column(db.String)

    @property
    def is_admin(self):
        return self.admin_access

    def has_shop_access(self):
        return bool(self.shop_access) and not bool(self.frozen)

    def has_backup_access(self):
        return self.backup_access
    
    def has_admin_access(self):
        return self.admin_access

    def has_access(self, access):
        if access == 'admin':
            return self.has_admin_access()
        elif access == 'shop':
            return self.has_shop_access()
        elif access == 'backup':
            return self.has_backup_access()


class TitleRequests(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    status = db.Column(db.String, nullable=False, default='open')
    title_id = db.Column(db.String, nullable=False)
    title_name = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('User', backref=db.backref('title_requests', lazy=True, cascade="all, delete-orphan"))


class TitleRequestViews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('title_requests.id', ondelete='CASCADE'), nullable=False)
    viewed_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'request_id', name='uq_title_request_views_user_request'),)

    user = db.relationship('User', backref=db.backref('title_request_views', lazy=True, cascade="all, delete-orphan"))
    request = db.relationship('TitleRequests', backref=db.backref('views', lazy=True, cascade="all, delete-orphan"))


class AccessEvents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    kind = db.Column(db.String, nullable=False)
    user = db.Column(db.String)
    remote_addr = db.Column(db.String)
    user_agent = db.Column(db.String)
    country = db.Column(db.String)
    country_code = db.Column(db.String)
    region = db.Column(db.String)
    city = db.Column(db.String)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    title_id = db.Column(db.String)
    file_id = db.Column(db.Integer)
    filename = db.Column(db.String)
    bytes_sent = db.Column(db.Integer)
    ok = db.Column(db.Boolean)
    status_code = db.Column(db.Integer)
    duration_ms = db.Column(db.Integer)


_ACCESS_EVENT_BUFFER_LOCK = threading.Lock()
_ACCESS_EVENT_BUFFER = []
_ACCESS_EVENT_BUFFER_MAX = 64
_ACCESS_EVENT_BUFFER_FLUSH_S = 1.0
_ACCESS_EVENT_LAST_FLUSH_TS = 0.0

_DOWNLOAD_COUNT_BUFFER_LOCK = threading.Lock()
_DOWNLOAD_COUNT_BUFFER = {}
_DOWNLOAD_COUNT_BUFFER_MAX = 128
_DOWNLOAD_COUNT_BUFFER_FLUSH_S = 1.5
_DOWNLOAD_COUNT_LAST_FLUSH_TS = 0.0


def flush_access_events_buffer(force=False):
    global _ACCESS_EVENT_LAST_FLUSH_TS
    now = time.time()
    with _ACCESS_EVENT_BUFFER_LOCK:
        if not _ACCESS_EVENT_BUFFER:
            _ACCESS_EVENT_LAST_FLUSH_TS = now
            return 0
        should_flush = force or len(_ACCESS_EVENT_BUFFER) >= _ACCESS_EVENT_BUFFER_MAX
        if not should_flush and (now - float(_ACCESS_EVENT_LAST_FLUSH_TS or 0.0)) >= _ACCESS_EVENT_BUFFER_FLUSH_S:
            should_flush = True
        if not should_flush:
            return 0
        batch = list(_ACCESS_EVENT_BUFFER)
        _ACCESS_EVENT_BUFFER.clear()
        _ACCESS_EVENT_LAST_FLUSH_TS = now

    try:
        db.session.bulk_insert_mappings(AccessEvents, batch)
        db.session.commit()
        return len(batch)
    except Exception:
        db.session.rollback()
        with _ACCESS_EVENT_BUFFER_LOCK:
            if batch:
                _ACCESS_EVENT_BUFFER[0:0] = batch
                if len(_ACCESS_EVENT_BUFFER) > 5000:
                    _ACCESS_EVENT_BUFFER[:] = _ACCESS_EVENT_BUFFER[-5000:]
        return 0


def queue_file_download_increment(file_id):
    global _DOWNLOAD_COUNT_LAST_FLUSH_TS
    try:
        file_id_int = int(file_id)
    except Exception:
        return False
    if file_id_int <= 0:
        return False

    now = time.time()
    with _DOWNLOAD_COUNT_BUFFER_LOCK:
        _DOWNLOAD_COUNT_BUFFER[file_id_int] = int(_DOWNLOAD_COUNT_BUFFER.get(file_id_int, 0)) + 1
        should_flush = len(_DOWNLOAD_COUNT_BUFFER) >= _DOWNLOAD_COUNT_BUFFER_MAX
        if not should_flush and (now - float(_DOWNLOAD_COUNT_LAST_FLUSH_TS or 0.0)) >= _DOWNLOAD_COUNT_BUFFER_FLUSH_S:
            should_flush = True
    if should_flush:
        flush_file_download_increments(force=False)
    return True


def flush_file_download_increments(force=False):
    global _DOWNLOAD_COUNT_LAST_FLUSH_TS
    now = time.time()
    with _DOWNLOAD_COUNT_BUFFER_LOCK:
        if not _DOWNLOAD_COUNT_BUFFER:
            _DOWNLOAD_COUNT_LAST_FLUSH_TS = now
            return 0
        should_flush = force or len(_DOWNLOAD_COUNT_BUFFER) >= _DOWNLOAD_COUNT_BUFFER_MAX
        if not should_flush and (now - float(_DOWNLOAD_COUNT_LAST_FLUSH_TS or 0.0)) >= _DOWNLOAD_COUNT_BUFFER_FLUSH_S:
            should_flush = True
        if not should_flush:
            return 0
        pending = dict(_DOWNLOAD_COUNT_BUFFER)
        _DOWNLOAD_COUNT_BUFFER.clear()
        _DOWNLOAD_COUNT_LAST_FLUSH_TS = now

    try:
        for file_id, count in pending.items():
            if count <= 0:
                continue
            (
                db.session.query(Files)
                .filter(Files.id == file_id)
                .update({Files.download_count: Files.download_count + int(count)}, synchronize_session=False)
            )
        db.session.commit()
        return len(pending)
    except Exception:
        db.session.rollback()
        with _DOWNLOAD_COUNT_BUFFER_LOCK:
            for file_id, count in pending.items():
                _DOWNLOAD_COUNT_BUFFER[file_id] = int(_DOWNLOAD_COUNT_BUFFER.get(file_id, 0)) + int(count or 0)
                if len(_DOWNLOAD_COUNT_BUFFER) > 10000:
                    break
        return 0


def add_access_event(
    kind,
    user=None,
    remote_addr=None,
    user_agent=None,
    country=None,
    country_code=None,
    region=None,
    city=None,
    latitude=None,
    longitude=None,
    title_id=None,
    file_id=None,
    filename=None,
    bytes_sent=None,
    ok=None,
    status_code=None,
    duration_ms=None,
):
    try:
        payload = {
            'at': datetime.datetime.utcnow(),
            'kind': kind,
            'user': user,
            'remote_addr': remote_addr,
            'user_agent': user_agent,
            'country': country,
            'country_code': country_code,
            'region': region,
            'city': city,
            'latitude': latitude,
            'longitude': longitude,
            'title_id': title_id,
            'file_id': file_id,
            'filename': filename,
            'bytes_sent': bytes_sent,
            'ok': ok,
            'status_code': int(status_code) if status_code is not None else None,
            'duration_ms': duration_ms,
        }
        with _ACCESS_EVENT_BUFFER_LOCK:
            _ACCESS_EVENT_BUFFER.append(payload)
        flush_access_events_buffer(force=False)
        return True
    except Exception:
        return False


def get_access_events(limit=100, kind=None, kinds=None):
    flush_access_events_buffer(force=True)
    try:
        limit = int(limit)
    except Exception:
        limit = 100
    limit = max(1, min(limit, 1000))

    q = AccessEvents.query
    if kinds:
        try:
            kinds = [str(k) for k in kinds if k is not None and str(k).strip()]
        except Exception:
            kinds = []
        if kinds:
            q = q.filter(AccessEvents.kind.in_(kinds))
    elif kind:
        q = q.filter_by(kind=str(kind))

    events = q.order_by(AccessEvents.at.desc()).limit(limit).all()
    out = []
    for e in events:
        out.append({
            'id': e.id,
            'at': int(e.at.timestamp()) if e.at else None,
            'kind': e.kind,
            'user': e.user,
            'remote_addr': e.remote_addr,
            'user_agent': e.user_agent,
            'country': e.country,
            'country_code': e.country_code,
            'region': e.region,
            'city': e.city,
            'latitude': e.latitude,
            'longitude': e.longitude,
            'title_id': e.title_id,
            'file_id': e.file_id,
            'filename': e.filename,
            'bytes_sent': e.bytes_sent,
            'ok': e.ok,
            'status_code': e.status_code,
            'duration_ms': e.duration_ms,
        })
    return out


def delete_access_events(kind=None, kinds=None):
    flush_access_events_buffer(force=True)
    try:
        q = AccessEvents.query
        if kinds:
            try:
                kinds = [str(k) for k in kinds if k is not None and str(k).strip()]
            except Exception:
                kinds = []
            if kinds:
                q = q.filter(AccessEvents.kind.in_(kinds))
        elif kind:
            q = q.filter_by(kind=str(kind))

        q.delete(synchronize_session=False)
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def delete_access_events_excluding(kinds=None):
    """Delete access events excluding the provided kinds."""
    flush_access_events_buffer(force=True)
    try:
        q = AccessEvents.query
        if kinds:
            try:
                kinds = [str(k) for k in kinds if k is not None and str(k).strip()]
            except Exception:
                kinds = []
            if kinds:
                q = q.filter(~AccessEvents.kind.in_(kinds))

        q.delete(synchronize_session=False)
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _sqlite_column_exists(table_name, column_name):
    rows = db.session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    for row in rows:
        try:
            if str(row[1]) == str(column_name):
                return True
        except Exception:
            continue
    return False


def ensure_performance_schema():
    try:
        dialect = (db.engine.dialect.name or '').lower()
    except Exception:
        dialect = ''

    if dialect != 'sqlite':
        return

    try:
        added_column = False
        if not _sqlite_column_exists('apps', 'app_version_num'):
            db.session.execute(text("ALTER TABLE apps ADD COLUMN app_version_num INTEGER"))
            db.session.commit()
            added_column = True

        db.session.execute(text("""
            UPDATE apps
            SET app_version_num = CAST(COALESCE(NULLIF(app_version, ''), '0') AS INTEGER)
            WHERE app_version_num IS NULL
        """))
        db.session.commit()

        ddl_statements = [
            "CREATE INDEX IF NOT EXISTS idx_app_files_file_id ON app_files(file_id)",
            "CREATE INDEX IF NOT EXISTS idx_apps_title_app_type ON apps(title_id, app_type)",
            "CREATE INDEX IF NOT EXISTS idx_apps_type_owned ON apps(app_type, owned)",
            "CREATE INDEX IF NOT EXISTS idx_apps_type_version_num ON apps(app_type, app_version_num)",
            "CREATE INDEX IF NOT EXISTS idx_apps_appid_type_version_num ON apps(app_id, app_type, app_version_num)",
        ]
        for ddl in ddl_statements:
            db.session.execute(text(ddl))
        db.session.commit()
        if added_column:
            logger.info("Added apps.app_version_num and applied performance indexes.")
        else:
            logger.info("Performance indexes verified for SQLite database.")
    except Exception as e:
        db.session.rollback()
        logger.warning("Failed to apply performance schema optimizations: %s", e)


def ensure_access_events_geo_schema():
    try:
        if db.engine.dialect.name != 'sqlite':
            return
    except Exception:
        return

    try:
        result = db.session.execute(text("PRAGMA table_info(access_events)"))
        existing = {row[1] for row in result if row and len(row) > 1}
    except Exception as e:
        logger.warning("Failed to read access_events schema: %s", e)
        return

    columns = [
        ('country', 'TEXT'),
        ('country_code', 'TEXT'),
        ('region', 'TEXT'),
        ('city', 'TEXT'),
        ('latitude', 'REAL'),
        ('longitude', 'REAL'),
    ]

    try:
        added = False
        for name, col_type in columns:
            if name in existing:
                continue
            ddl = f"ALTER TABLE access_events ADD COLUMN {name} {col_type}"
            db.session.execute(text(ddl))
            added = True
        if added:
            db.session.commit()
            logger.info("Added missing geo columns to access_events.")
    except Exception as e:
        db.session.rollback()
        logger.warning("Failed to apply access_events geo schema: %s", e)


def init_db(app):
    with app.app_context():
        # Ensure foreign keys are enforced when the SQLite connection is opened
        @event.listens_for(db.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()

        # create or migrate database
        if "db" not in sys.argv:
            if not os.path.exists(DB_FILE):
                db.create_all()
                command.stamp(get_alembic_cfg(), "head")
                logger.info("Database created and stamped to the latest migration version.")
            else:
                logger.info('Checking database migration...')
                if is_migration_needed():
                    create_db_backup()
                    command.upgrade(get_alembic_cfg(), "head")
                    logger.info("Database migration applied successfully.")
            ensure_performance_schema()
            ensure_access_events_geo_schema()

def file_exists_in_db(filepath):
    return Files.query.filter_by(filepath=filepath).first() is not None

def get_file_from_db(file_id):
    return Files.query.filter_by(id=file_id).first()

def update_file_path(library, old_path, new_path):
    try:
        # Find the file entry in the database using the old_path
        file_entry = Files.query.filter_by(filepath=old_path).one()

        # Extract the new folder and filename from the new_path
        folder = os.path.dirname(new_path)
        if os.path.normpath(library) == os.path.normpath(folder):
            # file is at the root of the library
            new_folder = ''
        else:
            new_folder = folder.replace(library, '')
            new_folder = '/' + new_folder if not new_folder.startswith('/') else new_folder

        filename = os.path.basename(new_path)

        # Update the file entry with the new path values
        file_entry.filename = filename
        file_entry.filepath = new_path
        file_entry.folder = new_folder
        
        # Commit the changes to the database
        db.session.commit()

        logger.debug(f"File path updated successfully from {old_path} to {new_path}.")
    
    except NoResultFound:
        logger.warning(f"No file entry found for the path: {old_path}.")
    except Exception as e:
        db.session.rollback()  # Roll back the session in case of an error
        logger.error(f"An error occurred while updating the file path: {str(e)}")

def get_all_titles_from_db():
    results = Files.query.all()
    return [to_dict(r) for r in results]

def get_all_title_files(title_id):
    title_id = title_id.upper()
    results = Files.query.filter_by(title_id=title_id).all()
    return [to_dict(r) for r in results]

def get_all_files_with_identification(identification):
    results = Files.query.filter_by(identification_type=identification).all()
    return[to_dict(r)['filepath']  for r in results]

def get_all_files_without_identification(identification):
    results = Files.query.filter(Files.identification_type != identification).all()
    return[to_dict(r)['filepath']  for r in results]

def _derive_title_id_from_app(app_id, app_type):
    app_id = str(app_id or '').upper()
    app_type = str(app_type or '').upper()
    if len(app_id) != 16:
        return None
    try:
        if app_type == APP_TYPE_BASE:
            return app_id
        if app_type == APP_TYPE_UPD:
            return f"{app_id[:-3]}000"
        if app_type == APP_TYPE_DLC:
            base = app_id[:-3]
            return (hex(int(base, base=16) - 1)[2:].rjust(len(base), '0') + '000').upper()
    except Exception:
        return None
    return None

def get_all_apps():
    size_subquery = (
        db.session.query(
            app_files.c.app_id.label('app_pk'),
            func.coalesce(func.sum(Files.size), 0).label('size'),
        )
        .outerjoin(Files, Files.id == app_files.c.file_id)
        .group_by(app_files.c.app_id)
        .subquery()
    )
    rows = (
        db.session.query(
            Apps.id.label('id'),
            Apps.title_id.label('title_fk_id'),
            Titles.id.label('title_db_id'),
            Titles.title_id.label('title_id'),
            Apps.app_id.label('app_id'),
            Apps.app_version.label('app_version'),
            Apps.app_type.label('app_type'),
            Apps.owned.label('owned'),
            func.coalesce(size_subquery.c.size, 0).label('size'),
        )
        .outerjoin(Titles, Apps.title_id == Titles.id)
        .outerjoin(size_subquery, size_subquery.c.app_pk == Apps.id)
        .all()
    )
    out = []
    missing_title_refs = 0
    for row in rows:
        title_id = row.title_id or _derive_title_id_from_app(row.app_id, row.app_type)
        if row.title_id is None:
            missing_title_refs += 1
        out.append({
            "id": row.id,
            "title_db_id": row.title_db_id if row.title_db_id is not None else row.title_fk_id,
            "title_id": title_id,
            "app_id": row.app_id,
            "app_version": row.app_version,
            "app_type": row.app_type,
            "owned": row.owned,
            "size": int(row.size or 0),
        })
    if missing_title_refs:
        logger.warning(
            "Detected %s app rows without matching titles rows; using fallback title_id derivation.",
            missing_title_refs
        )
    return out

def get_all_non_identified_files_from_library(library_id):
    return Files.query.filter_by(identified=False, library_id=library_id).all()

def get_files_with_identification_from_library(library_id, identification_type):
    return Files.query.filter_by(library_id=library_id, identification_type=identification_type).all()

def get_shop_files():
    results = Files.query.all()
    shop_files = [{
        "id": file.id,
        "filename": file.filename,
        "size": file.size
    } for file in results]
    return shop_files

def get_libraries():
    return Libraries.query.all()

def get_libraries_path():
    libraries = Libraries.query.all()
    return [l.path for l in libraries]

def add_library(library_path):
    stmt = insert(Libraries).values(path=library_path).on_conflict_do_nothing()
    db.session.execute(stmt)
    db.session.commit()

def delete_library(library):
    if not (isinstance(library, int) or library.isdigit()):
        library = get_library_id(library)
        
    db.session.delete(get_library(library))
    db.session.commit()

def get_library(library_id):
    return Libraries.query.filter_by(id=library_id).first()

def get_library_path(library_id):
    library_path = None
    library = Libraries.query.filter_by(id=library_id).first()
    if library:
        library_path = library.path
    return library_path

def get_library_id(library_path):
    library_id = None
    library = Libraries.query.filter_by(path=library_path).first()
    if library:
        library_id = library.id
    return library_id

def get_library_file_paths(library_id):
    return list(iter_library_file_paths(library_id))

def iter_library_file_paths(library_id, batch_size=2000):
    try:
        batch_size = max(1, int(batch_size))
    except Exception:
        batch_size = 2000
    query = (
        db.session.query(Files.filepath)
        .filter_by(library_id=library_id)
        .yield_per(batch_size)
    )
    for filepath, in query:
        yield filepath

def _files_to_identify_query(library_id, include_filename_retry=False, include_orphaned=False):
    query = db.session.query(Files.id).filter(Files.library_id == library_id)
    predicates = [Files.identified.is_(False)]
    if include_filename_retry:
        predicates.append(Files.identification_type == 'filename')
    if include_orphaned:
        orphaned = ~db.session.query(app_files.c.file_id).filter(app_files.c.file_id == Files.id).exists()
        predicates.append(orphaned)
    query = query.filter(or_(*predicates))
    return query.order_by(Files.id)

def iter_file_ids_for_identification(library_id, include_filename_retry=False, include_orphaned=False, batch_size=1000):
    try:
        batch_size = max(1, int(batch_size))
    except Exception:
        batch_size = 1000
    query = _files_to_identify_query(
        library_id,
        include_filename_retry=include_filename_retry,
        include_orphaned=include_orphaned
    ).yield_per(batch_size)
    for file_id, in query:
        yield file_id

def count_file_ids_for_identification(library_id, include_filename_retry=False, include_orphaned=False):
    return _files_to_identify_query(
        library_id,
        include_filename_retry=include_filename_retry,
        include_orphaned=include_orphaned
    ).count()

def set_library_scan_time(library_id, scan_time=None):
    library = get_library(library_id)
    library.last_scan = scan_time or datetime.datetime.now()
    db.session.commit()

def get_all_titles():
    return Titles.query.all()

def get_title(title_id):
    return Titles.query.filter_by(title_id=title_id).first()

def get_title_id_db_id(title_id):
    title = get_title(title_id)
    return title.id

def add_title_id_in_db(title_id):
    existing_title = Titles.query.filter_by(title_id=title_id).first()
    
    if not existing_title:
        new_title = Titles(title_id=title_id)
        db.session.add(new_title)
        db.session.commit()

def get_all_title_apps(title_id):
    size_subquery = (
        db.session.query(
            app_files.c.app_id.label('app_pk'),
            func.coalesce(func.sum(Files.size), 0).label('size'),
        )
        .outerjoin(Files, Files.id == app_files.c.file_id)
        .group_by(app_files.c.app_id)
        .subquery()
    )
    rows = (
        db.session.query(
            Apps.id.label('id'),
            Apps.title_id.label('title_id'),
            Apps.app_id.label('app_id'),
            Apps.app_version.label('app_version'),
            Apps.app_type.label('app_type'),
            Apps.owned.label('owned'),
            func.coalesce(size_subquery.c.size, 0).label('size'),
        )
        .join(Titles, Apps.title_id == Titles.id)
        .outerjoin(size_subquery, size_subquery.c.app_pk == Apps.id)
        .filter(Titles.title_id == title_id)
        .all()
    )
    return [
        {
            'id': row.id,
            'title_id': row.title_id,
            'app_id': row.app_id,
            'app_version': row.app_version,
            'app_type': row.app_type,
            'owned': row.owned,
            'size': int(row.size or 0),
        }
        for row in rows
    ]

def get_app_by_id_and_version(app_id, app_version):
    """Get app entry for a specific app_id and version (unique due to constraint)"""
    return Apps.query.filter_by(app_id=app_id, app_version=app_version).first()

def get_app_files(app_id, app_version):
    """Get all file_ids associated with a specific app_id and version"""
    app = get_app_by_id_and_version(app_id, app_version)
    return [f.id for f in app.files] if app else []

def is_app_owned(app_id, app_version):
    """Check if an app is owned (has at least one file associated with it)"""
    app = get_app_by_id_and_version(app_id, app_version)
    return app.owned if app else False

def add_file_to_app(app_id, app_version, file_id):
    """Add a file to an existing app using many-to-many relationship"""
    app = get_app_by_id_and_version(app_id, app_version)
    if app:
        file_obj = get_file_from_db(file_id)
        if file_obj and file_obj not in app.files:
            app.files.append(file_obj)
            app.owned = True
            db.session.commit()
            return True
    return False

def remove_file_from_apps(file_id):
    """Remove a file from all apps that reference it and update owned status"""
    apps_updated = 0
    file_obj = get_file_from_db(file_id)
    
    if file_obj:
        # Get all apps associated with this file using the many-to-many relationship
        associated_apps = file_obj.apps
        
        for app in associated_apps:
            # Remove the file from the app's files relationship
            app.files.remove(file_obj)
            
            # Update owned status based on remaining files
            app.owned = len(app.files) > 0
            apps_updated += 1
            
            logger.debug(f"Removed file_id {file_id} from app {app.app_id} v{app.app_version}. Owned: {app.owned}")
        
        if apps_updated > 0:
            db.session.commit()
    
    return apps_updated

def has_owned_apps(title_id):
    """Check if a title has any owned apps"""
    title = get_title(title_id)
    if not title:
        return False
    
    owned_apps = Apps.query.filter_by(title_id=title.id, owned=True).first()
    return owned_apps is not None

def remove_titles_without_owned_apps():
    """Remove titles that have no owned apps"""
    titles_removed = 0
    titles = get_all_titles()
    
    for title in titles:
        if not has_owned_apps(title.title_id):
            logger.debug(f"Removing title {title.title_id} - no owned apps remaining")
            db.session.delete(title)
            titles_removed += 1
    
    return titles_removed

def delete_files_by_library(library_path):
    success = True
    errors = []
    try:
        # Find all files with the given library
        files_to_delete = Files.query.filter_by(library=library_path).all()
        
        # Update Apps table before deleting files
        total_apps_updated = 0
        for file in files_to_delete:
            apps_updated = remove_file_from_apps(file.id)
            total_apps_updated += apps_updated
        
        # Delete each file
        for file in files_to_delete:
            db.session.delete(file)
        
        # Commit the changes
        db.session.commit()
        
        logger.info(f"All entries with library '{library_path}' have been deleted.")
        if total_apps_updated > 0:
            logger.info(f"Updated {total_apps_updated} app entries to remove library file references.")
        return success, errors
    except Exception as e:
        # If there's an error, rollback the session
        db.session.rollback()
        logger.error(f"An error occurred: {e}")
        success = False
        errors.append({
            'path': 'library/paths',
            'error': f"An error occurred: {e}"
        })
        return success, errors

def delete_files_by_filepaths_batch(filepaths, commit=True):
    """Delete files and update app ownership in a single batched transaction."""
    try:
        unique_paths = list(dict.fromkeys([str(path) for path in (filepaths or []) if path]))
    except Exception:
        unique_paths = []
    if not unique_paths:
        return 0, 0

    file_ids = [
        row.id
        for row in db.session.query(Files.id).filter(Files.filepath.in_(unique_paths)).all()
    ]
    if not file_ids:
        return 0, 0

    affected_app_ids = [
        row.app_id
        for row in (
            db.session.query(app_files.c.app_id)
            .filter(app_files.c.file_id.in_(file_ids))
            .distinct()
            .all()
        )
    ]

    db.session.execute(app_files.delete().where(app_files.c.file_id.in_(file_ids)))
    deleted_count = (
        db.session.query(Files)
        .filter(Files.id.in_(file_ids))
        .delete(synchronize_session=False)
    )

    apps_updated = 0
    if affected_app_ids:
        apps_updated = len(affected_app_ids)
        has_files_expr = (
            db.session.query(app_files.c.app_id)
            .filter(app_files.c.app_id == Apps.id)
            .exists()
        )
        (
            db.session.query(Apps)
            .filter(Apps.id.in_(affected_app_ids))
            .update({Apps.owned: has_files_expr}, synchronize_session=False)
        )

    if commit:
        db.session.commit()
    return int(deleted_count or 0), int(apps_updated or 0)

def delete_file_by_filepath(filepath):
    try:
        deleted_count, apps_updated = delete_files_by_filepaths_batch([filepath], commit=True)
        if deleted_count <= 0:
            logger.info(f"File '{filepath}' not present in database.")
            return

        logger.info(f"File '{filepath}' removed from database.")
        if apps_updated > 0:
            logger.info(f"Updated {apps_updated} app entries to remove file reference.")
            
    except Exception as e:
        # If there's an error, rollback the session
        db.session.rollback()
        logger.error(f"An error occurred while removing the file path: {str(e)}")

def remove_missing_files_from_db():
    try:
        batch_size = 500
        last_id = 0
        total_deleted = 0
        total_apps_updated = 0

        while True:
            rows = (
                db.session.query(Files.id, Files.filepath)
                .filter(Files.id > last_id)
                .order_by(Files.id)
                .limit(batch_size)
                .all()
            )
            if not rows:
                break
            last_id = rows[-1].id

            ids_to_delete = []
            for row in rows:
                if not row.filepath or not os.path.exists(row.filepath):
                    ids_to_delete.append(row.id)
                    logger.debug(f"File not found, marking file for deletion: {row.filepath}")

            if not ids_to_delete:
                db.session.expunge_all()
                continue

            ids_to_delete_set = set(ids_to_delete)
            filepaths_to_delete = [
                row.filepath
                for row in rows
                if row.id in ids_to_delete_set and row.filepath
            ]
            deleted_count, apps_updated = delete_files_by_filepaths_batch(filepaths_to_delete, commit=True)
            total_deleted += deleted_count
            total_apps_updated += apps_updated
            db.session.expunge_all()

        if total_deleted > 0:
            logger.info(f"Deleted {total_deleted} files from the database.")
            if total_apps_updated > 0:
                logger.info(f"Updated {total_apps_updated} app entries to remove missing file references.")
        else:
            logger.debug("No files were deleted. All files are present on disk.")
    
    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        logger.error(f"An error occurred while removing missing files: {str(e)}")


@atexit.register
def _flush_db_buffers_at_exit():
    try:
        flush_access_events_buffer(force=True)
    except Exception:
        pass
    try:
        flush_file_download_increments(force=True)
    except Exception:
        pass
