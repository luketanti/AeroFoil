import os
import shutil
import sqlite3
import unittest
from unittest.mock import patch

from flask import Flask

from app import library
from app.db import Files, Libraries, db


class IdentifyLibraryFilesLockTests(unittest.TestCase):
    def test_write_lock_is_free_when_each_file_is_identified(self):
        root = os.path.abspath(os.path.join(".tmp", "identify-lock-tests"))
        shutil.rmtree(root, ignore_errors=True)
        os.makedirs(root)
        self.addCleanup(shutil.rmtree, root, True)
        db_path = os.path.join(root, "test.db")
        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
        db.init_app(app)
        lock_free = []

        def identify_file(filepath):
            conn = sqlite3.connect(db_path, timeout=0)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
                lock_free.append(True)
            except sqlite3.OperationalError:
                lock_free.append(False)
            finally:
                conn.close()
            title_id = f"010000000000{filepath[-5]}000"
            return "cnmt", True, [{"title_id": title_id, "app_id": title_id, "type": "BASE", "version": 0}], None

        with app.app_context():
            db.create_all()
            lib = Libraries(path=root)
            db.session.add(lib)
            db.session.commit()
            for index in range(3):
                path = os.path.join(root, f"Example Title {index}.nsp")
                open(path, "wb").close()
                db.session.add(Files(library_id=lib.id, filepath=path, filename=os.path.basename(path)))
            db.session.commit()

            with patch.object(library.titles_lib, "identify_file", side_effect=identify_file), \
                    patch.object(library.titles_lib, "keys_loaded", return_value=False):
                library.identify_library_files(lib.id)
            db.session.remove()
            db.engine.dispose()

        self.assertEqual(lock_free, [True, True, True])


if __name__ == "__main__":
    unittest.main()
