import os
import shutil
import struct
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from app import local_file_metadata


class LocalFileMetadataCompressedTests(unittest.TestCase):
    def setUp(self):
        self.test_root = os.path.join(
            os.getcwd(),
            ".tmp",
            "local-metadata-tests",
            "case-compressed",
        )
        shutil.rmtree(self.test_root, ignore_errors=True)
        os.makedirs(self.test_root, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_root, ignore_errors=True)

    def _touch(self, path, payload=b"fixture"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(payload)

    def test_extract_local_metadata_nsz_routes_to_nsp_parser(self):
        nsz_path = os.path.join(self.test_root, "Example Title.nsz")
        self._touch(nsz_path)

        with patch.object(
            local_file_metadata,
            "resolve_switch_guides_scripts_dir",
            return_value="app/vendor/switch_ghidra_scripts",
        ), patch.object(
            local_file_metadata,
            "_load_switch_guides_modules",
            return_value={},
        ), patch.object(
            local_file_metadata,
            "_extract_from_nsp",
            return_value={"title_id": "0100AAAABBBBCCCC"},
        ) as extract_nsp:
            out = local_file_metadata.extract_local_metadata(
                nsz_path,
                preferred_language="en",
                preferred_region="US",
            )

        self.assertEqual(out.get("title_id"), "0100AAAABBBBCCCC")
        extract_nsp.assert_called_once()

    def test_extract_local_metadata_xcz_uses_decompress_then_xci_parser(self):
        xcz_path = os.path.join(self.test_root, "Example Title.xcz")
        self._touch(xcz_path)

        with patch.object(
            local_file_metadata,
            "resolve_switch_guides_scripts_dir",
            return_value="app/vendor/switch_ghidra_scripts",
        ), patch.object(
            local_file_metadata,
            "_load_switch_guides_modules",
            return_value={},
        ), patch.object(
            local_file_metadata,
            "_extract_from_xci",
            return_value={"title_id": "0100DDDDEEEEFFFF"},
        ) as extract_xci:
            out = local_file_metadata.extract_local_metadata(
                xcz_path,
                preferred_language="en",
                preferred_region="US",
            )

        self.assertEqual(out.get("title_id"), "0100DDDDEEEEFFFF")
        extract_xci.assert_called_once()

    def test_extract_local_metadata_nsz_uses_persistent_cache_after_first_parse(self):
        nsz_path = os.path.join(self.test_root, "Cached Title.nsz")
        cache_dir = Path(self.test_root) / "cache"
        self._touch(nsz_path)

        with patch.object(
            local_file_metadata,
            "DEFAULT_LOCAL_METADATA_CACHE_DIR",
            cache_dir,
        ), patch.object(
            local_file_metadata,
            "resolve_switch_guides_scripts_dir",
            return_value="app/vendor/switch_ghidra_scripts",
        ), patch.object(
            local_file_metadata,
            "_load_switch_guides_modules",
            return_value={},
        ), patch.object(
            local_file_metadata,
            "_extract_from_nsp",
            return_value={"title_id": "0100AAAABBBBCCCC", "icon_bytes": b"abc"},
        ) as extract_nsp:
            out_first = local_file_metadata.extract_local_metadata(
                nsz_path,
                preferred_language="en",
                preferred_region="US",
            )
            out_second = local_file_metadata.extract_local_metadata(
                nsz_path,
                preferred_language="en",
                preferred_region="US",
            )

        self.assertEqual(out_first.get("title_id"), "0100AAAABBBBCCCC")
        self.assertEqual(out_second.get("title_id"), "0100AAAABBBBCCCC")
        self.assertEqual(extract_nsp.call_count, 1)


def _partition(magic, files, entry_size):
    names = b"".join(name.encode() + b"\0" for name, _ in files)
    entries, offset, name_offset = b"", 0, 0
    for name, data in files:
        entries += struct.pack("<QQI", offset, len(data), name_offset).ljust(entry_size, b"\0")
        offset, name_offset = offset + len(data), name_offset + len(name) + 1
    header = magic + struct.pack("<III", len(files), len(names), 0) + entries + names
    return header, b"".join(data for _, data in files)


class LocalFileMetadataControlNcaTests(unittest.TestCase):
    # Only the CNMT and the Control NCA may be read in full: decrypting every
    # candidate NCA to check its type OOM-killed the app on multi-GiB NCAs.

    def _extract(self, extractor, payload):
        root = os.path.join(os.getcwd(), ".tmp", "local-metadata-tests", "case-control-nca")
        shutil.rmtree(root, ignore_errors=True)
        os.makedirs(root)
        self.addCleanup(shutil.rmtree, root, True)
        path = os.path.join(root, "Example Title")
        with open(path, "wb") as handle:
            handle.write(payload)

        full_reads = []
        types_by_tag = {b"M": "Meta", b"P": "Program", b"C": "Control"}

        class Nca:
            def __init__(self, data, titlekey=None):
                full_reads.append(data[:1])
                self.content_type = types_by_tag[data[:1]]

        class NcaHeaderOnly:
            def __init__(self, data):
                assert len(data) <= 0xC00
                self.content_type = types_by_tag[data[:1]]

        modules = local_file_metadata._load_switch_guides_modules("app/vendor/switch_ghidra_scripts")
        modules["nca"] = types.SimpleNamespace(NCA_HEADER_SIZE=0xC00, Nca=Nca, NcaHeaderOnly=NcaHeaderOnly)
        modules["cnmt"] = types.SimpleNamespace(parse_cnmt=lambda _: types.SimpleNamespace(title_id=1, version=0))
        with patch.object(local_file_metadata, "_extract_cnmt_payload_from_meta_nca", return_value=b"cnmt"), \
                patch.object(local_file_metadata, "_extract_nacp_and_icon_from_control_nca", return_value={"name": "Example Title"}):
            out = extractor(path, modules)
        self.assertEqual(out.get("name"), "Example Title")
        self.assertEqual(sorted(full_reads), [b"C", b"M"])

    def test_reads_only_headers_until_the_control_nca(self):
        files = [
            ("meta.cnmt.nca", b"M" * 0xC00),
            ("program.nca", b"P" * 0x8000),
            ("largest.nca", b"P" * 0x10000),
            ("control.nca", b"C" * 0x1000),
        ]
        header, data = _partition(b"PFS0", files, 0x18)
        with self.subTest("nsp"):
            self._extract(local_file_metadata._extract_from_nsp, header + data)

        secure_header, secure_data = _partition(b"HFS0", files, 0x40)
        root_header, _ = _partition(b"HFS0", [("secure", secure_header + secure_data)], 0x40)
        xci = bytearray(0x200)
        xci[0x100:0x104] = b"HEAD"
        xci[0x130:0x140] = struct.pack("<QQ", 0x200, len(root_header))
        with self.subTest("xci"):
            self._extract(local_file_metadata._extract_from_xci, bytes(xci) + root_header + secure_header + secure_data)


if __name__ == "__main__":
    unittest.main()
