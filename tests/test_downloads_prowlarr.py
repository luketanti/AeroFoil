import unittest

from app.downloads.prowlarr import ProwlarrClient, _normalize_numeric_list


class ProwlarrNormalizationTests(unittest.TestCase):
    def test_normalize_numeric_list_supports_comma_string(self):
        self.assertEqual(_normalize_numeric_list("43,48,50,51,52"), ["43", "48", "50", "51", "52"])

    def test_normalize_numeric_list_supports_mixed_list(self):
        values = [43, "48", "50,51", "", "abc", "52"]
        self.assertEqual(_normalize_numeric_list(values), ["43", "48", "50", "51", "52"])

    def test_search_serializes_legacy_indexers_and_categories(self):
        captured = {}

        class TestClient(ProwlarrClient):
            def _get(self, path, params=None):
                captured["path"] = path
                captured["params"] = params or {}
                return []

        client = TestClient("http://localhost:9696", "key")
        client.search("query", indexer_ids=["43,48,50,51,52"], categories="5000,5070")

        self.assertEqual(captured["path"], "/api/v1/search")
        self.assertEqual(captured["params"].get("indexerIds"), "43,48,50,51,52")
        self.assertEqual(captured["params"].get("categories"), "5000,5070")


if __name__ == "__main__":
    unittest.main()
