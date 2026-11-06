import unittest

from scanner.safe_reflection import inject_marker
from webapp.server import ScanStore, validate_target


class WebHelpersTests(unittest.TestCase):
    def test_target_must_be_http_or_https_without_embedded_credentials(self):
        self.assertEqual(validate_target("https://example.test/path"), "https://example.test/path")
        with self.assertRaises(ValueError):
            validate_target("example.test")
        with self.assertRaises(ValueError):
            validate_target("https://user:secret@example.test")

    def test_marker_replaces_one_existing_query_parameter(self):
        url = inject_marker("https://example.test/search?q=old&page=2", "q", "marker_123")
        self.assertIn("q=marker_123", url)
        self.assertIn("page=2", url)

    def test_store_returns_a_copy_of_scan_data(self):
        store = ScanStore()
        scan_id = store.create("https://example.test", {"max_pages": 10, "max_depth": 1, "safe_reflection": False})
        first_read = store.get(scan_id)
        first_read["progress"]["pages_found"] = 999
        self.assertEqual(store.get(scan_id)["progress"]["pages_found"], 0)


if __name__ == "__main__":
    unittest.main()
