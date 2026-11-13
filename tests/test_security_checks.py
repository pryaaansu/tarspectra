import unittest

from analyzer.security_checks import run_passive_security_checks


class PassiveSecurityChecksTests(unittest.TestCase):
    def test_hardened_https_response_has_no_missing_header_findings(self):
        response = {
            "url": "https://example.test/",
            "headers": {
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Strict-Transport-Security": "max-age=31536000",
            },
            "forms_detail": [],
        }
        ids = {finding["id"] for finding in run_passive_security_checks(response)}
        self.assertFalse(ids & {"missing_content_security_policy", "missing_hsts", "missing_frame_protection"})

    def test_password_get_form_is_high_priority(self):
        response = {
            "url": "https://example.test/login",
            "headers": {},
            "forms_detail": [{"action": "/login", "method": "get", "inputs": [{"name": "password", "type": "password"}]}],
        }
        findings = run_passive_security_checks(response)
        password_finding = next(finding for finding in findings if finding["id"] == "password_form_get")
        self.assertEqual(password_finding["severity"], "high")

    def test_unsafe_cors_pair_is_high_priority(self):
        response = {
            "url": "https://example.test/api",
            "headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
            "forms_detail": [],
        }
        findings = run_passive_security_checks(response)
        cors_finding = next(finding for finding in findings if finding["id"] == "permissive_cors_credentials")
        self.assertEqual(cors_finding["severity"], "high")

    def test_static_assets_never_produce_missing_header_findings(self):
        # A static CSS, JS or image file should NEVER be flagged for missing CSP or clickjacking
        response = {
            "url": "https://example.test/static/styles.css",
            "status_code": 200,
            "content_type": "text/css",
            "headers": {"Content-Type": "text/css"},
            "forms_detail": [],
        }
        findings = run_passive_security_checks(response)
        ids = {f["id"] for f in findings}
        self.assertFalse(ids & {"missing_content_security_policy", "missing_frame_protection", "missing_hsts"})

    def test_failed_requests_and_errors_do_not_produce_fake_findings(self):
        # A 404 or connection failure (status 0) must NOT spam missing header alerts
        failed_response = {
            "url": "https://example.test/not-found",
            "status_code": 404,
            "content_type": "text/html",
            "headers": {},
            "forms_detail": [],
        }
        findings = run_passive_security_checks(failed_response)
        self.assertEqual(len(findings), 0)

        network_error_response = {
            "url": "https://example.test/timeout",
            "status_code": 0,
            "error": "Connection timed out",
            "headers": {},
            "forms_detail": [],
        }
        findings2 = run_passive_security_checks(network_error_response)
        self.assertEqual(len(findings2), 0)

    def test_meta_tag_csp_and_framing_is_recognized(self):
        # When CSP is specified via <meta http-equiv="Content-Security-Policy">, it is not missing!
        response = {
            "url": "https://example.test/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {"X-Content-Type-Options": "nosniff"},
            "body_snippet": '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; frame-ancestors \'none\'"></head><body>Hello</body></html>',
            "forms_detail": [],
        }
        findings = run_passive_security_checks(response)
        ids = {f["id"] for f in findings}
        self.assertNotIn("missing_content_security_policy", ids)
        self.assertNotIn("missing_frame_protection", ids)

    def test_skip_headers_flag_bypasses_header_audit(self):
        # When check_headers=False, no missing headers are returned, but form hygiene is preserved
        response = {
            "url": "https://example.test/login",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {},
            "forms_detail": [{"action": "/login", "method": "get", "inputs": [{"name": "password", "type": "password"}]}],
        }
        findings = run_passive_security_checks(response, check_headers=False)
        ids = {f["id"] for f in findings}
        self.assertNotIn("missing_content_security_policy", ids)
        self.assertNotIn("missing_frame_protection", ids)
        self.assertIn("password_form_get", ids)


if __name__ == "__main__":
    unittest.main()
