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


if __name__ == "__main__":
    unittest.main()
