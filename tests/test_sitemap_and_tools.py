import unittest
from scanner.sitemap import build_hierarchical_sitemap, get_registered_domain
from analyzer.reporting import consolidate_findings
from scanner.tools_runner import _parse_nikto_output, _parse_nmap_xml_true_positive


class SitemapAndToolsTests(unittest.TestCase):
    def test_registered_domain_extraction(self):
        self.assertEqual(get_registered_domain("https://portal.dsatm.edu.in/login"), "dsatm.edu.in")
        self.assertEqual(get_registered_domain("testphp.vulnweb.com"), "vulnweb.com")

    def test_hierarchical_sitemap_groups_subdomains(self):
        collected = [
            {
                "url": "https://dsatm.edu.in/",
                "status_code": 200,
                "content_type": "text/html",
                "headers": {"server": "cloudflare"},
                "forms_detail": []
            },
            {
                "url": "https://dsatm.edu.in/about",
                "status_code": 200,
                "content_type": "text/html",
                "forms_detail": []
            },
            {
                "url": "https://portal.dsatm.edu.in/login",
                "status_code": 200,
                "content_type": "text/html",
                "forms_detail": [{"action": "/login", "method": "post", "inputs": [{"name": "user"}]}]
            }
        ]
        all_urls = {
            "https://dsatm.edu.in/",
            "https://dsatm.edu.in/about",
            "https://portal.dsatm.edu.in/login",
            "https://portal.dsatm.edu.in/reset"
        }
        passive_subs = ["lms.dsatm.edu.in"]

        sitemap = build_hierarchical_sitemap("https://dsatm.edu.in", collected, all_urls, passive_subs)

        self.assertEqual(sitemap["root_domain"], "dsatm.edu.in")
        self.assertIn("dsatm.edu.in", sitemap["subdomains"])
        self.assertIn("portal.dsatm.edu.in", sitemap["subdomains"])
        self.assertIn("lms.dsatm.edu.in", sitemap["subdomains"])
        self.assertEqual(sitemap["total_subdomains"], 3)
        self.assertEqual(len(sitemap["subdomains"]["dsatm.edu.in"]["endpoints"]), 2)
        self.assertEqual(len(sitemap["subdomains"]["portal.dsatm.edu.in"]["endpoints"]), 2)

    def test_consolidate_findings_removes_duplicate_header_spam(self):
        # 30 pages with identical missing CSP header
        pages = []
        for i in range(30):
            pages.append({
                "url": f"https://example.com/page{i}",
                "passive_findings": [
                    {
                        "id": "missing_content_security_policy",
                        "type": "Missing Content Security Policy",
                        "severity": "medium",
                        "evidence": "Header missing",
                        "remediation": "Add CSP"
                    }
                ]
            })

        consolidated = consolidate_findings(pages)
        # Should be consolidated into 1 finding instead of 30!
        self.assertEqual(len(consolidated), 1)
        self.assertEqual(consolidated[0]["id"], "missing_content_security_policy")
        self.assertEqual(consolidated[0]["affected_count"], 30)

    def test_nikto_parser_filters_informational_noise(self):
        raw_output = """
- Nikto v2.6.0
+ Target IP: 1.2.3.4
+ SSL Info: Subject: /CN=test.com
+ Platform: Windows
+ Multiple IPs found: 1.2.3.4, 5.6.7.8
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.
+ [FAIL] Unable to connect to host:443
+ /admin/: Admin directory found with default credentials.
+ /phpinfo.php: Contains PHP configuration information.
"""
        findings = _parse_nikto_output(raw_output, "https://test.com")
        titles = [f["title"] for f in findings]

        # Only the 2 real findings should be captured!
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("Admin directory found" in t for t in titles))
        self.assertTrue(any("phpinfo.php" in t for t in titles))
        # Verify noise was rejected
        self.assertFalse(any("SSL Info" in t for t in titles))
        self.assertFalse(any("Platform" in t for t in titles))
        self.assertFalse(any("No CGI" in t for t in titles))

    def test_nmap_parser_rejects_negative_results(self):
        xml_output = """
        <nmaprun>
          <host>
            <ports>
              <port portid="443">
                <script id="http-dombased-xss" output="Couldn't find any DOM based XSS." />
                <script id="http-stored-xss" output="Couldn't find any stored XSS." />
                <script id="http-csrf" output="Couldn't find any CSRF vulnerabilities." />
              </port>
            </ports>
          </host>
        </nmaprun>
        """
        findings = _parse_nmap_xml_true_positive(xml_output, "https://example.com")
        # Should be 0 findings! Negative statements must NOT be reported as vulnerabilities.
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
