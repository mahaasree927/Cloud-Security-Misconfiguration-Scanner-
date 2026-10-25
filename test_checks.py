import json
import os
import unittest

from scanner.cli import run_checks, main
from scanner.checks.iam import is_admin_policy

DATA = os.path.join(os.path.dirname(__file__), "..", "sample_data")


def load(name):
    with open(os.path.join(DATA, name)) as f:
        return json.load(f)


class ScannerTests(unittest.TestCase):
    def test_vulnerable_account_finds_expected_issues(self):
        ids = {f.check_id for f in run_checks(load("vulnerable_account.json"))}
        expected = {"IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005", "IAM-006",
                    "S3-001", "S3-002", "S3-003", "S3-004", "S3-005",
                    "NET-001", "NET-002", "NET-003", "NET-004",
                    "ENC-001", "ENC-002", "LOG-001", "LOG-005"}
        self.assertTrue(expected.issubset(ids), expected - ids)

    def test_secure_account_has_no_findings(self):
        self.assertEqual(run_checks(load("secure_account.json")), [])

    def test_admin_policy_detection(self):
        admin = {"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": "*"}}
        scoped = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        deny = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        self.assertTrue(is_admin_policy(admin))
        self.assertFalse(is_admin_policy(scoped))
        self.assertFalse(is_admin_policy(deny))

    def test_cli_fail_on_exit_codes(self):
        bad = os.path.join(DATA, "vulnerable_account.json")
        good = os.path.join(DATA, "secure_account.json")
        self.assertEqual(main(["--input", bad, "--fail-on", "high"]), 1)
        self.assertEqual(main(["--input", good, "--fail-on", "low"]), 0)


if __name__ == "__main__":
    unittest.main()
