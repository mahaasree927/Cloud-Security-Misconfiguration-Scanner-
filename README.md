# Cloud Security Misconfiguration Scanner

A read-only Python scanner that inspects an AWS account for common security misconfigurations across **IAM, storage (S3), networking, encryption and logging**, then produces a prioritised report with **remediation recommendations**.

**Tech:** Python 3.9+, boto3 (AWS SDK), IAM, S3, EC2, RDS, CloudTrail

## What it checks

| ID | Category | Check | Severity |
|---|---|---|---|
| IAM-001 / 002 | IAM | Root account without MFA / with access keys | Critical |
| IAM-003 | IAM | Console user without MFA | High |
| IAM-004 | IAM | Active access key older than 90 days | Medium |
| IAM-005 | IAM | Policy granting `Action:* on Resource:*` | High |
| IAM-006 | IAM | Missing or weak (<14 chars) password policy | Medium |
| S3-001 | Storage | Block Public Access not fully enabled | High |
| S3-002 | Storage | Bucket public via ACL or policy | Critical |
| S3-003 / 004 / 005 | Storage | No default encryption / versioning / access logging | Medium / Low / Low |
| NET-001 | Network | SSH/RDP open to 0.0.0.0/0 | High |
| NET-002 | Network | Security group allows all traffic from internet | Critical |
| NET-003 | Network | DB ports (MySQL, Postgres, MSSQL, MongoDB, Redis) open to internet | High |
| NET-004 | Network | RDS instance publicly accessible | High |
| ENC-001 / 002 | Encryption | Unencrypted EBS volume / RDS instance | Medium |
| LOG-001 / 002 | Logging | No CloudTrail / no multi-region trail | High / Medium |
| LOG-003 / 004 | Logging | Log validation off / trail not logging | Low / High |
| LOG-005 | Logging | VPC Flow Logs disabled | Medium |

## Architecture

```
AWS account --(boto3, read-only)--> collectors/aws.py --> snapshot (dict / JSON)
                                                              |
                                  checks/{iam,storage,network,encryption,logging_checks}.py
                                                              |
                                           findings --> report.py --> console | JSON | Markdown
```

Collection is separate from checking, so every check is a plain function over a dictionary. That makes the checks easy to unit test and lets you scan a saved snapshot **without AWS credentials**.

## Quick start

```bash
git clone https://github.com/<your-username>/cloud-misconfig-scanner.git
cd cloud-misconfig-scanner

# 1. Try it offline with the bundled sample data (no AWS needed)
python3 -m scanner --input sample_data/vulnerable_account.json

# 2. Scan a real account (install boto3 first)
pip install -r requirements.txt
python3 -m scanner --profile my-profile --region ap-south-1 --format markdown -o reports/report.md

# 3. CI mode: exit code 1 if any HIGH or CRITICAL finding exists
python3 -m scanner --profile my-profile --fail-on high
```

Options: `--format console|json|markdown`, `-o FILE`, `--save-snapshot FILE`, `--fail-on critical|high|medium|low`.

A sample output is in [`reports/sample_report.md`](reports/sample_report.md).

## Safety

- Uses only `Get*`, `List*` and `Describe*` calls. Nothing is changed in your account.
- Attach the least-privilege policy in [`iam_readonly_policy.json`](iam_readonly_policy.json) to the scanning identity.
- Only scan accounts you own or are authorised to assess.
- Don't commit real snapshots or reports; they contain account details (already git-ignored).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Adding a new check

1. Add a function or block in the relevant `scanner/checks/*.py` module that appends a `Finding(...)`.
2. If it needs new data, extend the matching `_collect_*` function in `collectors/aws.py`.
3. Add the field to `sample_data/` and an assertion in `tests/test_checks.py`.

## Roadmap

- Multi-region scanning and AWS Organizations support
- More services (KMS key rotation, Lambda, EKS, SNS/SQS policies)
- CIS AWS Foundations Benchmark mapping per check
- HTML report and Slack/email alerts

## License

MIT
