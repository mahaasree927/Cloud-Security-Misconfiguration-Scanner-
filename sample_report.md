# Cloud Security Misconfiguration Report

- **Account**: 111122223333
- **Region**: ap-south-1
- **Scanned at**: 2026-10-25 06:51 UTC
- **Scanner version**: 1.0.0

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 4 |
| HIGH | 7 |
| MEDIUM | 6 |
| LOW | 2 |

## Findings

### [CRITICAL] IAM-001 - Root account has no MFA

- **Category:** IAM
- **Resource:** `root account`
- **Why it matters:** The root user has unrestricted access; without MFA a stolen password means full account takeover.
- **Remediation:** Enable a hardware or virtual MFA device on the root user.

### [CRITICAL] IAM-002 - Root account has active access keys

- **Category:** IAM
- **Resource:** `root account`
- **Why it matters:** Root access keys bypass IAM permission boundaries and are a top breach vector.
- **Remediation:** Delete root access keys and use IAM roles or users with least privilege.

### [CRITICAL] NET-002 - Security group allows ALL traffic from the internet

- **Category:** Network
- **Resource:** `sg-0ccc333 (allow-all)`
- **Why it matters:** Every port on attached resources is reachable from anywhere.
- **Remediation:** Remove the rule; allow only required ports from specific CIDRs.

### [CRITICAL] S3-002 - Bucket is publicly accessible via ACL or bucket policy

- **Category:** Storage
- **Resource:** `s3://company-public-assets`
- **Why it matters:** Anyone on the internet can read (or write) objects in this bucket.
- **Remediation:** Remove public grants/principals '*' and enable Block Public Access.

### [HIGH] IAM-003 - Console user without MFA

- **Category:** IAM
- **Resource:** `user/alice`
- **Why it matters:** Password-only console access is vulnerable to phishing and credential stuffing.
- **Remediation:** Enforce MFA for the user, or require it via an IAM policy condition.

### [HIGH] IAM-005 - Inline policy grants full admin (Action:* on Resource:*)

- **Category:** IAM
- **Resource:** `user/alice inline policy full-access`
- **Why it matters:** Over-privileged identities turn any compromise into total account compromise.
- **Remediation:** Replace with least-privilege permissions scoped to required actions/resources.

### [HIGH] LOG-001 - No CloudTrail trail configured

- **Category:** Logging
- **Resource:** `account`
- **Why it matters:** API activity is not recorded, so investigations and audits are impossible.
- **Remediation:** Create a multi-region trail with log file validation, delivering to a protected S3 bucket.

### [HIGH] NET-001 - SSH (port 22) open to 0.0.0.0/0

- **Category:** Network
- **Resource:** `sg-0aaa111 (web-ssh)`
- **Why it matters:** Remote-admin ports exposed to the internet are constantly brute-forced.
- **Remediation:** Restrict to a trusted IP range, or use SSM Session Manager / a VPN.

### [HIGH] NET-003 - MySQL (port 3306) open to 0.0.0.0/0

- **Category:** Network
- **Resource:** `sg-0bbb222 (db-open)`
- **Why it matters:** Databases reachable from the internet risk data theft and ransomware.
- **Remediation:** Limit access to application security groups or private subnets.

### [HIGH] NET-004 - RDS instance is publicly accessible

- **Category:** Network
- **Resource:** `rds/prod-db`
- **Why it matters:** A public endpoint widens the attack surface of the database.
- **Remediation:** Disable public accessibility and place the instance in private subnets.

### [HIGH] S3-001 - S3 Block Public Access not fully enabled

- **Category:** Storage
- **Resource:** `s3://company-public-assets`
- **Why it matters:** Without all four settings, an ACL or policy mistake can expose data publicly.
- **Remediation:** Enable all four Block Public Access settings on the bucket (and account).

### [MEDIUM] ENC-001 - EBS volume is not encrypted

- **Category:** Encryption
- **Resource:** `ebs/vol-0123`
- **Why it matters:** Data on the volume and its snapshots is stored in plaintext.
- **Remediation:** Snapshot, copy the snapshot with encryption on, and restore; enable EBS default encryption.

### [MEDIUM] ENC-002 - RDS storage is not encrypted

- **Category:** Encryption
- **Resource:** `rds/prod-db`
- **Why it matters:** Database storage, backups and replicas are unencrypted.
- **Remediation:** Create an encrypted snapshot copy and restore a new encrypted instance.

### [MEDIUM] IAM-004 - Access key is 240 days old (> 90)

- **Category:** IAM
- **Resource:** `user/alice key AKIAEXAMPLEOLD1`
- **Why it matters:** Long-lived keys increase the window for leaked-credential abuse.
- **Remediation:** Rotate the key and delete the old one; prefer temporary credentials via roles.

### [MEDIUM] IAM-006 - Minimum password length is 8 (< 14)

- **Category:** IAM
- **Resource:** `account password policy`
- **Why it matters:** Short passwords are easier to brute-force.
- **Remediation:** Raise MinimumPasswordLength to at least 14.

### [MEDIUM] LOG-005 - VPC Flow Logs not enabled

- **Category:** Logging
- **Resource:** `vpc/vpc-0abc`
- **Why it matters:** Network traffic cannot be analysed for suspicious activity.
- **Remediation:** Enable flow logs to CloudWatch Logs or S3.

### [MEDIUM] S3-003 - Default encryption not enabled

- **Category:** Storage
- **Resource:** `s3://company-public-assets`
- **Why it matters:** Objects may be stored unencrypted at rest.
- **Remediation:** Enable default SSE-S3 or SSE-KMS encryption.

### [LOW] S3-004 - Versioning disabled

- **Category:** Storage
- **Resource:** `s3://company-public-assets`
- **Why it matters:** Deleted or overwritten objects cannot be recovered (also weakens ransomware resilience).
- **Remediation:** Enable bucket versioning; consider MFA Delete for critical buckets.

### [LOW] S3-005 - Server access logging disabled

- **Category:** Storage
- **Resource:** `s3://company-public-assets`
- **Why it matters:** No audit trail of requests made to the bucket.
- **Remediation:** Enable server access logging to a dedicated log bucket.
