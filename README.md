# Snyk Test Project - Vulnerability Testing & Ignores

This project contains intentionally vulnerable code and dependencies for testing Snyk's SCA (Software Composition Analysis) and SAST (Static Application Security Testing) capabilities, as well as the ignore functionality.

## Project Contents

### Vulnerable Dependencies (SCA Testing)
The [requirements.txt](requirements.txt) and [setup.py](setup.py) files contain outdated packages with known vulnerabilities:
- `flask==2.0.1` - Multiple CVEs
- `requests==2.25.0` - Known security issues
- `django==3.1.0` - Several vulnerabilities
- `pyyaml==5.3.1` - Deserialization vulnerability
- `jinja2==2.11.0` - Template injection issues
- `cryptography==3.3.2` - Known vulnerabilities
- `urllib3==1.26.4` - Security issues
- `Pillow==8.1.0` - Image processing vulnerabilities

### Vulnerable Code (SAST Testing)

#### [src/vulnerable_app.py](src/vulnerable_app.py)
Contains various code-level vulnerabilities:
- **SQL Injection** - Direct string concatenation in queries
- **Command Injection** - Unsanitized shell execution
- **Path Traversal** - Unvalidated file paths
- **Insecure Deserialization** - Using pickle with untrusted data
- **YAML Deserialization** - Using unsafe yaml.load()
- **Server-Side Template Injection (SSTI)** - User input in templates
- **Hardcoded Credentials** - Passwords and API keys in code
- **Weak Cryptography** - MD5 hashing
- **Insecure Random** - Using random for security tokens
- **XXE Vulnerability** - Unsafe XML parsing
- **Open Redirect** - Unvalidated URL redirects
- **Cross-Site Scripting (XSS)** - Unsanitized output
- **Code Injection** - Use of eval()
- **Debug Mode** - Running Flask in debug mode on 0.0.0.0

#### [src/crypto_issues.py](src/crypto_issues.py)
Additional cryptographic vulnerabilities:
- **Weak Hash Functions** - SHA1 and MD5 for passwords
- **Insecure Cipher Modes** - ECB mode
- **Hardcoded Encryption Keys** - Keys in source code
- **Hardcoded API Keys** - AWS, Stripe, GitHub tokens
- **Insecure Random** - Using random for session IDs

## Testing Instructions

### Step 1: Run Initial Snyk Scans

#### SCA Scan (Dependency Vulnerabilities)
```bash
# Test for open source vulnerabilities
snyk test

# Or with JSON output
snyk test --json > sca-results.json
```

#### SAST Scan (Code Vulnerabilities)
```bash
# Test for code issues
snyk code test

# Or with JSON output
snyk code test --json > sast-results.json
```

### Step 2: Review Findings

After running the scans, you should see:
- **SCA findings**: Multiple CVEs from the vulnerable dependencies
- **SAST findings**: Code security issues like SQL injection, command injection, hardcoded credentials, etc.

Make note of specific Snyk IDs and vulnerability types you want to test ignoring.

### Step 3: Configure Ignores

Edit the [.snyk](.snyk) file to ignore specific vulnerabilities. Here are examples:

#### Ignore a Specific SCA Vulnerability by Snyk ID
```yaml
ignore:
  SNYK-PYTHON-FLASK-1234567:
    - '*':
        reason: Example ignore - False positive
        expires: 2025-12-31T00:00:00.000Z
```

#### Ignore All Vulnerabilities in a Package
```yaml
ignore:
  SNYK-PYTHON-PYYAML-*:
    - 'pyyaml@5.3.1':
        reason: Cannot upgrade due to compatibility
        expires: 2026-01-31T00:00:00.000Z
```

#### Ignore Code Issues (SAST)
```yaml
# Exclude entire files from code scanning
exclude:
  code:
    - src/crypto_issues.py

# Or ignore specific code rules
ignore:
  'python/hardcoded-credentials':
    - '*':
        reason: Test credentials only
        expires: 2025-12-31T00:00:00.000Z

  'python/sql-injection':
    - 'src/vulnerable_app.py > get_user_by_id':
        reason: Protected by WAF
        expires: 2025-12-31T00:00:00.000Z
```

### Step 4: Test Ignore Functionality

After configuring ignores in [.snyk](.snyk):

```bash
# Run scans again to verify ignores work
snyk test
snyk code test

# Compare with previous results - ignored items should not appear
```

### Step 5: Using Snyk CLI to Add Ignores

You can also add ignores interactively:

```bash
# For SCA - will prompt for each vulnerability
snyk ignore --id=SNYK-PYTHON-FLASK-1234567

# For SAST - use policy
snyk ignore --policy-path=.snyk
```

## Common Ignore Patterns

### By Severity
```yaml
# Note: Snyk doesn't directly filter by severity in .snyk file
# Use CLI: snyk test --severity-threshold=high
```

### By Path
```yaml
exclude:
  global:
    - tests/**
    - '**/*.test.py'
    - examples/**
```

### Temporary Ignores with Expiration
```yaml
ignore:
  SNYK-PYTHON-DJANGO-1234567:
    - '*':
        reason: Waiting for vendor fix
        expires: 2025-03-01T00:00:00.000Z
```

### By CWE (Common Weakness Enumeration)
```yaml
# Ignore specific weakness types
ignore:
  'python/hardcoded-credentials':
    - '*':
        reason: Demo application only
```

## Verification Workflow

1. **Baseline scan**: Run `snyk test` and `snyk code test` without ignores
2. **Document findings**: Note the Snyk IDs and issue types
3. **Add ignores**: Update [.snyk](.snyk) with specific ignore rules
4. **Verify**: Re-run scans and confirm ignored issues don't appear
5. **Test expiration**: Set past dates to verify expired ignores are reported again

## Additional Notes

- The [.snyk](.snyk) file should be committed to version control
- Ignored vulnerabilities still exist - this just suppresses reporting
- Use expiration dates to ensure regular review of ignored issues
- Document clear reasons for each ignore
- For production use, prefer fixing over ignoring vulnerabilities

## Clean Up

To remove installed dependencies:
```bash
pip uninstall -r requirements.txt -y
```

## Security Warning

⚠️ **This project contains intentional security vulnerabilities for testing purposes only.**
- Do NOT use this code in production
- Do NOT deploy this application to any public-facing environment
- Use only in isolated testing environments
