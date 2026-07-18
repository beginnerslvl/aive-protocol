# AIVE Patch Plan

- Repository: `demo`
- Scan timestamp: `2026-07-18T11:38:23.115402+00:00`
- Findings: `3`

## Decision Frame

This report treats each finding as an exploit-to-patch candidate. The question is not only whether a risky pattern exists, but whether it is reproducible, how far it can spread, and which safe patch path should be promoted toward merge.

## Finding 1: Direct OS command execution

- Record ID: `AIVE-PY-003`
- Location: `deploy.py:7`
- Severity: `high`
- Confidence: `0.83`
- Blast radius: `localized`
- Exploit hypothesis: a raw OS command call can be steered by unsanitised input
- Trigger snippet: `os.system("git checkout " + branch)`

### Patch Options

- **Swap os.system for subprocess.run with an argv list**: Call subprocess.run([...], shell=False) so arguments are never re-parsed by a shell.
  - Never interpolate user input into the command string.
  - Fail closed on unexpected arguments.
- **Reproduce the exploit path**: Write the smallest failing test or proof that confirms the issue is real before changing behavior.
  - Avoid patching from pattern match alone.
  - Preserve a replay artifact for verifier agents.
- **Ship behind a narrow branch**: Apply the fix in an isolated branch and require independent verification before merge.
  - Do not patch directly on main.
  - Attach regression results to the PR body.

### Merge Gate

- one agent proposes the patch
- independent agents reproduce and compare the result
- regression checks must pass before merge eligibility

## Finding 2: Unsafe deserialization

- Record ID: `AIVE-PY-004`
- Location: `deploy.py:8`
- Severity: `high`
- Confidence: `0.80`
- Blast radius: `localized`
- Exploit hypothesis: deserializing untrusted data can execute arbitrary objects on load
- Trigger snippet: `manifest = pickle.loads(blob)`

### Patch Options

- **Replace pickle with a schema-checked format**: Deserialize untrusted data with JSON or a validated schema rather than pickle.
  - Only unpickle data you produced yourself.
  - Add a signature or integrity check if pickle is unavoidable.
- **Reproduce the exploit path**: Write the smallest failing test or proof that confirms the issue is real before changing behavior.
  - Avoid patching from pattern match alone.
  - Preserve a replay artifact for verifier agents.
- **Ship behind a narrow branch**: Apply the fix in an isolated branch and require independent verification before merge.
  - Do not patch directly on main.
  - Attach regression results to the PR body.

### Merge Gate

- one agent proposes the patch
- independent agents reproduce and compare the result
- regression checks must pass before merge eligibility

## Finding 3: Weak hashing primitive

- Record ID: `AIVE-SEC-003`
- Location: `deploy.py:9`
- Severity: `low`
- Confidence: `0.55`
- Blast radius: `localized`
- Exploit hypothesis: md5/sha1 are unsuitable for security-sensitive hashing
- Trigger snippet: `return hashlib.md5(manifest).hexdigest()`

### Patch Options

- **Upgrade to a modern hashing primitive**: Use SHA-256+ for integrity and a slow KDF (bcrypt/argon2/scrypt) for passwords.
  - Keep md5/sha1 only for non-security checksums.
  - Migrate stored hashes on next authentication.
- **Reproduce the exploit path**: Write the smallest failing test or proof that confirms the issue is real before changing behavior.
  - Avoid patching from pattern match alone.
  - Preserve a replay artifact for verifier agents.
- **Ship behind a narrow branch**: Apply the fix in an isolated branch and require independent verification before merge.
  - Do not patch directly on main.
  - Attach regression results to the PR body.

### Merge Gate

- one agent proposes the patch
- independent agents reproduce and compare the result
- regression checks must pass before merge eligibility

