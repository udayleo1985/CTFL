# JWT Weak Secret Attack Demo

# Description
Demonstrates how a JWT using a weak HMAC secret can be exploited to forge tokens and escalate privileges.

# Requirements
- Python 3.x
- PyJWT (`pip install pyjwt`)

# Setup & Usage
1. Save `jwt_attack_demo.py` to your machine.
2. Run: `python jwt_attack_demo.py`
3. The script outputs a forged JWT. Use it on an endpoint that uses the same weak secret for validation.

# References
- OWASP JWT Cheat Sheet
- NIST CVE Database
- https://www.vaadata.com/blog/jwt-json-web-token-vulnerabilities-common-attacks-and-security-best-practices/
