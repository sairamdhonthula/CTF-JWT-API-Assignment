
JWT Security Research (1-2 page)
-------------------------------
Summary:
JSON Web Tokens (JWT) provide a compact, URL-safe mechanism to transmit claims between parties.
Common use-cases: stateless authentication, service-to-service auth, short-lived access tokens.

Key vulnerabilities:
1. alg=none / algorithm confusion
   - Description: If a verifier trusts the algorithm declared in the token header, an attacker can set "alg":"none"
     and provide an unsigned token. Secure verifiers MUST never accept tokens without a signature or must restrict
     accepted algorithms explicitly.
   - Mitigation: Server-side enforce allowed algorithms (e.g., algorithms=["RS256"] or ["HS256"]) and do not
     accept "none". Use library options that disallow "none" by default.

2. Weak HMAC secrets (brute-force / dictionary)
   - Description: HS256 and other HMAC algorithms rely on the secrecy and entropy of the symmetric key.
     Weak/guessable keys (e.g., 'secret', 'password') allow forging tokens via brute-force.
   - Mitigation: Use high-entropy secrets (>=32 bytes), store in secure vaults, rotate keys, and monitor authentication failures.

3. Key confusion (RS256 vs HS256)
   - Description: When servers support both asymmetric (RS256) and symmetric (HS256) algorithms and
     mishandle key material (e.g., using the RSA public key as an HMAC secret), attackers can forge tokens by
     signing with HS256 using the public key as secret.
   - Mitigation: Do not accept algorithm from token; explicitly set and enforce the algorithm. Separate keys for
     different algorithms and never treat public keys as symmetric secrets.

4. Replay attacks
   - Description: JWT tokens can be replayed until expiry. Long expiration windows increase risk.
   - Mitigation: Use short-lived access tokens and implement refresh tokens with rotation and server-side revocation lists
     (e.g., store revoked JTIs). Use nonce/jti claims and validate against server-side cache for critical operations.

5. Insecure storage / transport
   - Description: Tokens stored in localStorage or transmitted over insecure channels are vulnerable to theft (XSS / MITM).
   - Mitigation: Transmit only over HTTPS; prefer secure, httpOnly cookies for browser sessions; implement CSRF protections.

6. Insufficient claim validation
   - Description: Not validating standard claims (iss, aud, exp, nbf) or custom claims can lead to misuse.
   - Mitigation: Validate issuer, audience, expiry, and any custom claims needed for authorization decisions.

References:
- OWASP JWT Cheat Sheet (recommended): https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- NIST NVD: https://nvd.nist.gov/
- PyJWT: https://pypi.org/project/PyJWT/
- Flask-JWT-Extended documentation
