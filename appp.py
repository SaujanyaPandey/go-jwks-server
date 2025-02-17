from flask import Flask, jsonify, request
import jwt
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# In-memory storage for keys
keys = {}

def generate_rsa_key_pair(kid):
    """Generate an RSA key pair and store it with a Key ID (kid)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Store the key pair
    keys[kid] = {
        "private_key": private_key,
        "public_key": public_key,
        "expires_at": datetime.utcnow() + timedelta(hours=1)  # Key expires in 1 hour
    }

    return private_key, public_key

def get_jwks():
    """Generate the JWKS (JSON Web Key Set) from non-expired keys."""
    jwks = {"keys": []}
    for kid, key_info in keys.items():
        if key_info["expires_at"] > datetime.utcnow():  # Only include non-expired keys
            public_key = key_info["public_key"]
            jwk = {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": public_key.public_numbers().n,
                "e": public_key.public_numbers().e,
            }
            jwks["keys"].append(jwk)
    return jwks

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Serve the JWKS endpoint."""
    return jsonify(get_jwks())

@app.route("/auth", methods=["POST"])
def auth():
    """Issue a JWT. If 'expired' query parameter is present, use an expired key."""
    expired = request.args.get("expired") == "true"

    # Generate a new key if none exists
    if not keys:
        kid = "key1"
        generate_rsa_key_pair(kid)

    # Use the first key in the keys dictionary
    kid = next(iter(keys))
    key_info = keys[kid]

    # If expired, generate a new key with an expired timestamp
    if expired:
        kid = "expiredKey"
        private_key, _ = generate_rsa_key_pair(kid)
        keys[kid]["expires_at"] = datetime.utcnow() - timedelta(hours=1)  # Expired key
    else:
        private_key = key_info["private_key"]

    # Create the JWT
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": int(time.time()),
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),  # Token expires in 1 hour
    }
    headers = {"kid": kid}
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

    return jsonify({"token": token})

if __name__ == "__main__":
    # Generate an initial key pair
    generate_rsa_key_pair("key1")
    app.run(port=8080)
