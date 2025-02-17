import unittest
import requests
import json
from datetime import datetime, timedelta
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class TestJWKSServer(unittest.TestCase):
    BASE_URL = "http://localhost:8080"

    def test_jwks_endpoint(self):
        """Test the JWKS endpoint to ensure it returns valid keys."""
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200, "JWKS endpoint should return status code 200")

        # Check if the response is valid JSON
        try:
            jwks = response.json()
        except json.JSONDecodeError:
            self.fail("JWKS endpoint did not return valid JSON")

        # Check if the response contains the "keys" field
        self.assertIn("keys", jwks, "JWKS response should contain 'keys' field")

        # Check if at least one key is present
        self.assertGreater(len(jwks["keys"]), 0, "JWKS response should contain at least one key")

    def test_auth_endpoint(self):
        """Test the /auth endpoint to ensure it returns a valid JWT."""
        response = requests.post(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 200, "/auth endpoint should return status code 200")

        # Check if the response contains a token
        token = response.json().get("token")
        self.assertIsNotNone(token, "/auth endpoint should return a token")

        # Decode the token without verification to check its structure
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            self.assertIn("sub", decoded, "Token should contain 'sub' claim")
            self.assertIn("name", decoded, "Token should contain 'name' claim")
            self.assertIn("iat", decoded, "Token should contain 'iat' claim")
            self.assertIn("exp", decoded, "Token should contain 'exp' claim")
        except jwt.DecodeError:
            self.fail("Failed to decode the token")

    def test_auth_endpoint_expired(self):
        """Test the /auth endpoint with the 'expired' query parameter."""
        response = requests.post(f"{self.BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200, "/auth endpoint should return status code 200")

        # Check if the response contains a token
        token = response.json().get("token")
        self.assertIsNotNone(token, "/auth endpoint should return a token")

        # Decode the token without verification to check its structure
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            self.assertIn("sub", decoded, "Token should contain 'sub' claim")
            self.assertIn("name", decoded, "Token should contain 'name' claim")
            self.assertIn("iat", decoded, "Token should contain 'iat' claim")
            self.assertIn("exp", decoded, "Token should contain 'exp' claim")

            # Check if the token is expired
            exp_timestamp = decoded["exp"]
            exp_time = datetime.utcfromtimestamp(exp_timestamp)
            self.assertLess(exp_time, datetime.utcnow(), "Token should be expired")
        except jwt.DecodeError:
            self.fail("Failed to decode the token")

    def test_jwks_key_usage(self):
        """Test if the JWKS keys can be used to verify a JWT."""
        # Get the JWKS
        jwks_response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        jwks = jwks_response.json()

        # Get a valid JWT
        auth_response = requests.post(f"{self.BASE_URL}/auth")
        token = auth_response.json().get("token")

        
