# sample_plugin.py - A sample PQVPN plugin

from src.pqvpn.plugins import AuthPlugin


class SampleAuthPlugin(AuthPlugin):
    @property
    def name(self):
        return "sample_auth"

    @property
    def version(self):
        return "1.0.0"

    def initialize(self, context):
        print(f"Sample auth plugin initialized with context: {context}")

    def cleanup(self):
        print("Sample auth plugin cleaned up")

    def authenticate(self, credentials):
        # Simple authentication: check if username == password
        username = credentials.get("username")
        password = credentials.get("password")
        return username == password
