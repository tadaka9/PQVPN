from oqs import oqs

# Example of signing and verifying a message using ML-DSA-87 (or Dilithium5)
# Ensure it's enabled (see above)

try:
    with oqs.Signature("ML-DSA-87") as sig:  # Or "Dilithium5" if that's the name
        # Generate a keypair
        public_key = sig.generate_keypair()

        # Message to sign
        message = b"Hello, world!"

        # Sign
        signature = sig.sign(message)

        # Verify
        is_valid = sig.verify(message, signature, public_key)

        print(f"Signature valid: {is_valid}")  # Should be True

        # Optional: Check details
        print("Sig details:", sig.details)

except oqs.MechanismNotSupportedError as e:
    print(f"Algorithm not supported: {e}")
except oqs.MechanismNotEnabledError as e:
    print(f"Algorithm supported but not enabled: {e}")
except Exception as e:
    print(f"Other error: {e}")
