from oqs import oqs

# Example of signing and verifying a message using ML-DSA-87 (a post-quantum signature algorithm)


def main():
    # Check if ML-DSA-87 is enabled
    enabled_sigs = oqs.get_enabled_sig_mechanisms()
    if "ML-DSA-87" not in enabled_sigs:
        print("ML-DSA-87 is not enabled. Available enabled signature mechanisms:")
        for sig in enabled_sigs:
            print(f"  - {sig}")
        return

    # Create a Signature instance for ML-DSA-87
    with oqs.Signature("ML-DSA-87") as signer:
        # Generate a keypair (public and secret key)
        public_key = signer.generate_keypair()
        print(f"Generated public key (length: {len(public_key)} bytes)")

        # The secret key is automatically managed; you can export it if needed
        # secret_key = signer.export_secret_key()

        # Message to sign
        message = b"Hello, this is a test message for ML-DSA-87 signing!"

        # Sign the message
        signature = signer.sign(message)
        print(f"Generated signature (length: {len(signature)} bytes)")

    # Verify the signature using a verifier instance
    with oqs.Signature("ML-DSA-87") as verifier:
        is_valid = verifier.verify(message, bytes(signature), public_key)
    print(f"Signature verification: {'Valid' if is_valid else 'Invalid'}")

    # Optional: Test with a tampered message (should fail)
    tampered_message = b"Hello, this is a tampered message!"
    with oqs.Signature("ML-DSA-87") as verifier2:
        is_valid_tampered = verifier2.verify(
            bytes(tampered_message), bytes(signature), public_key
        )
    print(
        f"Tampered message verification: {'Valid' if is_valid_tampered else 'Invalid'}"
    )


if __name__ == "__main__":
    main()
