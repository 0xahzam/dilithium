import time

from dilithium.dilithium import OptimizedDilithium


def main():
    print("=== DILITHIUM SIGNATURE METRICS ===")
    print("Security Level: 2")
    print("Message: 'Hello, Dilithium!'\n")

    dilithium = OptimizedDilithium(security_level=2)
    message = b"Hello, Dilithium!"

    # Key Generation
    print("Generating keypair...")
    start_ns = time.perf_counter_ns()
    pub, priv = dilithium.keygen()
    keygen_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    print(f"✓ Keys generated in {keygen_time_ms:.2f} ms")
    print(f"Public key (first 5): {pub[1][0].coefficients[:5]}\n")

    # Signing
    print("Generating signature...")
    start_ns = time.perf_counter_ns()
    try:
        z, c, w = dilithium.sign(message)
        sign_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        print(f"✓ Signature generated in {sign_time_ms:.2f} ms")

        print("\nSignature Details:")
        print("-----------------")
        print(f"Challenge (c): {c.coefficients[:5]}")
        print(f"Response (z): {z[0].coefficients[:5]}")
        print(f"Witness (w): {w[0].coefficients[:5]}\n")

        # Verification
        print("Verifying signature...")
        start_ns = time.perf_counter_ns()
        valid = dilithium.verify(message, (z, c, w), pub)
        verify_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        print("\nPerformance Summary:")
        print("------------------")
        print(f"Key Generation: {keygen_time_ms:>8.2f} ms")
        print(f"Signing Time:   {sign_time_ms:>8.2f} ms")
        print(f"Verify Time:    {verify_time_ms:>8.2f} ms")
        print(
            f"Total Time:     {(keygen_time_ms + sign_time_ms + verify_time_ms):>8.2f} ms"
        )

        if valid:
            print("\n✓ Signature verification successful")
        else:
            print("\n✗ Signature verification failed")

    except Exception as e:
        print(f"\nError: {e}")


if __name__ == "__main__":
    main()
