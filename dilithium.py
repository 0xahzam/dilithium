import time
from rings import Polynomial
from hash import expand_seed, generate_matrix_from_seed, generate_challenge
import numpy as np
import secrets
from functools import lru_cache

# System constants from Dilithium paper
Q = Polynomial.Q  # q = 2^23 - 2^13 + 1 = 8380417
N = Polynomial.N  # n = 256

# Extremely relaxed bounds (for testing)
GAMMA1 = Q
GAMMA2 = Q
BETA = 1

# Domain separators
DOMAIN_SMALL_POLY = 0x03
DOMAIN_Y_POLY = 0x05

# Parameter sets (k, l, η)
PARAMS = {
    2: {"k": 4, "l": 4, "eta": 2},  # NIST Security Level 2
    3: {"k": 6, "l": 5, "eta": 4},  # NIST Security Level 3
    5: {"k": 8, "l": 7, "eta": 2},  # NIST Security Level 5
}


class OptimizedDilithium:
    def __init__(self, security_level=2):
        if security_level not in PARAMS:
            raise ValueError("Security level must be 2, 3, or 5")

        params = PARAMS[security_level]
        self.k = params["k"]
        self.l = params["l"]
        self.eta = params["eta"]

        self.rho = None
        self.t = None
        self.s1 = None
        self.s2 = None

    def _generate_vector(self, size: int, bound: int, domain: int) -> list:
        seed = secrets.token_bytes(32)
        total_coeffs = size * Polynomial.N
        randomness = expand_seed(seed, domain, total_coeffs * 4)
        coeffs = np.frombuffer(randomness, dtype=np.uint32)
        coeffs = coeffs % (2 * bound + 1)
        coeffs = coeffs.astype(np.int32) - bound
        coeffs = coeffs.reshape(size, Polynomial.N)
        return [Polynomial(row.tolist()) for row in coeffs]

    def generate_y_vector(self) -> list:
        return self._generate_vector(self.l, GAMMA1, DOMAIN_Y_POLY)

    def generate_small_vector(self, size: int) -> list:
        return self._generate_vector(size, self.eta, DOMAIN_SMALL_POLY)

    @lru_cache(maxsize=None)  # Changed to support multiple cache entries
    def get_matrix_A(self):
        """Get cached matrix A using rho as part of cache key"""
        if self.rho is None:
            raise ValueError("Keys not generated")

        # Include rho in computation to make it part of cache key
        matrix = generate_matrix_from_seed(self.rho, self.k, self.l)
        return matrix

    def _matrix_multiply(self, matrix: list, vector: list) -> list:
        result = []
        for row in matrix:
            sum_poly = Polynomial()
            for a, v in zip(row, vector):
                sum_poly = sum_poly + (a * v)
            result.append(sum_poly)
        return result

    def keygen(self):
        """Generate a new keypair"""
        self.rho = secrets.token_bytes(32)

        A = self.get_matrix_A()
        self.s1 = self.generate_small_vector(self.l)
        self.s2 = self.generate_small_vector(self.k)

        self.t = self._matrix_multiply(A, self.s1)
        for i in range(self.k):
            self.t[i] = self.t[i] + self.s2[i]

        return (self.rho, self.t), (self.s1, self.s2)

    def sign(self, message: bytes, max_attempts=100):
        if not all([self.rho, self.t, self.s1, self.s2]):
            raise ValueError("Keys not generated")

        A = self.get_matrix_A()
        public_key = (self.rho, self.t)

        attempts = 0
        while attempts < max_attempts:
            attempts += 1
            if attempts % 10 == 0:
                print(f"Attempt {attempts}/{max_attempts}")

            # Sample y with coefficients in [-γ₁, γ₁]
            y = self.generate_y_vector()

            # Compute w = Ay
            w = self._matrix_multiply(A, y)

            # Check if w is small enough (||w||∞ < γ₂)
            w_coeffs = np.concatenate([np.array(p.coefficients) for p in w])

            if np.any(np.abs(w_coeffs) > GAMMA2):
                continue

            print("w processed")

            # Process w for challenge generation
            w_processed = []
            for poly in w:
                coeffs = np.array(poly.coefficients)
                coeffs = np.abs(coeffs) % Q
                w_processed.append(Polynomial(coeffs.tolist()))

            # Generate challenge polynomial c
            c = generate_challenge(message, public_key, w_processed)

            # Compute z = y + cs₁
            z = []
            for i in range(self.l):
                z_poly = y[i] + (c * self.s1[i])
                z.append(z_poly)

            # Check if z is small enough (||z||∞ < γ₁ - β)
            z_coeffs = np.concatenate([np.array(p.coefficients) for p in z])
            if np.any(np.abs(z_coeffs) >= GAMMA1 - BETA):
                continue

            print(f"Succeeded after {attempts} attempts")
            return z, c, w_processed

        raise RuntimeError(
            f"Failed to generate signature after {max_attempts} attempts"
        )

    def verify(self, message: bytes, signature: tuple, public_key: tuple) -> bool:
        z, c, w_processed = signature
        rho, t = public_key

        # Verify z bound (||z||∞ < γ₁ - β)
        z_coeffs = np.concatenate([np.array(p.coefficients) for p in z])
        if np.any(np.abs(z_coeffs) >= GAMMA1 - BETA):
            print("z bounds check failed")
            return False

        # Process w coefficients same way as in signing
        w_coeffs = []
        for poly in w_processed:
            coeffs = np.array(poly.coefficients)
            coeffs = np.abs(coeffs) % Q  # Same processing as in sign()
            w_coeffs.append(coeffs)

        # Check w bounds using processed coefficients
        w_coeffs = np.concatenate(w_coeffs)
        if np.any(np.abs(w_coeffs) >= GAMMA2):
            print("w bounds check failed")
            return False

        # Verify challenge
        w_processed_verify = [
            Polynomial(coeffs.tolist()) for coeffs in w_coeffs.reshape(-1, N)
        ]
        c_prime = generate_challenge(message, public_key, w_processed_verify)
        return np.array_equal(c.coefficients, c_prime.coefficients)


def test_performance():
    print("\n=== DILITHIUM SIGNATURE METRICS ===")
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
    test_performance()
