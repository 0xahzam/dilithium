"""
Optimized SHAKE128 Implementation for Dilithium

Key optimizations:
1. Batch operations with numpy
2. Cached matrix generation
3. Vectorized coefficient generation
4. Pre-allocated buffers
"""

import numpy as np
from Crypto.Hash import SHAKE128
from functools import lru_cache

from dilithium.rings import Polynomial

# Domain separators
DOMAIN_MATRIX = 0x01
DOMAIN_CHALLENGE = 0x02
DOMAIN_MESSAGE = 0x04

# Constants
TAU = 60  # Number of ±1's in challenge polynomial
CHUNK_SIZE = 4  # Bytes per coefficient


class OptimizedHasher:
    def __init__(self):
        """Initialize with reusable SHAKE128 instances"""
        self._shake = SHAKE128.new()
        self._matrix_cache = {}

    def reset(self):
        """Reset SHAKE instance"""
        self._shake = SHAKE128.new()
        return self

    @staticmethod
    @lru_cache(maxsize=32)
    def expand_seed(seed: bytes, domain: int, length: int) -> bytes:
        """Cached seed expansion"""
        shake = SHAKE128.new()
        shake.update(seed + bytes([domain]))
        return shake.read(length)

    def generate_matrix(self, seed: bytes, k: int, l: int) -> list:  # noqa: E741
        """
        Optimized matrix generation with caching and vectorized operations.
        """
        # Check cache first
        cache_key = (seed, k, l)
        if cache_key in self._matrix_cache:
            return self._matrix_cache[cache_key]

        # Pre-allocate matrix
        matrix = [[None for _ in range(l)] for _ in range(k)]

        # Generate all randomness at once
        total_coeffs = k * l * Polynomial.N
        total_bytes = total_coeffs * CHUNK_SIZE

        # Single SHAKE call for all coefficients
        shake = SHAKE128.new()
        shake.update(seed + bytes([DOMAIN_MATRIX]))
        all_data = np.frombuffer(shake.read(total_bytes), dtype=np.uint8)

        # Reshape data for vectorized processing
        coeffs_array = all_data.reshape(-1, CHUNK_SIZE)

        # Convert to coefficients using vectorized operations
        coeffs = np.zeros(total_coeffs, dtype=np.int32)

        # Process 4-byte chunks efficiently
        coeffs = (
            coeffs_array[:, 0].astype(np.int32)
            | (coeffs_array[:, 1].astype(np.int32) << 8)
            | (coeffs_array[:, 2].astype(np.int32) << 16)
            | (coeffs_array[:, 3].astype(np.int32) << 24)
        )

        # Modulo operation on whole array
        coeffs = coeffs % Polynomial.Q

        # Reshape into matrix of polynomials
        coeffs = coeffs.reshape(k, l, Polynomial.N)

        # Convert to polynomials
        for i in range(k):
            for j in range(l):
                matrix[i][j] = Polynomial(coeffs[i, j])

        # Cache result
        self._matrix_cache[cache_key] = matrix
        return matrix

    def hash_message(self, message: bytes) -> bytes:
        """Optimized message hashing"""
        self.reset()
        self._shake.update(bytes([DOMAIN_MESSAGE]) + message)
        return self._shake.read(32)

    def generate_challenge(
        self, message: bytes, public_key: tuple, w1: list
    ) -> Polynomial:
        """Optimized challenge generation"""
        rho, _ = public_key

        # Hash message
        mu = self.hash_message(message)

        # Initialize SHAKE
        self.reset()
        self._shake.update(mu)
        self._shake.update(rho)

        # Efficiently process w1 coefficients
        for poly in w1:
            coeffs = np.array(poly.coefficients, dtype=np.int32)
            self._shake.update(coeffs.tobytes())

        self._shake.update(bytes([DOMAIN_CHALLENGE]))

        # Generate challenge coefficients efficiently
        challenge_bytes = np.frombuffer(self._shake.read(TAU * 2), dtype=np.uint8)

        # Pre-allocate coefficient array
        coeffs = np.zeros(Polynomial.N, dtype=np.int32)

        # Process positions and signs efficiently
        positions = (
            challenge_bytes[::2].astype(np.uint16)
            | (challenge_bytes[1::2].astype(np.uint16) << 8)
        ) % Polynomial.N

        signs = np.where(challenge_bytes[::2] & 0x80, 1, -1)

        # Fill unique positions
        used_positions = set()
        pos_idx = 0

        while len(used_positions) < TAU and pos_idx < len(positions):
            pos = positions[pos_idx]
            if pos not in used_positions:
                coeffs[pos] = signs[pos_idx]
                used_positions.add(pos)
            pos_idx += 1

        return Polynomial(coeffs)


# Global instance for reuse
HASHER = OptimizedHasher()


# Optimized interface functions
def expand_seed(seed: bytes, domain: int, length: int) -> bytes:
    return OptimizedHasher.expand_seed(seed, domain, length)


def generate_matrix_from_seed(seed: bytes, k: int, l: int) -> list:  # noqa: E741
    return HASHER.generate_matrix(seed, k, l)


def hash_message(message: bytes) -> bytes:
    return HASHER.hash_message(message)


def generate_challenge(message: bytes, public_key: tuple, w1: list) -> Polynomial:
    return HASHER.generate_challenge(message, public_key, w1)


def test_performance():
    """Performance test"""
    import time

    print("=== Hash Operations Performance Test ===\n")

    # Test seed expansion
    start = time.time()
    seed = b"test_seed" * 4
    for _ in range(1000):
        _ = expand_seed(seed, DOMAIN_MATRIX, 32)
    print(f"1000 seed expansions: {time.time() - start:.3f} seconds")

    # Test matrix generation
    start = time.time()
    _ = generate_matrix_from_seed(seed, 4, 4)
    print(f"4x4 matrix generation: {time.time() - start:.3f} seconds")

    # Test cached matrix generation
    start = time.time()
    _ = generate_matrix_from_seed(seed, 4, 4)
    print(f"Cached matrix generation: {time.time() - start:.3f} seconds")

    # Test challenge generation
    dummy_w1 = [Polynomial([1, 2, 3]) for _ in range(4)]
    start = time.time()
    for _ in range(100):
        _ = generate_challenge(b"test message", (seed, dummy_w1), dummy_w1)
    print(f"100 challenge generations: {time.time() - start:.3f} seconds")


if __name__ == "__main__":
    test_performance()
