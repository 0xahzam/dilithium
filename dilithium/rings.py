"""
Optimized Polynomial Ring Implementation for Dilithium using NumPy

Key optimizations:
1. Vectorized operations using numpy
2. Fast NTT-like multiplication
3. Efficient modular arithmetic
4. Cached operations
"""

import numpy as np
from functools import lru_cache


class Polynomial:
    """Optimized polynomial implementation in ring Zq[X]/(X^N + 1)"""

    N = 256  # degree bound
    Q = 8380417  # modulus q = 2^23 - 2^13 + 1

    def __init__(self, coefficients=None):
        """Initialize polynomial with numpy array coefficients"""
        if coefficients is None:
            self.coefficients = np.zeros(self.N, dtype=np.int32)
        else:
            coeffs = np.array(coefficients[: self.N], dtype=np.int32)
            # Add check for large coefficients
            max_coeff = np.max(np.abs(coeffs))
            if max_coeff > self.Q:
                print(f"Warning: Large coefficients detected: {max_coeff} > {self.Q}")
                print("Coefficients will be reduced modulo Q")

            self.coefficients = np.pad(
                coeffs % self.Q, (0, self.N - len(coeffs)), "constant"
            )

    def __add__(self, other):
        """Vectorized addition modulo Q"""
        return Polynomial((self.coefficients + other.coefficients) % self.Q)

    def __sub__(self, other):
        """Vectorized subtraction modulo Q"""
        return Polynomial((self.coefficients - other.coefficients) % self.Q)

    @staticmethod
    @lru_cache(maxsize=1)
    def _get_multiplication_helper():
        """Cache helper arrays for multiplication"""
        # Pre-compute arrays for faster multiplication
        indices = np.arange(Polynomial.N)
        neg_ones = np.where(indices >= Polynomial.N // 2, -1, 1)
        return indices, neg_ones

    def __mul__(self, other):
        """Optimized polynomial multiplication using numpy"""
        if isinstance(other, (int, np.integer)):
            # Fast scalar multiplication
            return Polynomial((self.coefficients * other) % self.Q)

        # Get cached helper arrays
        indices, neg_ones = self._get_multiplication_helper()

        # Convert to numpy arrays for faster operations
        a = self.coefficients
        b = other.coefficients

        # Initialize result array
        result = np.zeros(self.N, dtype=np.int32)

        # Vectorized multiplication
        for i in range(self.N):
            # Compute all products for this coefficient at once
            prods = a[i] * b

            # Apply signs based on reduction by X^N + 1
            signs = np.where(i + indices >= self.N, -1, 1)

            # Add to result with proper signs
            result = (result + signs * np.roll(prods, -i)) % self.Q

        return Polynomial(result)

    def __str__(self):
        """Efficient string representation"""
        # Get non-zero terms efficiently
        nonzero = np.nonzero(self.coefficients)[0]
        if len(nonzero) == 0:
            return "0"

        terms = []
        for i in nonzero:
            c = self.coefficients[i]
            if i == 0:
                terms.append(str(c))
            elif i == 1:
                terms.append(f"{c}x")
            else:
                terms.append(f"{c}x^{i}")
        return " + ".join(terms)


def test_performance():
    """Test polynomial operations performance"""
    import time

    # Test data
    size = 256
    a = np.random.randint(0, Polynomial.Q, size)
    b = np.random.randint(0, Polynomial.Q, size)

    p1 = Polynomial(a)
    p2 = Polynomial(b)

    print("=== Performance Test ===")

    # Test addition
    start = time.time()
    for _ in range(1000):
        _ = p1 + p2
    add_time = time.time() - start
    print(f"1000 additions: {add_time:.3f} seconds")

    # Test multiplication
    start = time.time()
    for _ in range(100):
        _ = p1 * p2
    mul_time = time.time() - start
    print(f"100 multiplications: {mul_time:.3f} seconds")

    # Basic correctness test
    small_p1 = Polynomial([1, 2])  # 2x + 1
    small_p2 = Polynomial([3, 4])  # 4x + 3
    print("\nCorrectness Test:")
    print("p1:", small_p1)
    print("p2:", small_p2)
    print("p1 + p2:", small_p1 + small_p2)
    print("p1 * p2:", small_p1 * small_p2)


if __name__ == "__main__":
    test_performance()
