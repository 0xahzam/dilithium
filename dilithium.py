"""
CRYSTALS-Dilithium Implementation

This module implements the key generation part of the Dilithium digital signature scheme
using the polynomial ring arithmetic defined in rings.py.

Key components:
1. Matrix A: k x l matrix of uniformly random polynomials
2. Secret vectors: s1 (l x 1) and s2 (k x 1) of small polynomials
3. Public key: (A, t) where t = As1 + s2
"""

from rings import Polynomial
import random

# Dilithium Parameters
# For this implementation we'll use NIST level 2 parameters
# Reference: https://www.researchgate.net/figure/Dilithium-parameter-sets-for-NIST-security-levels-2-3-and-5-with-corresponding-expected_tbl2_362263379
K = 4  # matrix height
L = 4  # matrix width
ETA = 2  # bound for sampling small polynomials


def generate_uniform_poly():
    """
    Generate a polynomial with coefficients uniform in [0, Q-1]
    Used for matrix A elements
    """
    coeffs = [random.randrange(Polynomial.Q) for _ in range(Polynomial.N)]
    return Polynomial(coeffs)


def generate_small_poly():
    """
    Generate a polynomial with "small" coefficients in [-ETA, ETA]
    Used for secret vectors s1, s2
    """
    coeffs = [random.randint(-ETA, ETA) for _ in range(Polynomial.N)]
    return Polynomial(coeffs)


def generate_matrix_A(k: int, l: int):
    """
    Generate k x l matrix A with uniform random polynomials
    """
    return [[generate_uniform_poly() for _ in range(l)] for _ in range(k)]


def matrix_vector_multiply(matrix, vector):
    """
    Multiply matrix A with vector s1
    Returns resulting vector
    """
    k = len(matrix)
    l = len(matrix[0])
    result = []

    for i in range(k):
        sum_poly = Polynomial()  # zero polynomial
        for j in range(l):
            product = matrix[i][j] * vector[j]
            sum_poly = sum_poly + product
        result.append(sum_poly)

    return result


def generate_keys():
    """
    Generate Dilithium keypair
    Returns (public_key, private_key)
    """
    # 1. Generate uniform random matrix A
    A = generate_matrix_A(K, L)

    # 2. Generate small secret vectors s1 and s2
    s1 = [generate_small_poly() for _ in range(L)]
    s2 = [generate_small_poly() for _ in range(K)]

    # 3. Compute t = As1 + s2
    As1 = matrix_vector_multiply(A, s1)
    t = [As1[i] + s2[i] for i in range(K)]

    public_key = (A, t)
    private_key = (s1, s2)

    return public_key, private_key


def test_keygen():
    """
    Test key generation and print key components in a readable format
    """
    public_key, private_key = generate_keys()
    A, t = public_key
    s1, s2 = private_key

    print("=== DILITHIUM KEY GENERATION TEST ===")

    # Print summary of matrix A
    print("\n--- Public Key ---")
    print(f"Matrix A ({K}x{L}):")
    print("Sample entries (showing first few terms of each polynomial):")
    for i in range(min(2, K)):
        for j in range(min(2, L)):
            terms = str(A[i][j]).split("+")[:3]  # Get first 3 terms
            print(
                f"A[{i},{j}] = {' + '.join(terms)}{'...' if len(str(A[i][j]).split('+')) > 3 else ''}"
            )
    print("..." if K > 2 else "")

    # Print summary of vector t
    print("\nVector t:")
    for i in range(min(2, K)):
        terms = str(t[i]).split("+")[:3]
        print(
            f"t[{i}] = {' + '.join(terms)}{'...' if len(str(t[i]).split('+')) > 3 else ''}"
        )
    print("..." if K > 2 else "")

    # Print summary of private key
    print("\n--- Private Key ---")
    print("Vector s1 (small coefficients in [-η, η]):")
    for i in range(min(2, L)):
        terms = str(s1[i]).split("+")[:3]
        print(
            f"s1[{i}] = {' + '.join(terms)}{'...' if len(str(s1[i]).split('+')) > 3 else ''}"
        )
    print("..." if L > 2 else "")

    print("\nVector s2 (small coefficients in [-η, η]):")
    for i in range(min(2, K)):
        terms = str(s2[i]).split("+")[:3]
        print(
            f"s2[{i}] = {' + '.join(terms)}{'...' if len(str(s2[i]).split('+')) > 3 else ''}"
        )
    print("..." if K > 2 else "")

    # Print statistics
    print("\n--- Key Statistics ---")
    print(f"Matrix dimensions: {K}x{L}")
    print(f"Polynomial degree: {Polynomial.N-1}")
    print(f"Coefficient modulus q: {Polynomial.Q}")
    print(f"Small coefficient bound η: {ETA}")

    # Verify t = As1 + s2
    print("\n--- Verification ---")
    As1 = matrix_vector_multiply(A, s1)
    t_verify = [As1[i] + s2[i] for i in range(K)]

    matches = all(t[i].coefficients == t_verify[i].coefficients for i in range(K))
    print(f"Key verification: {'✓ successful' if matches else '✗ failed'}")

    return matches


if __name__ == "__main__":
    test_keygen()
