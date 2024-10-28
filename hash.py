"""
SHAKE128 Implementation for Dilithium using PyCryptodome

Key Components:
1. SHAKE128: An eXtendable Output Function (XOF) from SHA-3 family
  - Can produce output of any desired length
  - '128' indicates security level in bits
  - Based on Keccak sponge construction
  - Standardized in FIPS 202

2. Usage in Dilithium:
  a. Deterministic Matrix Generation:
     - Generate matrix A from small seed
     - Makes public keys smaller (store seed instead of matrix)
     - Ensures reproducibility
"""

from Crypto.Hash import SHAKE128

# Domain separators to prevent cross-protocol attacks
DOMAIN_MATRIX = 0x01
DOMAIN_CHALLENGE = 0x02


def expand_seed(seed: bytes, domain: int, length: int) -> bytes:
    """
    Expand a seed to desired length using SHAKE128 with domain separation.

    Args:
        seed: Input seed bytes
        domain: Domain separator (prevents attacks across different uses)
        length: Desired output length in bytes

    Returns:
        bytes: Expanded seed of specified length
    """
    shake = SHAKE128.new()
    shake.update(seed + bytes([domain]))
    return shake.read(length)


def generate_matrix_from_seed(seed: bytes, k: int, l: int) -> list:
    """
    Deterministically generate matrix A from seed.
    Each matrix element is a polynomial in ring Zq[X]/(X^N + 1).

    Process:
    1. Use seed + position + domain to generate randomness
    2. Convert randomness to polynomial coefficients
    3. Ensure coefficients are properly reduced modulo q

    Args:
        seed: 32-byte random seed
        k: Number of rows in matrix
        l: Number of columns in matrix

    Returns:
        list: k x l matrix of polynomials
    """
    from rings import Polynomial

    # Initialize empty k × l matrix
    matrix = []

    for i in range(k):
        row = []
        for j in range(l):
            # 1. Generate unique randomness for position (i,j)
            shake = SHAKE128.new()
            # Make input unique by concatenating:
            # - seed: base randomness (same for whole matrix)
            # - [i, j]: position indicators (unique per position)
            # - DOMAIN_MATRIX: separates this use from other SHAKE128 uses
            shake.update(seed + bytes([i, j, DOMAIN_MATRIX]))

            # 2. Generate randomness for polynomial coefficients
            # Need 256 coefficients (degree N-1 polynomial)
            # Each coefficient needs 4 bytes because:
            # - q = 8,380,417 needs 23 bits
            # - 4 bytes = 32 bits is enough to cover this
            data = shake.read(Polynomial.N * 4)  # 256 * 4 = 1024 bytes

            # 3. Convert bytes to coefficients modulo q
            coeffs = []
            # Take 4 bytes at a time from data
            for idx in range(0, len(data), 4):
                # Convert 4 bytes to integer (little-endian)
                # Example: b'\x01\x02\x03\x04' -> 67,305,985
                coeff = int.from_bytes(data[idx : idx + 4], "little")
                # Reduce modulo q to get valid coefficient
                coeffs.append(coeff % Polynomial.Q)

            # 4. Create polynomial with these coefficients
            # and add to current matrix position
            row.append(Polynomial(coeffs))
        matrix.append(row)

    return matrix


def test_hash_functions():
    """
    Test vectors and functionality verification for hash operations
    """
    print("=== SHAKE128 Function Tests ===\n")

    # Test 1: Seed expansion
    seed = b"test_seed"
    print("Test seed expansion:")
    expanded = expand_seed(seed, DOMAIN_MATRIX, 32)
    print(f"Input seed: {seed.hex()}")
    print(f"Expanded (32 bytes): {expanded.hex()}\n")

    # Test 2: Matrix generation (small example)
    print("Test matrix generation (2x2 sample):")
    matrix = generate_matrix_from_seed(seed, 2, 2)
    for i in range(2):
        for j in range(2):
            terms = str(matrix[i][j]).split("+")[:2]
            print(f"A[{i},{j}] = {' + '.join(terms)}...")
    print()


if __name__ == "__main__":
    test_hash_functions()
