"""
CRYSTALS-Dilithium Implementation

This is a structured implementation of Dilithium's key generation using:
1. Ring operations from rings.py
2. Deterministic randomness from hash.py (SHAKE128)
"""

from rings import Polynomial
from hash import expand_seed, generate_matrix_from_seed
import secrets  # For secure random seed generation

# Dilithium Parameters
# Reference: https://www.researchgate.net/figure/Dilithium-parameter-sets-for-NIST-security-levels-2-3-and-5-with-corresponding-expected_tbl2_362263379
PARAMS = {
    2: {"k": 4, "l": 4, "eta": 2},  # NIST Security Level 2
    3: {"k": 6, "l": 5, "eta": 4},  # NIST Security Level 3
    5: {"k": 8, "l": 7, "eta": 2},  # NIST Security Level 5
}


class Dilithium:
    def __init__(self, security_level=2):
        """Initialize Dilithium with desired security level"""
        if security_level not in PARAMS:
            raise ValueError("Security level must be 2, 3, or 5")

        params = PARAMS[security_level]
        self.k = params["k"]  # Matrix height
        self.l = params["l"]  # Matrix width
        self.eta = params["eta"]  # Bound for small coefficients

    def generate_small_poly(self):
        """Generate polynomial with coefficients in [-eta, eta]"""
        # Example: if eta=2, coefficients are in {-2, -1, 0, 1, 2}
        seed = secrets.token_bytes(32)
        coeffs = []

        # Get randomness from SHAKE128
        randomness = expand_seed(seed, 0x03, Polynomial.N)  # 0x03 domain for small poly
        for byte in randomness:
            # Convert byte to coefficient in [-eta, eta]
            coeff = byte % (2 * self.eta + 1) - self.eta
            coeffs.append(coeff)

        return Polynomial(coeffs[: Polynomial.N])

    def keygen(self):
        """
        Generate Dilithium keypair
        Returns (public_key, private_key)
        """
        # 1. Generate random seed for matrix A (32 bytes)
        rho = secrets.token_bytes(32)

        # 2. Generate matrix A deterministically from seed
        A = generate_matrix_from_seed(rho, self.k, self.l)

        # 3. Generate secret vectors with small coefficients
        s1 = [self.generate_small_poly() for _ in range(self.l)]
        s2 = [self.generate_small_poly() for _ in range(self.k)]

        # 4. Compute t = As1 + s2
        t = []
        for i in range(self.k):
            row_sum = s2[i]  # Start with s2[i]
            for j in range(self.l):
                row_sum = row_sum + A[i][j] * s1[j]
            t.append(row_sum)

        # Public key is (rho, t), where rho is seed for A
        # Private key is (s1, s2)
        return (rho, t), (s1, s2)


def test_keygen():
    """Test key generation with detailed output"""
    print("\n=== DILITHIUM KEY GENERATION TEST ===")

    # Create instance with security level 2
    dilithium = Dilithium(security_level=2)
    print(f"\nParameters:")
    print(f"k = {dilithium.k} (matrix rows)")
    print(f"l = {dilithium.l} (matrix columns)")
    print(f"η = {dilithium.eta} (coefficient bound)")

    # Generate keys
    public_key, private_key = dilithium.keygen()
    rho, t = public_key
    s1, s2 = private_key

    print("\n--- Public Key ---")
    print(f"rho (seed for A): {rho.hex()}")
    print("\nVector t (sample entries):")
    for i in range(min(2, len(t))):
        terms = str(t[i]).split("+")[:3]
        print(f"t[{i}] = {' + '.join(terms)}...")

    print("\n--- Private Key ---")
    print("Vector s1 (sample entries):")
    for i in range(min(2, len(s1))):
        print(f"s1[{i}] = {s1[i]}")

    print("\nVector s2 (sample entries):")
    for i in range(min(2, len(s2))):
        print(f"s2[{i}] = {s2[i]}")

    # Verify t = As1 + s2
    print("\n--- Verification ---")
    A = generate_matrix_from_seed(rho, dilithium.k, dilithium.l)
    t_verify = []
    for i in range(dilithium.k):
        row_sum = s2[i]
        for j in range(dilithium.l):
            row_sum = row_sum + A[i][j] * s1[j]
        t_verify.append(row_sum)

    matches = all(
        t[i].coefficients == t_verify[i].coefficients for i in range(dilithium.k)
    )
    print(f"Key verification: {'✓ successful' if matches else '✗ failed'}")


if __name__ == "__main__":
    test_keygen()
