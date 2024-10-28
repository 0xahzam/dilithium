"""
Polynomial Ring Implementation for Dilithium

This module implements the polynomial ring Zq[X]/(X^N + 1) used in the CRYSTALS-Dilithium 
digital signature scheme. The ring consists of polynomials with:
- Degree bound N = 256
- Coefficients in Zq where q = 2^23 - 2^13 + 1 = 8,380,417
- Reduction by X^N + 1

The implementation provides basic ring operations (addition, subtraction, multiplication)
with all arithmetic performed modulo q and polynomial reduction by X^N + 1.

Example:
   # Create and operate on polynomials
   p1 = Polynomial([1, 2])  # represents 2x + 1
   p2 = Polynomial([3, 4])  # represents 4x + 3
   sum_poly = p1 + p2      # polynomial addition
   prod_poly = p1 * p2     # polynomial multiplication
"""


class Polynomial:
    """
    A polynomial in the ring Zq[X]/(X^N + 1).

    Attributes:
        N (int): Degree bound of polynomials (256)
        Q (int): Modulus for coefficient arithmetic (2^23 - 2^13 + 1 = 8,380,417)
        coefficients (list): List of polynomial coefficients [a₀, a₁, ..., a_{N-1}]
    """

    N = 256  # degree bound
    Q = 8380417  # modulus q = 2^23 - 2^13 + 1

    def __init__(self, coefficients=None):
        """
        Initialize a polynomial with given coefficients.

        Args:
            coefficients (list, optional): List of integer coefficients.
            - If None, creates zero polynomial.
            - Coefficients are reduced modulo Q and padded/truncated to length N.
        """
        if coefficients is None:
            self.coefficients = [0] * self.N
        else:
            # Reduce coefficients modulo Q
            self.coefficients = [c % self.Q for c in coefficients[: self.N]]
            # Pad with zeros to length N
            self.coefficients.extend([0] * (self.N - len(self.coefficients)))

    def __add__(self, other):
        """
        Add two polynomials coefficient-wise modulo Q.

        Args:
            other (Polynomial): Polynomial to add

        Returns:
            Polynomial: Result of addition
        """
        return Polynomial(
            [(a + b) % self.Q for a, b in zip(self.coefficients, other.coefficients)]
        )

    def __sub__(self, other):
        """
        Subtract two polynomials coefficient-wise modulo Q.

        Args:
            other (Polynomial): Polynomial to subtract

        Returns:
            Polynomial: Result of subtraction
        """
        return Polynomial(
            [(a - b) % self.Q for a, b in zip(self.coefficients, other.coefficients)]
        )

    def __mul__(self, other):
        """
        Multiply two polynomials and reduce modulo (X^N + 1).

        Implementation of polynomial multiplication in the ring Zq[X]/(X^N + 1).
        The result is reduced both coefficient-wise modulo Q and by the polynomial X^N + 1.

        Args:
            other (Polynomial): Polynomial to multiply

        Returns:
            Polynomial: Result of multiplication
        """
        result = [0] * self.N

        for i in range(self.N):
            for j in range(self.N):
                # Calculate degree after multiplication
                deg = i + j
                if deg >= self.N:
                    # If degree ≥ N, use reduction X^N = -1
                    deg = deg - self.N
                    coeff = (-self.coefficients[i] * other.coefficients[j]) % self.Q
                else:
                    coeff = (self.coefficients[i] * other.coefficients[j]) % self.Q
                result[deg] = (result[deg] + coeff) % self.Q

        return Polynomial(result)

    def __str__(self):
        """
        Convert polynomial to string representation.

        Returns:
            str: Human-readable string showing non-zero terms of the polynomial
        """
        terms = []
        for i, c in enumerate(self.coefficients):
            if c != 0:
                if i == 0:
                    terms.append(str(c))
                elif i == 1:
                    terms.append(f"{c}x")
                else:
                    terms.append(f"{c}x^{i}")
        return " + ".join(terms) if terms else "0"


def test():
    """
    Test basic polynomial operations.

    Creates simple polynomials and tests addition, subtraction, and multiplication
    operations to verify correct implementation.
    """
    # Create simple polynomials
    p1 = Polynomial([1, 2])  # 2x + 1
    p2 = Polynomial([3, 4])  # 4x + 3

    print("p1:", p1)
    print("p2:", p2)
    print("p1 + p2:", p1 + p2)
    print("p1 - p2:", p1 - p2)
    print("p1 * p2:", p1 * p2)


if __name__ == "__main__":
    test()
