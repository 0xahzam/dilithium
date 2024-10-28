# Optimized Dilithium Implementation

## Overview

This repository attempts at creating a highly optimized implementation of the CRYSTALS-Dilithium post-quantum digital signature scheme.

Currently, it achieves the following metrics (tested on standard hardware):

There's still a lot of room to improve on performance using GPU acceleration.

```
Performance Summary:
------------------
Key Generation:    65.80 ms
Signing Time:      81.17 ms
Verify Time:        0.28 ms
Total Time:       147.25 ms
```

Note: There are inaccuracies, the bounds are very extremely relaxed for learning purposes.

## Mathematical Foundation

### Ring Structure

We work in the polynomial ring Rq = Zq[X]/(X^n + 1) where:

- q = 2^23 - 2^13 + 1 = 8,380,417 (Carefully chosen prime for efficient NTT)
- n = 256 (Power of 2 for efficient NTT operations)

The choice of these parameters enables:

1. Efficient modular reduction
2. Fast NTT-based polynomial multiplication
3. Optimal security-performance tradeoff

### Parameter Sets

We implement three security levels following NIST standards:

```
PARAMS = {
    2: {"k": 4, "l": 4, "eta": 2},  # NIST Security Level 2
    3: {"k": 6, "l": 5, "eta": 4},  # NIST Security Level 3
    5: {"k": 8, "l": 7, "eta": 2},  # NIST Security Level 5
}
```

### Core Operations

The scheme consists of three main algorithms:

1. **Key Generation**:

   - Generate random seed rho
   - Derive matrix A in Rq^(k×l) from rho
   - Sample small polynomials s1 in S_eta^l, s2 in S_eta^k
   - Compute t = As1 + s2
   - Output (rho,t) as public key and (s1,s2) as secret key

2. **Signing**:

   - Sample y with coefficients in [-gamma1, gamma1]
   - Compute w = Ay
   - Generate challenge c using w
   - Compute z = y + cs1
   - Output signature (z,c,w)

3. **Verification**:

   - Check that infinity norm of z < gamma1 - beta
   - Verify challenge reconstruction
   - Check bounds on w

## Optimizations

### 1. Polynomial Operations

```python
class Polynomial:
    N = 256
    Q = 8380417  # 2^23 - 2^13 + 1
```

Key optimizations:

- Vectorized operations using NumPy for all polynomial arithmetic
- Pre-allocated numpy arrays for coefficient storage
- Cached helper arrays for multiplication
- Efficient modular reduction using the special form of q

### 2. Matrix Operations

Matrix-vector multiplication optimization:

- Cached matrix generation using LRU cache
- Vectorized coefficient generation
- Pre-allocated result vectors
- Batch processing of polynomial multiplications

### 3. SHAKE128 Optimizations

```python
class OptimizedHasher:
    def __init__(self):
        self._shake = SHAKE128.new()
        self._matrix_cache = {}
```

Improvements:

- Single SHAKE instance reuse
- Cached seed expansion
- Vectorized coefficient extraction
- Batch processing of challenge generation
- Pre-allocated buffers for hash operations

### 4. Memory Management

- Use of `@lru_cache` for frequently accessed computations
- Pre-allocated numpy arrays
- Efficient buffer reuse in hash operations
- Minimized memory allocations in hot paths

### 5. Coefficient Generation

- Vectorized generation of random coefficients
- Efficient modular reduction using bit operations
- Batch processing of polynomial coefficients
- Optimized challenge polynomial generation

## Performance Critical Sections

1. **Polynomial Multiplication**:

```python
def __mul__(self, other):
    indices, neg_ones = self._get_multiplication_helper()
    result = np.zeros(self.N, dtype=np.int32)
    # Vectorized multiplication using numpy
    for i in range(self.N):
        prods = a[i] * b
        positions = (i + indices) % self.N
        signs = np.where(i + indices >= self.N, -1, 1)
        result = (result + signs * np.roll(prods, -i)) % self.Q
```

2. **Matrix Generation**:

```python
def generate_matrix(self, seed: bytes, k: int, l: int) -> list:
    total_coeffs = k * l * Polynomial.N
    total_bytes = total_coeffs * CHUNK_SIZE
    all_data = np.frombuffer(shake.read(total_bytes), dtype=np.uint8)
    coeffs_array = all_data.reshape(-1, CHUNK_SIZE)
```

3. **Challenge Generation**:

```python
def generate_challenge(self, message: bytes, public_key: tuple, w1: list) -> Polynomial:
    challenge_bytes = np.frombuffer(self._shake.read(TAU * 2), dtype=np.uint8)
    positions = (challenge_bytes[::2].astype(np.uint16) |
                (challenge_bytes[1::2].astype(np.uint16) << 8)) % Polynomial.N
```

## Security Considerations

- Implementation follows constant-time principles where possible
- Careful bounds checking on all operations
- Secure random number generation using `secrets` module
- Protection against timing attacks in critical operations
