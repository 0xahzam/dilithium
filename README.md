# Lattice-Based Cryptography Notes

## Basic Concepts

### What is a Lattice?

- In cryptography, a lattice is a mathematical structure - specifically, it's a set of points in n-dimensional space with a periodic structure
- Think of it like an infinite grid of points, but potentially in many dimensions, not just 2D or 3D like crystal lattices

### Mathematical Definition

A lattice L is a set of all integer linear combinations of some linearly independent vectors b₁, ..., bₙ:

$L = \{a₁b₁ + a₂b₂ + ... + aₙbₙ : aᵢ ∈ Z\}$

where:

- b₁, ..., bₙ are the basis vectors
- aᵢ are integers
- n is the dimension of the lattice

## Core Problems in Lattice Cryptography

### 1. Shortest Vector Problem (SVP)

- **Definition**: Find the shortest non-zero vector in a lattice
- **Mathematical form**: Find $v ∈ L, v ≠ 0$ that minimizes $\|v\|$
- **Why it's hard**: Complexity grows exponentially with dimension

### 2. Closest Vector Problem (CVP)

- **Definition**: Find the closest lattice point to a given target point
- **Mathematical form**: Given target t, find $v ∈ L$ that minimizes $\|t - v\|$
- **Why it's hard**: Related to SVP, also exponentially hard with dimension

### 3. Learning With Errors (LWE)

- **Definition**: Recover secret vector s from noisy inner products
- **Mathematical form**: Given $(A, As + e)$, find s where:
- A is a random matrix
- s is the secret vector
- e is a small error vector

## Public Key Encryption Using Lattices

### Using SVP for Encryption:

1. Key Generation:

- Generate a lattice with a known short vector s (private key)
- Transform the lattice basis to hide s (public key)
- The hard problem: Finding s from the public basis requires solving SVP

2. Encryption Process:

- Encode message as points near lattice points
- Add small random shifts to these points
- Security comes from hardness of finding original points without knowing s

3. Decryption Process:

- Use private key s to find closest lattice points
- Remove random shifts
- Recover original message

### Using CVP for Encryption:

1. Setup:

- Create a lattice with two bases:
  - B₁: "good" basis (private key) - makes finding close points easy
  - B₂: "bad" basis (public key) - makes finding close points hard

2. Encryption:

- Convert message m to a point p
- Find a lattice point near p using public basis
- Add small random error e
- Ciphertext = nearest_point + e

3. Decryption:

- Use private basis to find closest lattice point to ciphertext
- Distance between this point and original gives message

### Security Foundation:

- Finding closest points is easy with "good" basis (private key)
- Finding closest points is hard with "bad" basis (public key)
- Converting between bases requires solving hard lattice problems
