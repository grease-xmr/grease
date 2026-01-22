# libgrease - Cryptogrpahic primitves and ZK-snark support

## Poseidon 2

The `next_witness` function for the GrumpkinPosedin2 VCOF makes use of only the permutation of Poseidon2, rather than a full sponge
construction.

What follows is a security analysis comparing the Sponge construction versus the Direct Permutation approach for Poseidon2.

### Executive Summary

The Sponge construction (`poseidon_hash`) is the architecturally sound and conservative choice for general-purpose hashing. It offers
standard cryptographic guarantees (Collision Resistance, Preimage Resistance) and creates a clear separation between the internal state and
the output.

The Direct Permutation approach (often called a "Compression Function" or "Permutation-based" hash) is theoretically weaker because it
treats the cryptographic permutation as a random oracle without the domain separation and rate/capacity safeguards of a sponge. However, in
the specific context of Zero-Knowledge (ZK) proof systems where Poseidon2 is primarily used, this approach is considered **secure in
practice** and is widely adopted (as seen in Noir, Aztec, and Polygon) because the security proofs for ZK-SNARKs often rely on the hardness
of inverting the underlying permutation, which remains extremely high.

To answer your specific question directly: **The direct permutation approach is *theoretically* invertible, but *practically* infeasible to
invert.**

---

### Detailed Security Analysis

#### 1. Sponge Construction (`poseidon_hash`)

This approach treats the Poseidon2 permutation as a core component of a sponge mode of operation.

* **Mechanism:**
    * **State:** Rate ($r$) + Capacity ($c$). In your case, $r=3$, $c=1$ (Width 4).
    * **Process:** Input is absorbed into the rate elements. The permutation $P$ is applied. Output is squeezed from the rate elements.
    * **IV:** Uses an Initialization Vector derived from length ($len \cdot 2^{64}$), preventing length-extension attacks and ensuring
      unique mappings for different input lengths.

* **Security Guarantees:**
    * **Collision Resistance:** If the permutation $P$ behaves like a random permutation, the sponge inherits collision resistance up
      to $2^{min(r, c)/2}$.
    * **Preimage Resistance:** Resistant to preimage attacks up to $2^{min(r, c)}$.
    * **Indifferentiability from Random Oracle (IRO):** The Sponge construction is proven to be indifferentiable from a Random Oracle,
      assuming the underlying permutation is random. This is the "gold standard" for hash function design.

* **Pros:**
    * **Standardized Security:** Benefits from decades of cryptographic analysis regarding sponge structures (e.g., Keccak/SHA-3).
    * **Capacity Protection:** The 1 element of capacity is never outputted. It acts as an internal "chaining value," ensuring that finding
      a collision requires controlling the internal state, which is exponentially harder than just finding inputs that map to the same
      output.
    * **Domain Separation:** The IV handling ensures that inputs of different lengths cannot collide.

* **Cons:**
    * **Cost:** Slightly higher cost in ZK contexts because you must execute the permutation for every block of input, plus potentially
      multiple permutations to "squeeze" out the full hash if the output length exceeds the rate.

#### 2. Direct Permutation Approach (Noir's `hash_3`)

This approach uses the Poseidon2 permutation directly as a compression function or a fixed-length hash.

* **Mechanism:**
    * **Input:** $[a, b, c, 0]$.
    * **Process:** Compute $P([a, b, c, 0]) = [h_0, h_1, h_2, h_3]$.
    * **Output:** Return $h_0$.

* **Theoretical Weaknesses:**
    * **Loss of IRO:** This method is **not** indifferentiable from a Random Oracle in the standard model. It exposes the internal state of
      the permutation directly as the output. A generic attack exists where an adversary can query the permutation on chosen inputs and
      potentially distinguish it from a random oracle or find a collision more efficiently than brute force ($2^{c/2}$ vs $2^n$).
    * **Multi-Collisions:** Because there is no capacity element acting as an internal churn, it is theoretically easier (though still
      practically hard) to find "multi-collisions" (many inputs mapping to the same state) compared to a sponge.
    * **Lack of Domain Separation (Inherent):** While specific implementations (like Noir) may handle padding, the primitive itself (the
      permutation) does not natively separate domains. If you hash 3 elements $[a, b, c]$ and 3 elements $[d, e, f]$ using the same
      permutation structure, they are in the same "domain."

* **Practical Security & "Why it works in ZK":**
    * **Poseidon2 Strength:** The security relies entirely on the permutation $P$ being indistinguishable from a random permutation.
      Poseidon2 is designed with massive full rounds to ensure algebraic immunity.
    * **Output Truncation:** By returning only $h_0$ (instead of the full 4-word state), you are essentially "freezing" the rest of the
      state. To invert the hash (find $a, b, c$ given $h_0$), an attacker would need to invert the permutation $P$.
    * **Inversion Complexity:** Inverting a single Poseidon2 permutation instance requires searching the entire input
      space ($2^{\text{field size}}$), which is computationally infeasible.

### Feasibility of Inversion (Direct Permutation)

**No, it is not feasibly invertible.**

Here is the distinction between theoretical and practical invertibility:

1. **Mathematical Invertibility:** Yes, the Poseidon2 permutation is a bijective function. For every output state $[h_0, h_1, h_2, h_3]$,
   there exists exactly one unique input state $[a, b, c, 0]$.
2. **Cryptographic Invertibility:** To find the input $a, b, c$ given the output $h_0$, you face two massive hurdles:
    * **Algebraic Structure:** The Poseidon2 permutation consists of S-boxes (power maps, typically $x^{-1}$ or $x^3$ or $x^5$ depending on
      the field) and linear layers (MDS matrices). The linear layers are easy to undo, but the non-linear S-boxes are designed to be
      trapdoors. Inverting them requires solving systems of high-degree polynomial equations over the prime field.
    * **Partial Output:** You only have $h_0$. You are missing $h_1, h_2, h_3$. Even if you had the entire output, inverting the permutation
      is still as hard as the "Algebraic One-Wayness" assumption.

**Conclusion on Inversion:**
While the function is mathematically reversible (bijective), there is no known algorithm that can invert a Poseidon2 permutation
significantly faster than brute force, provided the parameters (rounds, field size) are chosen correctly. Therefore, in practice, it acts as
a one-way function.

### Comparison Verdict

| Feature                  | Sponge Construction (`poseidon_hash`)                   | Direct Permutation (`hash_3`)                                     |
|:-------------------------|:--------------------------------------------------------|:------------------------------------------------------------------|
| **Theoretical Security** | **High.** Proven indifferentiable from a Random Oracle. | **Medium.** Not indifferentiable; relies on permutation strength. |
| **Collision Resistance** | $\approx 2^{min(r, c)/2}$                               | $\approx 2^{n/2}$ (Relies on permutation not being broken)        |
| **Preimage Resistance**  | $\approx 2^{min(r, c)}$                                 | $\approx 2^n$ (Algebraic One-Wayness)                             |
| **ZK Circuit Cost**      | Higher. Requires padding and state management.          | **Lower.** Single permutation call, optimized fixed-width.        |
| **Common Use Case**      | General hashing, Merkle Trees, Arbitrary Length Data.   | Merkle Paths (fixed width), Hashing public inputs, Commitments.   |

When optimizing a ZK circuit (like a Rollup or ZK-RPG) and specifically hashing fixed-width data (like 3 field elements) to minimize
gate count, the **Direct Permutation approach is acceptable and standard industry practice**, provided you are confident in the Poseidon2
parameters (rounds) used. The "theoretical weakness" is an academic distinction that does not currently translate to a practical exploit.
