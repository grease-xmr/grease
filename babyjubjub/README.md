# Grease BabyJubJub

This repository contains an implementation of the BabyJubJub elliptic curve in Rust. 
BabyJubJub is a twisted Edwards curve that is widely used in zero-knowledge proof systems 
and privacy-preserving applications.

This implementation uses the `ark` suite of libraries for finite field arithmetic and elliptic curve operations,
which provide a nice standardized interface and efficient algorithms that have been implemented using ietf standards.

## Benchmarks

The results of the benchmarks on a machine with an AMD Ryzen 9 7900X 12-Core Processor are as follows with no 
special optimizations are listed below. The `asm` feature is on by default.

A typical group element addition takes 170 ns, and a scalar multiplication takes 59 µs.
Field element operations take around 2 ns, and conversions to and from big integers take around 20 ns.

Command run: `cargo bench`

| Test Name                                                                        | Time      |
|----------------------------------------------------------------------------------|-----------|
| Sample BabyJubJub::ProjectivePoint elements                                      | 19.768 µs |
| Arithmetic for BabyJubJub::ProjectivePoint/Addition                              | 170.80 ns |
| Arithmetic for BabyJubJub::ProjectivePoint/Subtraction                           | 173.20 ns |
| Arithmetic for BabyJubJub::ProjectivePoint/Mixed Addition                        | 163.07 ns |
| Arithmetic for BabyJubJub::ProjectivePoint/Mixed Subtraction                     | 163.38 ns |
| Arithmetic for BabyJubJub::ProjectivePoint/Double                                | 135.91 ns |
| Arithmetic for BabyJubJub::ProjectivePoint/Scalar Multiplication                 | 59.203 µs |
| Serialization for BabyJubJub::ProjectivePoint/Serialize Compressed               | 26.977 ns |
| Serialization for BabyJubJub::ProjectivePoint/Serialize Uncompressed             | 36.405 ns |
| Serialization for BabyJubJub::ProjectivePoint/Deserialize Compressed             | 67.936 µs |
| Serialization for BabyJubJub::ProjectivePoint/Deserialize Compressed Unchecked   | 11.096 µs |
| Serialization for BabyJubJub::ProjectivePoint/Deserialize Uncompressed           | 56.746 µs |
| Serialization for BabyJubJub::ProjectivePoint/Deserialize Uncompressed Unchecked | 102.15 ns |
| MSM for BabyJubJub::ProjectivePoint                                              | 52.031 ms |
| Arithmetic for BabyJubJub::Fr/Addition                                           | 2.3221 ns |
| Arithmetic for BabyJubJub::Fr/Subtraction                                        | 2.3271 ns |
| Arithmetic for BabyJubJub::Fr/Negation                                           | 2.2002 ns |
| Arithmetic for BabyJubJub::Fr/Double                                             | 2.3093 ns |
| Arithmetic for BabyJubJub::Fr/Multiplication                                     | 15.204 ns |
| Arithmetic for BabyJubJub::Fr/Square                                             | 13.446 ns |
| Arithmetic for BabyJubJub::Fr/Inverse                                            | 2.7454 µs |
| Arithmetic for BabyJubJub::Fr/Sum of products of size 2                          | 24.988 ns |
| Arithmetic for BabyJubJub::Fr/Naive sum of products of size 2                    | 28.453 ns |
| Serialization for BabyJubJub::Fr/Serialize Compressed                            | 11.795 ns |
| Serialization for BabyJubJub::Fr/Serialize Uncompressed                          | 11.733 ns |
| Serialization for BabyJubJub::Fr/Deserialize Compressed                          | 23.108 ns |
| Serialization for BabyJubJub::Fr/Deserialize Compressed Unchecked                | 22.848 ns |
| Serialization for BabyJubJub::Fr/Deserialize Uncompressed                        | 22.692 ns |
| Serialization for BabyJubJub::Fr/Deserialize Uncompressed Unchecked              | 22.940 ns |
| SquareRoot for BabyJubJub::Fr/Square Root for QR                                 | 4.7030 µs |
| SquareRoot for BabyJubJub::Fr/Legendre for QR                                    | 4.6627 µs |
| Arithmetic for BabyJubJub::Fr::BigInt/Addition with carry                        | 2.3740 ns |
| Arithmetic for BabyJubJub::Fr::BigInt/Subtraction with borrow                    | 2.3693 ns |
| Arithmetic for BabyJubJub::Fr::BigInt/Multiplication by 2                        | 2.1842 ns |
| Arithmetic for BabyJubJub::Fr::BigInt/Division by 2                              | 1.9757 ns |
| Bitwise operations for BabyJubJub::Fr::BigInt/Number of bits                     | 2.3466 ns |
| Bitwise operations for BabyJubJub::Fr::BigInt/From Little-Endian bits            | 72.059 ns |
| Bitwise operations for BabyJubJub::Fr::BigInt/From Big-Endian bits               | 71.500 ns |
| Bitwise operations for BabyJubJub::Fr::BigInt/Comparison                         | 2.0372 ns |
| Bitwise operations for BabyJubJub::Fr::BigInt/Equality                           | 2.3583 ns |
| Bitwise operations for BabyJubJub::Fr::BigInt/Is Zero                            | 1.9834 ns |
| Conversions for BabyJubJub::Fr/From BigInt                                       | 19.209 ns |
| Conversions for BabyJubJub::Fr/Into BigInt                                       | 9.2030 ns |
| Arithmetic for BabyJubJub::Fq/Addition                                           | 2.3183 ns |
| Arithmetic for BabyJubJub::Fq/Subtraction                                        | 2.2760 ns |
| Arithmetic for BabyJubJub::Fq/Negation                                           | 2.2006 ns |
| Arithmetic for BabyJubJub::Fq/Double                                             | 2.3330 ns |
| Arithmetic for BabyJubJub::Fq/Multiplication                                     | 16.104 ns |
| Arithmetic for BabyJubJub::Fq/Square                                             | 13.412 ns |
| Arithmetic for BabyJubJub::Fq/Inverse                                            | 2.7632 µs |
| Arithmetic for BabyJubJub::Fq/Sum of products of size 2                          | 25.441 ns |
| Arithmetic for BabyJubJub::Fq/Naive sum of products of size 2                    | 28.960 ns |
| Serialization for BabyJubJub::Fq/Serialize Compressed                            | 11.024 ns |
| Serialization for BabyJubJub::Fq/Serialize Uncompressed                          | 10.978 ns |
| Serialization for BabyJubJub::Fq/Deserialize Compressed                          | 23.526 ns |
| Serialization for BabyJubJub::Fq/Deserialize Compressed Unchecked                | 23.377 ns |
| Serialization for BabyJubJub::Fq/Deserialize Uncompressed                        | 23.445 ns |
| Serialization for BabyJubJub::Fq/Deserialize Uncompressed Unchecked              | 23.569 ns |
| SquareRoot for BabyJubJub::Fq/Square Root for QR                                 | 7.9560 µs |
| SquareRoot for BabyJubJub::Fq/Legendre for QR                                    | 4.8499 µs |
| Arithmetic for BabyJubJub::Fq::BigInt/Addition with carry                        | 2.3782 ns |
| Arithmetic for BabyJubJub::Fq::BigInt/Subtraction with borrow                    | 2.3852 ns |
| Arithmetic for BabyJubJub::Fq::BigInt/Multiplication by 2                        | 2.1878 ns |
| Arithmetic for BabyJubJub::Fq::BigInt/Division by 2                              | 1.9777 ns |
| Bitwise operations for BabyJubJub::Fq::BigInt/Number of bits                     | 2.3690 ns |
| Bitwise operations for BabyJubJub::Fq::BigInt/From Little-Endian bits            | 71.365 ns |
| Bitwise operations for BabyJubJub::Fq::BigInt/From Big-Endian bits               | 70.893 ns |
| Bitwise operations for BabyJubJub::Fq::BigInt/Comparison                         | 2.0668 ns |
| Bitwise operations for BabyJubJub::Fq::BigInt/Equality                           | 2.3404 ns |
| Bitwise operations for BabyJubJub::Fq::BigInt/Is Zero                            | 1.9984 ns |
| Conversions for BabyJubJub::Fq/From BigInt                                       | 19.762 ns |
| Conversions for BabyJubJub::Fq/Into BigInt                                       | 8.6656 ns |


