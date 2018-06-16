PALISADE Lattice Cryptography Library - Demos
=============================================

[License Information](License.md)

[Contact Information](Contact.md)

Document Description
===================
This document is intended to describe the demo programs included with the PALISADE lattice crypto library.

Demo Directory Description
==========================

Directory Objective
-------------------
This directory contains demo programs that, when linked with the library, demonstrate the capabilities of the system

File Listing
------------

* Demo programs
- [demo_fusion_simple.cpp](src/pke/demo/demo_fusion_simple.cpp): a demo program of multiparty FHE operations built on FV.
- [demo-automorphism.cpp](src/pke/demo/demo-automorphism.cpp): demonstrates use of EvalAutomorphism for different schemes, plaintext encodings, and cyclotomic rings
- [demo-bfvrns.cpp](src/pke/demo/demo-bfvrns.cpp): demonstrates use of the BFVrns scheme for basic SHE operations
- [demo-cross-correlation.cpp](src/pke/demo/demo-cross-correlation.cpp): a demo program that demonstrates the use of serialization, DCRT, arbitrary cyclotomics, and packed encoding for an application that computes cross-correlation using inner products.
- [demo-cross-correlation-bfvrns.cpp](src/pke/demo/demo-cross-correlation-bfrns.cpp): a demo program that demonstrates the use of serialization, DCRT, power-of-two-cyclotomics, and packed encoding for an application that computes cross-correlation using inner products.
- [demo-crypt-pre-text.cpp](src/pke/demo/demo-crypt-pre-text.cpp): demonstrates use of PALISADE for encryption, re-encryption and decryption of text
- [demo-depth-bfvrns.cpp](src/pke/demo/demo-depth-bfvrns.cpp): demonstrates use of the BFVrns scheme for basic homomorphic encryption
- [demo-depth-bfvrns-b.cpp](src/pke/demo/demo-depth-bfvrns-b.cpp): demonstrates use of the BFVrnsB scheme for basic homomorphic encryption
- [demo-evalatindex.cpp](src/pke/demo/demo-evalatindex.cpp): demonstrates use of EvalAtIndex for different schemes and cyclotomic rings
- [demo-json.cpp](src/pke/demo/demo-json.cpp): demonstrates use of PALISADE encryption and decryption of vectors of integers, also illustrating the use of serializing information to text files
- [demo-linregress.cpp](src/pke/demo/demo-linregress.cpp): demonstrates performing linear regression on encrypted matrices
- [demo-packing.cpp](src/pke/demo/demo-packing.cpp): demonstrates inner product operations
- [demo-pke.cpp](src/pke/demo/demo-pke.cpp): demonstrates use of encryption across several schemes
- [demo-pre.cpp](src/pke/demo/demo-pre.cpp): demonstrates use of proxy re-encryption across several schemes
- [demo-she.cpp](src/pke/demo/demo-she.cpp): demonstrates SHE operations using several schemes
- [demo-timing.cpp](src/pke/demo/demo-timing.cpp): demonstrate the use of the TimingInfo feature of the CryptoContext
- [palisade.cpp](src/demo/pre/palisade.cpp): a program designed to demonstrate the key generation, evaluation key generation, encryption, re-encryption, and decryption functionality of the library. If you run the command without any parameters it generates a help message. Results are serialized into flat files, and are deserialized when needed. The program will read the crypto context parms file, or will read a file that you provide. Note you can also tell the program to figure out what crypto parameters to use based on whatever serialized object you are reading at the start of your program.
- [palisadedemo.sh](src/pke/demo/palisadedemo.sh): a shell script that runs the palisade demo
- [run-bfvrns.cpp](src/pke/demo/run-bfvrns.cpp): demonstrates benchmarking of RNS operations for BFVrns
- [run-bfvrns-b.cpp](src/pke/demo/run-bfvrns-b.cpp): demonstrates benchmarking of RNS operations for BFVrnsB
