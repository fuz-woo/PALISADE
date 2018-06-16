6/15/2018: PALISADE v1.2 is released

PALISADE v1.2 provides several important advancements and improvements to the library.  Most notably, we provide:

* The Bajard-Eynard-Hasan-Zucca RNS variant of the BFV scheme is added to the library
* The implementation of the Halevi-Polyakov-Shoup RNS variant of the BFV scheme is significantly improved
* Large multiplicative depths (up to 100 and higher) for both RNS variants are now supported.
* Several low-level optimizations, e.g., in Number Theoretic Transform and NTL multiprecision math backend, are implemented.
* Multiple improvements in plaintext encodings.
* Software engineering improvements: extended batteries of unit tests, cleaner design of the matrix class, better CryptoContext wrapper, etc.
* Fixes for bugs which have been brought to our attention.

1/29/2018: PALISADE v1.1.1 is released

PALISADE v1.1.1 includes bug fixes and minor optimizations:

* Fixes minor bugs in NativeInteger and multiprecision backends (BigInteger)
* Deals properly with a low-probability rounding error in BFVrns
* Fixes a compilation error on some CentOS systems
* Improves the performance of NativeInteger
* Fixes a couple of other minor bugs

12/29/2017: PALISADE v1.1 is released

PALISADE v1.1  includes the following new capabilities, library enhancements, and optimizations:

* New efficient homomorphic scheme: BFVrns
* Newly supported homomorphic operations for multi-depth computations
* Type checking, type safety, and improved error handling
* Faster/more capable Gaussian sampling
* NTL integration as a new option for the multiprecision arithmetic backend
* And more...

07/15/2017: PALISADE v1.0 is released
