PALISADE Lattice Cryptography Library
=====================================

[License Information](License.md)

[Contact Information](Contact.md)

[Library Contributors](Contributors.md)

[Library Wiki with documentation](https://git.njit.edu/palisade/palisade-student-edition/wikis/home)

This is a software library for general lattice crypto.  We implement this library in the following multiple layers:

* Math operations layer to support low-level modulus arithmetic.  This layer is implemented to be portable to multiple hardware computation substrates.
* Lattice operations layer to support lattice operations and ring algebra.  This layer makes calls to the math operations layer.
* Crypto layer to contain multiple implementations of lattice encryption schemes, including PRE schemes, leveled homomorphic encryption schemes, lattice trapdoors and lattice signature schemes.

The library includes unit tests and several sample application demos.

The library is implemented in C++11.

We build and run the library on Windows, Linux and Mac OSX environments.

We require a version of C++ compiler that supports the C++11 extensions. Recent vintages of GCC or Clang should work fine. We have removed support for Visual Studio and suggest that it not be used. We also use bison and flex in some parts of the library.

To check if your environment will allow you to build and use PALISADE, run the configure.sh script in the root directory of the library software distribution.

You build the entirety of PALISADE by running make. There are various command line arguments that can be passed to make to vary the details of what is made and where:

* BINDIR=directory builds the library with a different target directory
* BACKEND=n builds the library with MATHBACKEND set to n (you may want to touch the src/core/lib/math/backend.h file to force the build)
* COVERAGE=any builds the library with coverage testing enabled
* OMP=n builds the library with OMP flag set to n; currently n can be any value; turns on loop parallelization for the Matrix class in src/core/lib/math; additional levels of parallelization will be added in the future.