/**
 * @file backend.h This file contains the functionality to switch between math backends
 *
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef LBCRYPTO_MATH_BACKEND_H
#define LBCRYPTO_MATH_BACKEND_H

#include "version.h"

#include "utils/inttypes.h"
#include "utils/parallel.h"

 
// use of MS VC is not permitted because of various incompatibilities
#ifdef _MSC_VER
#error "MSVC COMPILER IS NOT SUPPORTED"
#endif

////////// definitions for native integer and native vector
#include "native_int/binint.h"
#include "native_int/binvect.h"
#include <initializer_list>

typedef native_int::NativeInteger<uint64_t>			NativeInteger;
typedef native_int::NativeVector<NativeInteger>		NativeVector;
typedef unsigned __int128 DoubleNativeInteger;

/*! Define the underlying default math implementation being used by defining MATHBACKEND */

// Each math backend is defined in its own namespace, and can be used at any time by referencing
// the objects in its namespace

// Selecting a math backend by defining MATHBACKEND means defining which underlying implementation
// is the default BigInteger and BigVector

// note that we #define how many bits the underlying integer can store as a guide for users of the backends

// MATHBACKEND 2
// 		Uses cpu_int:: definition as default
//		Implemented as a vector of integers
//		Configurable maximum bit length and type of underlying integer

// MATHBACKEND 4
// 		This uses exp_int:: definition as default
// 		This backend supports arbitrary bitwidths; no memory pool is used; can grow up to RAM limitation
//		Configurable type of underlying integer (either 32 or 64 bit)

// passes all tests with UBINT_32
// fails tests with UBINT_64
// there is a bug in the way modulus is computed. do not use.

// MATHBACKEND 6
//		This uses gmp_int:: definition as default
// 		GMP 6.1.2 / NTL 10.3.0 backend

//To select backend, please UNCOMMENT the appropriate line rather than changing the number on the
//uncommented line (and breaking the documentation of the line)

#ifndef MATHBACKEND
//#define MATHBACKEND 2
//#define MATHBACKEND 4
#define MATHBACKEND 6
#endif

#if MATHBACKEND != 2 && MATHBACKEND != 4 && MATHBACKEND != 6
#error "MATHBACKEND value is not valid"
#endif

////////// cpu_int code
typedef uint32_t integral_dtype;

	/** Define the mapping for BigInteger
	    1500 is the maximum bit width supported by BigIntegeregers, large enough for most use cases
		The bitwidth can be decreased to the least value still supporting BigInteger operations for a specific application -
		to achieve smaller runtimes
	**/

#ifndef BigIntegerBitLength
#define BigIntegerBitLength 1500 //for documentation on tests
#endif

#if BigIntegerBitLength < 600
#error "BigIntegerBitLength is too small"
#endif

inline const std::string& GetMathBackendParameters() {
	static std::string id = "Backend " + std::to_string(MATHBACKEND) +
			(MATHBACKEND == 2 ? " internal int size " + std::to_string(sizeof(integral_dtype)*8) + " BitLength " + std::to_string(BigIntegerBitLength) : "");
	return id;
}

#include "cpu_int/binint.h"
#include "cpu_int/binvect.h"
static_assert(cpu_int::DataTypeChecker<integral_dtype>::value,"Data type provided is not supported in BigInteger");

////////// for exp_int, decide if you want 32 bit or 64 bit underlying integers in the implementation
#define UBINT_32
//#define UBINT_64

#ifdef UBINT_32
#define MATH_UBBITS	32
typedef uint32_t expdtype;
#undef UBINT_64 //cant have both accidentally
#endif

#ifdef UBINT_64
#define MATH_UBBITS	64
typedef uint64_t expdtype;
#undef UBINT_32 //cant have both accidentally
#endif

#include "exp_int/ubint.h" //dynamically sized  unsigned big integers or ubints
#include "exp_int/mubintvec.h" //rings of ubints

namespace exp_int {
/** Define the mapping for ExpBigInteger (experimental) */
typedef ubint<expdtype> xubint;

/** Define the mapping for modulo Big Integer Vector */
typedef mubintvec<xubint> xmubintvec;
}

#include "gmp_int/gmpint.h" //experimental gmp unsigned big ints
#include "gmp_int/mgmpintvec.h" //rings of such

namespace gmp_int {
typedef NTL::myZZ ubint;
}

// typedefs for the known math backends
using M2Integer = cpu_int::BigInteger<integral_dtype,BigIntegerBitLength>;
using M2Vector = cpu_int::BigVectorImpl<M2Integer>;
using M4Integer = exp_int::xubint;
using M4Vector = exp_int::xmubintvec;
using M6Integer = NTL::myZZ;
using M6Vector = NTL::myVecP<M6Integer>;

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#if MATHBACKEND == 2

	using BigInteger = M2Integer;
	using BigVector = M2Vector;

#endif

#if MATHBACKEND == 4

#ifdef UBINT_64
	#error MATHBACKEND 4 with UBINT_64 currently does not work do not use.
#endif

	using BigInteger = M4Integer;
	using BigVector = M4Vector;

#endif

#if MATHBACKEND == 6

	using BigInteger = M6Integer;
	using BigVector = M6Vector;

#endif
}

#endif

// COMMON TESTING DEFINITIONS
extern bool TestB2;
extern bool TestB4;
extern bool TestB6;
extern bool TestNative;

// macros for unit testing
#define RUN_BIG_BACKENDS_INT(FUNCTION, MESSAGE) { \
	if( TestB2 ) { using T = M2Integer; FUNCTION<T>("BE2 " MESSAGE); } \
	if( TestB4 ) { using T = M4Integer; FUNCTION<T>("BE4 " MESSAGE); } \
	if( TestB6 ) { using T = M6Integer; FUNCTION<T>("BE6 " MESSAGE); } \
}

#define RUN_ALL_BACKENDS_INT(FUNCTION, MESSAGE) { \
	RUN_BIG_BACKENDS_INT(FUNCTION,MESSAGE) \
	if( TestNative ) { using T = NativeInteger; FUNCTION<T>("Native " MESSAGE); } \
}

#define RUN_BIG_BACKENDS(FUNCTION, MESSAGE) { \
	if( TestB2 ) { using V = M2Vector; FUNCTION<V>("BE2 " MESSAGE); } \
	if( TestB4 ) { using V = M4Vector; FUNCTION<V>("BE4 " MESSAGE); } \
	if( TestB6 ) { using V = M6Vector; FUNCTION<V>("BE6 " MESSAGE); } \
}

#define RUN_ALL_BACKENDS(FUNCTION, MESSAGE) { \
	RUN_BIG_BACKENDS(FUNCTION,MESSAGE) \
	if( TestNative ) { using V = NativeVector; FUNCTION<V>("Native " MESSAGE); } \
}


