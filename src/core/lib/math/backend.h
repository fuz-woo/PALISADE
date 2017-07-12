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

// MATHBACKEND 6
//		This uses gmp_int:: definition as default
// 		GMP 6.1.2 / NTL 10.3.0 backend

// MATHBACKEND 7
// 		This uses native_int:: as the default
// This backend provides a maximum size of 64 bits

//To select backend, please UNCOMMENT the appropriate line rather than changing the number on the
//uncommented line

#define MATHBACKEND 2
//#define MATHBACKEND 4
//#define MATHBACKEND 6 
//#define MATHBACKEND 7

////////// cpu_int code
#include "cpu_int/binint.cpp"
#include "cpu_int/binvect.cpp"
typedef uint32_t integral_dtype;
static_assert(cpu_int::DataTypeChecker<integral_dtype>::value,"Data type provided is not supported in BigInteger");

	/** Define the mapping for BigInteger
	    1500 is the maximum bit width supported by BigIntegeregers, large enough for most use cases
		The bitwidth can be decreased to the least value still supporting BBI multiplications for a specific application -
		to achieve smaller runtimes
	**/
#define BigIntegerBitLength 1500 //for documentation on tests

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
#include "exp_int/ubintvec.h" //vectors of experimental ubints
#include "exp_int/mubintvec.h" //rings of ubints

namespace exp_int {
/** Define the mapping for ExpBigIntegereger (experimental) */
typedef ubint<expdtype> xubint;

/** Define the mapping for Big Integer Vector */
typedef ubintvec<xubint> xubintvec;

/** Define the mapping for modulo Big Integer Vector */
typedef mubintvec<xubint> xmubintvec;
}

#if defined(__linux__) && MATHBACKEND == 6
////////// for gmp int
#include "gmp_int/gmpint.h" //experimental gmp unsigned big ints
#include "gmp_int/mgmpint.h" //experimental gmp modulo unsigned big ints
#include "gmp_int/gmpintvec.h" //vectors of such
#include "gmp_int/mgmpintvec.h" //rings of such

namespace gmp_int {
typedef NTL::myZZ ubint;
typedef NTL::myZZ_p mubint;
}
#endif

////////// for native int
#include "native_int/binint.h"
#include <initializer_list>
#define MATH_NATIVEBITS	64

namespace native_int {
typedef NativeInteger<uint64_t> BigInteger;
typedef cpu_int::BigVectorImpl<NativeInteger<uint64_t>> BigVector;
}

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#if MATHBACKEND == 2

	typedef cpu_int::BigInteger<integral_dtype,BigIntegerBitLength> BigInteger;
	typedef cpu_int::BigVectorImpl<BigInteger> BigVector;

#define MATH_DEFBITS BigIntegerBitLength

#endif

#if MATHBACKEND == 4
        #ifdef UBINT_64
	  #error MATHBACKEND 4 with UBINT_64 currently does not work do not use.
	#endif
	typedef exp_int::xubint BigInteger;
	typedef exp_int::xmubintvec BigVector;

#define MATH_DEFBITS 0

#endif

#if defined(__linux__)&& MATHBACKEND == 6

	/** Define the mapping for BigInteger */
	typedef NTL::myZZ BigInteger;
	
	/** Define the mapping for BigVector */
        typedef NTL::myVecP<NTL::myZZ_p> BigVector;

#define MATH_DEFBITS 0

#endif

#if MATHBACKEND == 7

	typedef native_int::BigInteger BigInteger;
	typedef native_int::BigVector BigVector;

#define MATH_DEFBITS MATH_NATIVEBITS
#endif

	template<typename IntType> class ILParamsImpl;
	template<typename ModType, typename IntType, typename VecType, typename ParmType> class PolyImpl;

	typedef ILParamsImpl<BigInteger> ILParams;
	typedef PolyImpl<BigInteger, BigInteger, BigVector, ILParams> Poly;

	typedef ILParamsImpl<native_int::BigInteger> ILNativeParams;

} // namespace lbcrypto ends

#endif
