/**
 * @file utilities.h This file contains the utility function functionality.
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

#ifndef LBCRYPTO_UTILS_UTILITIES_H
#define LBCRYPTO_UTILS_UTILITIES_H

#include "../math/backend.h"
#include "../math/nbtheory.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * Zero Padding of Elements. 
 * Adds zeros to form a polynomial of length 2n  (corresponding to cyclotomic order m = 2n). 
 * It is used by the forward transform of ChineseRemainderTransform (a modified version of ZeroPadd will be used for the non-power-of-2 case).
 *
 * @param &InputPoly is the element to perform the transform on.
 * @param target_order is the intended target ordering.
 * @return is the output of the zero padding.	  	  
 */
template<typename V>
V ZeroPadForward(const V &InputPoly, usint target_order);

/**
 * Zero Pad Inverse of Elements.
 * Adds alternating zeroes to form a polynomial of length of length 2n (corresponding to cyclotomic order m = 2n). 
 * It is used by the inverse transform of ChineseRemainderTransform (a modified version of ZeroPadInverse will be used for the non-power-of-2 case).
 *
 * @param &InputPoly is the element to perform the transform on.
 * @param target_order is the intended target ordering.
 * @return is the output of the zero padding.	  	  
 */
template<typename V>
V ZeroPadInverse(const V &InputPoly, usint target_order);

/**
 * Determines if a number is a power of 2.
 *
 * @param Input to test if it is a power of 2.
 * @return is true if the unsigned int is a power of 2.	  	  
 */
bool IsPowerOfTwo(usint Input);

/**
 * Auxiliary function to replace a specific character "in" with another character "out"
 *
 * @param str string where in which characters are replaced
 * @param in character being replaced
 * @param out character to be replaced with
 * @return the modified string.	  	  
 */
// auxiliary function to replace a specific character "in" with another character "out"
std::string replaceChar(std::string str, char in, char out);


// Lazy Reduction functions: 64-bit multiplier and 128-bit Barrett reducer
// Originally proposed for BFVrnsB
/**
 * check if adding two 64-bit number can cause overflow
 * @param a: operand 1
 * @param b: operand 2
 * @return 1 if overflow occurs, 0 otherwise
 */
inline uint32_t IsAdditionOverflow(uint64_t a, uint64_t b)
{
	a += b;
	if (a < b )
		return 1;
	else
		return 0;
}

/**
 * add two 64-bit number with carry out, c = a + b
 * @param a: operand 1
 * @param b: operand 2
 * @param c: c = a + b
 * @return 1 if overflow occurs, 0 otherwise
 */

inline uint32_t AdditionWithCarryOut(uint64_t a, uint64_t b, uint64_t &c)
{
	a += b;
	c = a;
	if (a < b )
		return 1;
	else
		return 0;
}

/**
 * 64-bit uint multiplier, result is 128-bit
 * @param a: operand 1
 * @param b: operand 2
 * @return result: 128-bit result = a * b
 */
inline DoubleNativeInteger Mul128(uint64_t a, uint64_t b) {
	DoubleNativeInteger result = (DoubleNativeInteger)a * (DoubleNativeInteger)b;
    return result;
}

/**
 * Barrett reduction of 128-bit integer modulo 64-bit integer. Source: Menezes, Alfred; Oorschot, Paul; Vanstone, Scott. Handbook of Applied Cryptography, Section 14.3.3.
 * @param a: operand (128-bit)
 * @param m: modulus (64-bit)
 * @param mu: 2^128/modulus (128-bit)
 * @return result: 64-bit result = a mod m
 */
inline uint64_t BarrettUint128ModUint64(DoubleNativeInteger a, uint64_t modulus, DoubleNativeInteger mu)
{
	// (a * mu)/2^128 // we need the upper 128-bit of (256-bit product)
	uint64_t result = 0, a_lo = 0, a_hi = 0, mu_lo = 0, mu_hi = 0, left_hi = 0, middle_lo = 0, middle_hi = 0, tmp1 = 0, tmp2 = 0, carry = 0;
	DoubleNativeInteger middle = 0;

	a_lo = (uint64_t)a;
	a_hi = a >> 64;
	mu_lo = (uint64_t)mu;
	mu_hi = mu >> 64;

	left_hi = (Mul128( a_lo, mu_lo )) >> 64; // mul left parts, discard lower word

	middle =  Mul128( a_lo, mu_hi ); // mul middle first
	middle_lo = (uint64_t)middle;
	middle_hi = middle >> 64;

	carry = AdditionWithCarryOut(middle_lo, left_hi, tmp1); // accumulate and check carry

	tmp2 = middle_hi + carry; // accumulate

	middle = Mul128( a_hi, mu_lo ); // mul middle second
	middle_lo = (uint64_t)middle;
	middle_hi = middle >> 64;

	carry = IsAdditionOverflow(middle_lo, tmp1); // check carry

	left_hi = middle_hi + carry; // accumulate

	tmp1 = a_hi*mu_hi + tmp2 + left_hi; // now we have the lower word of (a * mu)/2^128, no need for higher word

	// subtract lower words only, higher words should be the same
	result = a_lo - tmp1 * modulus;

	while (result >= modulus)
		result -= modulus;

	return result;
}

/**
 * Only meant for debugging [not necessarily efficient]
 * @param a: 128-bit integer to convert
 * @return std:string of a
 */
inline std::string Uint128ToString(DoubleNativeInteger &a) noexcept
{
	DoubleNativeInteger tmp = a;
	char buffer[128];
	memset(buffer, 0, sizeof(buffer));

	std::string out = "";

	char *d = std::end(buffer);
	do {
		--d;
		*d = "0123456789"[tmp % 10];
		tmp /= 10;
	} while (tmp != 0);

	for (size_t i = 0; i < sizeof(buffer); i++)
	{
		if (buffer[i] != '\0')
			out += buffer[i];
	}

	return out;
}

} // namespace lbcrypto ends

#endif
