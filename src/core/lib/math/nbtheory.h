/**
 * @file nbtheory.h This code provides number theory utilities.
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
 /*
 * 	NBTHEORY is set set of functions that will be used to calculate following:
 *		- If two numbers are coprime.
 *		- GCD of two numbers 
 *		- If number i Prime
 *		- witnesss function to test if number is prime
 *		- Roots of unit for provided cyclotomic integer
 *		- Eulers Totient function phin(n)
 *		- Generator algorithm
 */

#ifndef LBCRYPTO_MATH_NBTHEORY_H
#define LBCRYPTO_MATH_NBTHEORY_H

#include <vector>
#include <set>
#include <string>
#include <random>
#include "../utils/inttypes.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {


	/**
	 * Finds roots of unity for given input.  Assumes the the input is a power of two. 
	 *
	 * @param m as number which is cyclotomic(in format of int).
	 * @param &modulo which is used to find generator.
	 * 
	 * @return a root of unity.  	  
	 */
	template<typename IntType>
	IntType RootOfUnity(usint m, const IntType &modulo);

	/**
	 * Finds roots of unity for given input.  Assumes the the input cyclotomicorder is a power of two. 
	 *
	 * @param m as number which is cyclotomic(in format of int).
	 * @param moduli vector of modulus
	 * 
	 * @returns a vector of roots of unity corresponding to each modulus.  	  
	 */
	template<typename IntType>
	std::vector<IntType> RootsOfUnity(usint m, const std::vector<IntType> moduli);

	/**
	 * Method to reverse bits of num and return an unsigned int, for all bits up to an including the designated most significant bit.
	 *
	 * @param input an unsigned int
	 * @param msb the most significant bit.  All larger bits are disregarded.
	 * 
	 * @return an unsigned integer that represents the reversed bits.	  
	 */
	usint ReverseBits(usint input, usint msb);

	/**
	 * Get MSB of an unsigned 64 bit integer.
	 *
	 * @param x the input to find MSB of.
	 * 
	 * @return the index of the MSB bit location.	  
	 */
	inline usint GetMSB64(uint64_t x) {
		if (x == 0) return 0;

		// hardware instructions for finding MSB are used are used;
#if defined(_MSC_VER)
		// a wrapper for VC++
		unsigned long msb;
		_BitScanReverse64(&msb, x);
		return msb + 1;
#else
		// a wrapper for GCC
		return  64 - (sizeof(unsigned long) == 8 ? __builtin_clzl(x) : __builtin_clzll(x));
#endif
	}

	/**
	 * Return greatest common divisor of two big binary integers.
	 *
	 * @param a one integer to find greatest common divisor of.
	 * @param b another integer to find greatest common divisor of.
	 * 
	 * @return the greatest common divisor.	  
	 */
	template<typename IntType>
	IntType GreatestCommonDivisor(const IntType& a, const IntType& b);

	/**
	 * Perform the MillerRabin primality test on an IntType.
	 * This approach to primality testing is iterative and randomized.  
	 * It returns false if evidence of non-primality is found, and true if no evidence is found after multiple rounds of testing.  
	 * The const parameter PRIMALITY_NO_OF_ITERATIONS determines how many rounds are used ( set in nbtheory.h).
	 *
	 * @param p the candidate prime to test.
	 * @param niter Number of iterations used for primality
	 *              testing (default = 100.
	 * 
	 * @return false if evidence of non-primality is found.  True is no evidence of non-primality is found.	
	 */
	template<typename IntType>
	bool MillerRabinPrimalityTest(const IntType& p, const usint niter = 100);

	/**
	 * Perform the PollardRho factorization of a IntType.
	 * Returns IntType::ONE if no factorization is found.
	 *
	 * @param n the value to perform a factorization on.
	 * @return a factor of n, and IntType::ONE if no other factor is found.
	 */
	template<typename IntType>
	const IntType PollardRhoFactorization(const IntType &n);

	/**
	 * Recursively factorizes to find the distinct primefactors of a number.
	 * @param &n the value to factorize. [note the value of n is destroyed]
	 * @param &primeFactors set of factors found [must begin cleared]
	 Side effects: n is destroyed.  
	 */
	template<typename IntType>
	void PrimeFactorize( IntType n, std::set<IntType> &primeFactors);

	/**
	* Finds the first prime that satisfies q = 1 mod m
	*
	* @param nBits the number of bits needed to be in q.
	* @param m the the ring parameter.
	*
	* @return the next prime modulus.
	*/
	template<typename IntType>
	IntType FirstPrime(usint nBits, usint m);

	/**
	* Finds the next prime that satisfies q = 1 mod m
	*
	* @param &q is the prime number to start from (the number itself is not included)
	*
	* @return the next prime modulus.
	*/
	template<typename IntType>
	IntType NextPrime(const IntType &q, usint cyclotomicOrder);

	/**
	 * Multiplicative inverse for primitive unsigned integer data types
	 *
	 * @param a the number we need the inverse of.
	 * @param b the modulus we are working with.
	 *
	 * @return the multiplicative inverse  
	 */
	usint ModInverse(usint a, usint b);

	/**
	* Returns the next power of 2 that is greater than the input number.
	*
	* @param &n is the input value for which next power of 2 needs to be computed.
	* @return Next power of 2 that is greater or equal to n.
	*/
	template<typename IntType>
	IntType NextPowerOfTwo(const IntType &n);

	/**
	* Returns the totient value φ(n) of a number n.
	*
	* @param &n the input number.
	* @return φ(n) which is the number of integers m coprime to n such that 1 ≤ m ≤ n.
	*/
	uint64_t GetTotient(const uint64_t n);


	/**
	* Returns the list of coprimes to number n in ascending order.
	*
	* @param &n the input number.
	* @return vector of mi's such that 1 ≤ mi ≤ n and gcd(mi,n)==1.
	*/
	template<typename IntType>
	std::vector<IntType> GetTotientList(const IntType &n);

	/**
	* Returns the polynomial modulus.
	*
	* @param &dividend the input dividend polynomial with degree >= degree of divisor.
	* @param &divisor the input divisor polynomial with degree <= degree of dividend and divisor is a monic polynomial.
	* @param &modulus the working modulus.
	* @return resultant polynomial vector s.t. return = divident mod (divisor,modulus).
	*/
	template<typename IntVector, typename IntType>
	IntVector PolyMod(const IntVector &dividend, const IntVector &divisor, const IntType &modulus);

	/**
	* Returns the polynomial multiplication of the input operands.
	*
	* @param &a the input polynomial.
	* @param &b the input polynomial.
	* a and b must have the same modulus.
	* @return resultant polynomial s.t. return = a*b and coefficinet ci = ci%modulus.
	*/
	template<typename IntVector>
	IntVector PolynomialMultiplication(const IntVector &a, const IntVector &b);

	/**
	* Returns the m-th cyclotomic polynomial.
	* Added as a wrapper to GetCyclotomicPolynomialRecursive
	* @param &m the input cyclotomic order.
	* @param &modulus is the working modulus.
	* @return resultant m-th cyclotomic polynomial with coefficients in modulus.
	*/
	template<typename IntVector, typename IntType>
	IntVector GetCyclotomicPolynomial(usint m, const IntType &modulus);

	/**
	* Returns the m-th cyclotomic polynomial.
	*
	* @param &m the input cyclotomic order.
	* @return resultant m-th cyclotomic polynomial.
	*/
	std::vector<int> GetCyclotomicPolynomialRecursive(usint m);

	/**
	* Returns the remainder after polynomial division of dividend with divisor = x-a.
	* Uses synthetic division algorithm.
	* @param &dividend is the input polynomial dividend in lower to higher coefficient form.
	* @param &a is the integer in divisor[x-a].
	* @return remainder after division with x-a.
	*/
	template<typename IntVector, typename IntType>
	IntType SyntheticRemainder(const IntVector &dividend, const IntType &a, const IntType &modulus);

	/**
	* Returns the remainder vector after polynomial division of dividend with divisor = x-aList[i].
	* Uses synthetic division algorithm.
	* @param &dividend is the input polynomial dividend in lower to higher coefficient form.
	* @param &aList is the integer vector for divisor[x-aList[i]].
	* @return remainder vector after division with x-aList[i].
	*/
	template<typename IntVector, typename IntType>
	IntVector SyntheticPolyRemainder(const IntVector &dividend, const IntVector &aList, const IntType &modulus);

	/**
	* Returns the polynomial after raising it by exponent = power.
	* Returns input^power.Uses Frobenius mapping.
	* @param &input is operand polynomial which needs to be exponentiated.
	* @param &power is the exponent.
	* @return exponentiated polynomial.
	*/
	template<typename IntVector, typename IntType>
	IntVector PolynomialPower(const IntVector &input, usint power);

	/**
	* Returns the quotient after polynomial division of dividend with divisor = x-a.
	* Uses synthetic division algorithm.
	* @param &dividend is the input polynomial dividend in lower to higher coefficient form.
	* @param &a is the integer in divisor[x-a].
	* @return quotient after division with x-a.
	*/
	template<typename IntVector, typename IntType>
	IntVector SyntheticPolynomialDivision(const IntVector &dividend, const IntType &a, const IntType &modulus);

	/**
	* Checkes if g is a generator for any cyclic group with modulus q (non-prime moduli are supported); currently q up to 64 bits only are supported
	* @param &g is candidate generator
	* @param &q is the modulus ( 2, 4, p^k, or 2*p^k where p^k is a power of an odd prime number )
	* @return true if g is a generator
	*/
	template<typename IntType>
	bool IsGenerator(const IntType& g, const IntType& q);

	/**
	* Finds a generator for any cyclic group with modulus q (non-prime moduli are supported); currently q up to 64 bits only are supported
	* @param &q is the modulus ( 2, 4, p^k, or 2*p^k where p^k is a power of an odd prime number )
	* @return true if g is a generator
	*/
	template<typename IntType>
	IntType FindGeneratorCyclic(const IntType& q);


	/**
	* Pre-computes the mu factor that is used in Barrett modulo reduction
	* @param &q is the modulus
	* @return the value of mu
	*/
	template<typename IntType>
	IntType ComputeMu(const IntType& q);
	

} // namespace lbcrypto ends

#endif
