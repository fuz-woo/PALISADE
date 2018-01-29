/**
 * @file nbtheory.cpp This code provides number theory utilities.
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

#include "nbtheory.h"
#include "distributiongenerator.h"

#include "time.h"
#include <chrono>

#include "../utils/debug.h"


#define _USE_MATH_DEFINES 
#include <cmath>
#include <time.h>
#include <sstream>

namespace lbcrypto {


	template BigInteger RootOfUnity<BigInteger>(usint m, const BigInteger& modulo);
	template std::vector<BigInteger> RootsOfUnity(usint m, const std::vector<BigInteger> moduli);
	template BigInteger GreatestCommonDivisor(const BigInteger& a, const BigInteger& b);
	template bool MillerRabinPrimalityTest(const BigInteger& p, const usint niter);
	template const BigInteger PollardRhoFactorization(const BigInteger &n);
	template void PrimeFactorize(BigInteger n, std::set<BigInteger> &primeFactors);
	template BigInteger FirstPrime(usint nBits, usint m);
	template BigInteger NextPrime(const BigInteger &q, usint cyclotomicOrder);
	template BigVector PolyMod(const BigVector &dividend, const BigVector &divisor, const BigInteger &modulus);
	template BigVector PolynomialMultiplication(const BigVector &a, const BigVector &b);
	template BigVector GetCyclotomicPolynomial(usint m, const BigInteger &modulus);
	template BigInteger SyntheticRemainder(const BigVector &dividend, const BigInteger &a, const BigInteger &modulus);
	template BigVector SyntheticPolyRemainder(const BigVector &dividend, const BigVector &aList, const BigInteger &modulus);
	template BigVector PolynomialPower<BigVector, BigInteger>(const BigVector &input, usint power);
	template BigVector SyntheticPolynomialDivision(const BigVector &dividend, const BigInteger &a, const BigInteger &modulus);
	template BigInteger FindGeneratorCyclic(const BigInteger& modulo);
	template bool IsGenerator(const BigInteger& g, const BigInteger& modulo);
	template BigInteger ComputeMu(const BigInteger& q);

	template std::vector<usint> GetTotientList(const usint &n);

	template NativeInteger RootOfUnity<NativeInteger>(usint m, const NativeInteger& modulo);
	template std::vector<NativeInteger> RootsOfUnity(usint m, const std::vector<NativeInteger> moduli);
	template NativeInteger GreatestCommonDivisor(const NativeInteger& a, const NativeInteger& b);
	template bool MillerRabinPrimalityTest(const NativeInteger& p, const usint niter);
	template const NativeInteger PollardRhoFactorization(const NativeInteger &n);
	template void PrimeFactorize(NativeInteger n, std::set<NativeInteger> &primeFactors);
	template NativeInteger FirstPrime(usint nBits, usint m);
	template NativeInteger NextPrime(const NativeInteger &q, usint cyclotomicOrder);
	template NativeVector PolyMod(const NativeVector &dividend, const NativeVector &divisor, const NativeInteger &modulus);
	template NativeVector PolynomialMultiplication(const NativeVector &a, const NativeVector &b);
	template NativeVector GetCyclotomicPolynomial(usint m, const NativeInteger &modulus);
	template NativeInteger SyntheticRemainder(const NativeVector &dividend, const NativeInteger &a, const NativeInteger &modulus);
	template NativeVector SyntheticPolyRemainder(const NativeVector &dividend, const NativeVector &aList, const NativeInteger &modulus);
	template NativeVector PolynomialPower<NativeVector, NativeInteger>(const NativeVector &input, usint power);
	template NativeVector SyntheticPolynomialDivision(const NativeVector &dividend, const NativeInteger &a, const NativeInteger &modulus);
	template NativeInteger FindGeneratorCyclic(const NativeInteger& modulo);
	template bool IsGenerator(const NativeInteger& g, const NativeInteger& modulo);

	template NativeInteger ComputeMu(const NativeInteger& q);
#if MATHBACKEND != 2
  //TODO: figure out why this needs to be here at all for BE = 4,6
  template cpu_int::BigInteger<integral_dtype,BigIntegerBitLength> ComputeMu(const cpu_int::BigInteger<integral_dtype,BigIntegerBitLength>& q);
#endif
  /*
		Generates a random number between 0 and n.
		Input: BigInteger n.
		Output: Randomly generated BigInteger between 0 and n.
	*/
	template<typename IntType>
	static IntType RNG(const IntType& modulus)
	{
		// static parameters for the 32-bit unsigned integers used for multiprecision random number generation
		static const usint chunk_min = 0;
		static const usint chunk_width = std::numeric_limits<uint32_t>::digits;
		static const usint chunk_max = std::numeric_limits<uint32_t>::max();

		static std::uniform_int_distribution<uint32_t> distribution(chunk_min, chunk_max);

		// Update values that depend on modulus.
		usint modulusWidth = modulus.GetMSB();
		// Get the number of chunks in the modulus
		// 1 is subtracted to make sure the last chunk is fully used by the modulus
		usint chunksPerValue = (modulusWidth - 1) / chunk_width;

		// result is initialized to 0
		IntType result;

		//temp is used for intermediate multiprecision computations
		IntType temp;

		//stores current random number generated by built-in C++ 11 uniform generator (used for 32-bit unsigned integers)
		uint32_t value;

		do {

			result = 0;

			// Generate random uint32_t "limbs" of the BigInteger
			for (usint i = 0; i < chunksPerValue; i++) {
				//Generate an unsigned long integer
				value = distribution(PseudoRandomNumberGenerator::GetPRNG());
				// converts value into IntType
				temp = value;
				//Move it to the appropriate chunk of the big integer
				temp <<= i*chunk_width;
				//Add it to the current big integer storing the result
				result += temp;
			}

			//work with the remainder - after all 32-bit chunks were processed
			temp = modulus >> chunksPerValue*chunk_width;

			// Generate a uniform number for the remainder
			// If not 1, i.e., the modulus is either 1 or a power of 2*CHUNK_WIDTH
			if (temp.GetMSB() != 1)
			{
				uint32_t bound = temp.ConvertToInt();

				// default generator for the most significant chunk of the multiprecision number
				std::uniform_int_distribution<uint32_t>  distribution2 = std::uniform_int_distribution<uint32_t>(chunk_min, bound);

				value = distribution2(PseudoRandomNumberGenerator::GetPRNG());
				// converts value into IntType
				temp = value;
				//Move it to the appropriate chunk of the big integer
				temp <<= chunksPerValue*chunk_width;
				//Add it to the current big integer storing the result
				result += temp;

			}

		} while (result > modulus); // deals with the rare scenario when the bits in the most significant chunk are the same
		// and the bits in the following chunk of the result are larger than in the modulus

		return result;
	}

	//native NTL version
	NTL::myZZ RNG(const NTL::myZZ& modulus)
	{
		bool dbg_flag = false;
		DEBUG("in NTL RNG");
		return RandomBnd(modulus);

	}

	/*
		A witness function used for the Miller-Rabin Primality test.
		Inputs: a is a randomly generated witness between 2 and p-1,
				p is the number to be tested for primality,
				s and d satisfy p-1 = ((2^s) * d), d is odd.
		Output: true if p is composite,
				false if p is likely prime
	*/
	template<typename IntType>
	static bool WitnessFunction(const IntType& a, const IntType& d, usint s, const IntType& p)
	{
		bool dbg_flag = false;
		DEBUG("calling modexp a " << a << " d " << d << " p " << p);
		IntType mod = a.ModExp(d, p);
		DEBUG("mod " << mod);
		bool prevMod = false;
		for (usint i = 1; i < s + 1; i++) {
			DEBUG("wf " << i);
			if (mod != IntType(1) && mod != p - IntType(1))
				prevMod = true;
			else
				prevMod = false;
			mod = mod.ModMul(mod, p);
			if (mod == IntType(1) && prevMod) return true;
		}
		return (mod != IntType(1));
	}

	/*
		A helper function to RootOfUnity function. This finds a generator for a given prime q.
		Input: BigInteger q which is a prime.
		Output: A generator of prime q
	*/
    template<typename IntType>
    static IntType FindGenerator(const IntType& q)
    {
            bool dbg_flag = false;
            std::set<IntType> primeFactors;
            DEBUG("FindGenerator(" << q << "),calling PrimeFactorize");

            IntType qm1 = q - IntType(1);
            IntType qm2 = q - IntType(2);
            PrimeFactorize<IntType>(qm1, primeFactors);
            DEBUG("prime factors of " << qm1);
            for( auto& v : primeFactors ) DEBUG(v << " ");

            bool generatorFound = false;
            IntType gen;
            while (!generatorFound) {
                    usint count = 0;

                    //gen = RNG(qm2).ModAdd(IntType::ONE, q); //modadd note needed
                    gen = RNG(qm2) + IntType(1);
                    DEBUG("generator " << gen);
                    DEBUG("cycling thru prime factors");

                    for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it) {
                            DEBUG(qm1 << " / " << *it << " " << gen.ModExp(qm1 / (*it), q));

                            if (gen.ModExp(qm1 / (*it), q) == IntType(1)) break;
                            else count++;
                    }
                    if (count == primeFactors.size()) generatorFound = true;
            }
            return gen;
    }

	/*
	A helper function for arbitrary cyclotomics. This finds a generator for any composite q (cyclic group).
	Input: BigInteger q (cyclic group).
	Output: A generator of q
	*/
	template<typename IntType>
	IntType FindGeneratorCyclic(const IntType& q)
	{
		bool dbg_flag = false;
		std::set<IntType> primeFactors;
		DEBUG("calling PrimeFactorize");

		IntType phi_q = IntType(GetTotient(q.ConvertToInt()));
		IntType phi_q_m1 = IntType(GetTotient(q.ConvertToInt()));

		PrimeFactorize<IntType>(phi_q, primeFactors);
		DEBUG("done");
		bool generatorFound = false;
		IntType gen;
		while (!generatorFound) {
			usint count = 0;
			DEBUG("count " << count);

			gen = RNG(phi_q_m1) + IntType(1); // gen is random in [1, phi(q)]
			if (GreatestCommonDivisor<IntType>(gen, q) != IntType(1)) {
				// Generator must lie in the group!
				continue;
			}

			// Order of a generator cannot divide any co-factor
			for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it) {
				DEBUG("in set");
				DEBUG("divide " << phi_q << " by " << *it);

				if (gen.ModExp(phi_q / (*it), q) == IntType(1)) break;
				else count++;
			}

			if (count == primeFactors.size()) generatorFound = true;
		}
		return gen;
	}

	/*
	A helper function for arbitrary cyclotomics. Checks if g is a generator of q (supports any cyclic group, not just prime-modulus groups)
	Input: Candidate generator g and modulus q
	Output: returns true if g is a generator for q
	*/
	template<typename IntType>
	bool IsGenerator(const IntType &g, const IntType& q)
	{
		bool dbg_flag = false;
		std::set<IntType> primeFactors;
		DEBUG("calling PrimeFactorize");

		IntType qm1 = IntType(GetTotient(q.ConvertToInt()));

		PrimeFactorize<IntType>(qm1, primeFactors);
		DEBUG("done");

		usint count = 0;

		for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it) {
			DEBUG("in set");
			DEBUG("divide " << qm1 << " by " << *it);

			if (g.ModExp(qm1 / (*it), q) == IntType(1)) break;
			else count++;
		}

		if (count == primeFactors.size())
			return true;
		else
			return false;

	}

	/*
		finds roots of unity for given input.  Assumes the the input is a power of two.  Mostly likely does not give correct results otherwise.
		input:	m as number which is cyclotomic(in format of int),
				modulo which is used to find generator (in format of BigInteger)

		output:	root of unity (in format of BigInteger)
	*/
	template<typename IntType>
	IntType RootOfUnity(usint m, const IntType& modulo)
	{
		bool dbg_flag = false;
		DEBUG("in Root of unity m :" << m << " modulo " << modulo.ToString());
		IntType M(m);
		if ((modulo - IntType(1)).Mod(M) != IntType(0)) {
			std::string errMsg = "Please provide a primeModulus(q) and a cyclotomic number(m) satisfying the condition: (q-1)/m is an integer. The values of primeModulus = " + modulo.ToString() + " and m = " + std::to_string(m) + " do not satisfy this condition";
			throw std::runtime_error(errMsg);
		}
		IntType result;
		DEBUG("calling FindGenerator");
		IntType gen = FindGenerator(modulo);
		DEBUG("gen = " << gen.ToString());

		DEBUG("calling gen.ModExp( " << ((modulo - IntType(1)).DividedBy(M)).ToString() << ", modulus " << modulo.ToString());
		result = gen.ModExp((modulo - IntType(1)).DividedBy(M), modulo);
		DEBUG("result = " << result.ToString());
		if (result == IntType(1)) {
			DEBUG("LOOP?");
			return RootOfUnity(m, modulo);
		}
		return result;
	}

	template<typename IntType>
	std::vector<IntType> RootsOfUnity(usint m, const std::vector<IntType> moduli) {
		std::vector<IntType> rootsOfUnity(moduli.size());
		for (usint i = 0; i < moduli.size(); i++) {
			rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		}
		return rootsOfUnity;
	}

	// precomputed reverse of a byte

	inline static unsigned char reverse_byte(unsigned char x)
	{
		static const unsigned char table[] = {
			0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
			0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
			0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
			0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
			0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
			0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
			0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
			0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
			0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
			0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
			0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
			0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
			0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
			0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
			0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
			0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
			0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
			0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
			0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
			0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
			0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
			0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
			0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
			0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
			0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
			0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
			0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
			0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
			0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
			0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
			0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
			0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
		};
		return table[x];
	}

	static int shift_trick[] = { 0, 7, 6, 5, 4, 3, 2, 1 };

	/* Function to reverse bits of num */
	usint ReverseBits(usint num, usint msb)
	{
		usint msbb = msb / 8 + (msb % 8 ? 1 : 0);

		switch (msbb) {
		case 1:
			return (reverse_byte((num) & 0xff) >> shift_trick[msb % 8]);

		case 2:
			return (reverse_byte((num) & 0xff) << 8 |
				reverse_byte((num >> 8) & 0xff)) >> shift_trick[msb % 8];

		case 3:
			return (reverse_byte((num) & 0xff) << 16 |
				reverse_byte((num >> 8) & 0xff) << 8 |
				reverse_byte((num >> 16) & 0xff)) >> shift_trick[msb % 8];

		case 4:
			return (reverse_byte((num) & 0xff) << 24 |
				reverse_byte((num >> 8) & 0xff) << 16 |
				reverse_byte((num >> 16) & 0xff) << 8 |
				reverse_byte((num >> 24) & 0xff)) >> shift_trick[msb % 8];
		default:
			throw std::logic_error("msbb value not handled:" + std::to_string(msbb));
		}
	}

	template<typename IntType>
	IntType GreatestCommonDivisor(const IntType& a, const IntType& b)
	{
		bool dbg_flag = false;
		IntType m_a, m_b, m_t;
		m_a = a;
		m_b = b;
		DEBUG("GCD a " << a.ToString() << " b " << b.ToString());
		while (m_b != IntType(0)) {
			m_t = m_b;
			DEBUG("GCD m_a.Mod(b) " << m_a.ToString() << "( " << m_b.ToString() << ")");
			m_b = m_a.Mod(m_b);

			m_a = m_t;
			DEBUG("GCD m_a " << m_b.ToString() << " m_b " << m_b.ToString());
		}
		DEBUG("GCD ret " << m_a.ToString());
		return m_a;
	}

	//define an NTL native implementation 
	NTL::myZZ GreatestCommonDivisor(const NTL::myZZ& a, const NTL::myZZ& b)
	{
		bool dbg_flag = false;
		DEBUG("NTL::GCD a " << a << " b " << b);
		return GCD(a, b);
	}

	/*
	  The Miller-Rabin Primality Test
	  Input: p the number to be tested for primality.
	  Output: true if p is prime,
	  false if p is not prime
	*/
	template<typename IntType>
	bool MillerRabinPrimalityTest(const IntType& p, const usint niter)
	{
		bool dbg_flag = false;
		if (p < IntType(2) || ((p != IntType(2)) && (p.Mod(2) == IntType(0))))
			return false;
		if (p == IntType(2) || p == IntType(3) || p == IntType(5))
			return true;

		IntType d = p - IntType(1);
		usint s = 0;
		DEBUG("start while d " << d);
		while (d.Mod(2) == IntType(0)) {
			d.DividedByEq(2);
			s++;
		}
		DEBUG("end while s " << s);
		bool composite = true;
		for (usint i = 0; i < niter; i++) {
			DEBUG(".1");
			IntType a = RNG(p - IntType(3)).ModAdd(2, p);
			DEBUG(".2");
			composite = (WitnessFunction(a, d, s, p));
			if (composite)
				break;
		}
		DEBUG("done composite " << composite);
		return (!composite);
	}


	//NTL native version
	bool MillerRabinPrimalityTest(const NTL::myZZ& p, const usint niter)
	{
		bool dbg_flag = false;
		DEBUG("in NTL MRPT");
		if (p < NTL::myZZ(2) || ((p != NTL::myZZ(2)) &&
			(p.Mod(NTL::myZZ(2)) == NTL::myZZ(0))))
			return false;
		if (p == NTL::myZZ(2) || p == NTL::myZZ(3) || p == NTL::myZZ(5))
			return true;

		return (bool)ProbPrime(p, niter); //TODO: check to see if niter >maxint
	}

	/*
		The Pollard Rho factorization of a number n.
		Input: n the number to be factorized.
		Output: a factor of n.
	*/
	template<typename IntType>
	const IntType PollardRhoFactorization(const IntType &n)
	{
		bool dbg_flag = false;
		IntType divisor(1);

		IntType c(RNG(n));
		IntType x(RNG(n));
		IntType xx(x);

		//check divisibility by 2
		if (n.Mod(2) == IntType(0))
			return IntType(2);

		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(n);

		do {
#if MATHBACKEND == 6
			x = (x*x + c).ModBarrett(n,mu);
			xx = (xx*xx + c).ModBarrett(n,mu);
			xx = (xx*xx + c).ModBarrett(n,mu);
#else		
			x = x.ModBarrettMul(x, n, mu).ModBarrettAdd(c, n, mu);
			xx = xx.ModBarrettMul(xx, n, mu).ModBarrettAdd(c, n, mu);
			xx = xx.ModBarrettMul(xx, n, mu).ModBarrettAdd(c, n, mu);
#endif
			divisor = GreatestCommonDivisor(((x - xx) > IntType(0)) ? x - xx : xx - x, n);
			DEBUG("PRF divisor " << divisor.ToString());

		} while (divisor == IntType(1));

		return divisor;
	}

	/*
		Recursively factorizes and find the distinct primefactors of a number
		Input: n is the number to be prime factorized,
			   primeFactors is a set of prime factors of n.
	*/
	template<typename IntType>
	void PrimeFactorize(IntType n, std::set<IntType> &primeFactors)
	{
		bool dbg_flag = false;
		DEBUG("PrimeFactorize " << n);

		// primeFactors.clear();
		DEBUG("In PrimeFactorize n " << n);
		DEBUG("set size " << primeFactors.size());

		if (n == IntType(0) || n == IntType(1)) return;
		DEBUG("calling MillerRabinPrimalityTest(" << n << ")");
		if (MillerRabinPrimalityTest(n)) {
			DEBUG("Miller true");
			primeFactors.insert(n);
			return;
		}

		DEBUG("calling PrFact n " << n);
		IntType divisor(PollardRhoFactorization(n));

		DEBUG("calling PF " << divisor);
		PrimeFactorize(divisor, primeFactors);

		DEBUG("calling div " << divisor);
		//IntType reducedN = n.DividedBy(divisor);
		n /= divisor;

		DEBUG("calling PF reduced n " << n);
		PrimeFactorize(n, primeFactors);
	}

	template<typename IntType>
	IntType FirstPrime(usint nBits, usint m) {
		bool dbg_flag = false;
		IntType r = IntType(2).ModExp(nBits, m);
		DEBUG("r "<<r);
		IntType qNew = (IntType(1) << nBits) + (IntType(m) - r) + IntType(1);

		size_t i = 1;
	        // TP: size_t is a system dependent size, i.e., not of a known size.  Seems like it would
		// be better to make this a well-defined and system independent type.
		//  Seems much better to match the type to m

		while (!MillerRabinPrimalityTest(qNew)) {
			// TP: Dangerous assumption?  This assumes that i*m is smaller than the maximum size of an arg to IntType, whihc
			// is probably no bigger than 2^32-1 or 2^64-1.
			// Also, should this really add a steadly increasing value to qNew or just keet adding m?
			qNew += IntType(i*m);
			i++;
		}

		return qNew;

	}

	template<typename IntType>
	IntType NextPrime(const IntType &q, usint m) {

		IntType M(m);
		IntType qNew = q + M;

		while (!MillerRabinPrimalityTest(qNew)) {
			qNew += M;
		}

		return qNew;

	}


	/*
		Finds multiplicative inverse using the Extended Euclid Algorithms
	*/
	usint ModInverse(usint a, usint b)
	{

		//usint b0 = b;
		usint t, q;
		usint x0 = 0, x1 = 1;
		if (b == 1) return 1;
		while (a > 1) {
			q = a / b;
			t = b, b = a % b, a = t;
			t = x0, x0 = x1 - q * x0, x1 = t;
		}
		//if (x1 < 0) x1 += b0;
		//TODO: x1 is never < 0

		return x1;
	}

	template<>
	usint GreatestCommonDivisor(const usint& a, const usint& b)
	{
		bool dbg_flag = false;
		usint m_a, m_b, m_t;
		m_a = a;
		m_b = b;
		DEBUG("GCD a " << a << " b " << b);
		while (m_b != 0) {
			m_t = m_b;
			DEBUG("GCD m_a.Mod(b) " << m_a << "( " << m_b << ")");
			m_b = m_a % (m_b);

			m_a = m_t;
			DEBUG("GCD m_a " << m_b << " m_b " << m_b);
		}
		DEBUG("GCD ret " << m_a);
		return m_a;
	}

	template<typename IntType>
	IntType NextPowerOfTwo(const IntType &n) {
		usint result = ceil(log2(n));
		return result;
	}

	uint64_t GetTotient(const uint64_t n) {

		std::set<NativeInteger> factors;
		NativeInteger enn(n);
		PrimeFactorize(enn, factors);

		NativeInteger primeProd(1);
		NativeInteger numerator(1);
		for (auto &r : factors) {
			numerator = numerator * (r - 1);
			primeProd = primeProd * r;
		}

		primeProd = (enn / primeProd) * numerator;
		return primeProd.ConvertToInt();
	}

	/*Naive Loop to find coprimes to n*/
	template<typename IntType>
	std::vector<IntType> GetTotientList(const IntType &n) {

		std::vector<IntType> result;
		IntType one(1);
		for (IntType i = IntType(1); i < n; i = i + IntType(1)) {
			if (GreatestCommonDivisor(i, n) == one)
				result.push_back(i);
		}

		return std::move(result);
	}

	/* Calculate the remainder from polynomial division */
	template<typename IntVector, typename IntType>
	IntVector PolyMod(const IntVector &dividend, const IntVector &divisor, const IntType &modulus) {

		usint divisorLength = divisor.GetLength();
		usint dividendLength = dividend.GetLength();

		IntVector result(divisorLength - 1, modulus);
		usint runs = dividendLength - divisorLength + 1; //no. of iterations

		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(modulus);

		auto mat = [](const IntType &x, const IntType &y, const IntType &z, const IntType &mod, const IntType &muBarrett) {
			IntType result(z.ModBarrettSub(x*y, mod, muBarrett));
			return result;
		};

		IntVector runningDividend(dividend);

		usint  divisorPtr;
		for (usint i = 0; i < runs; i++) {
			IntType divConst(runningDividend.at(dividendLength - 1));//get the highest degree coeff
			divisorPtr = divisorLength - 1;
			for (usint j = 0; j < dividendLength - i - 1; j++) {
				if (divisorPtr > j) {
					runningDividend.at(dividendLength - 1 - j)=
						mat(divisor.at(divisorPtr - 1 - j), divConst, runningDividend.at(dividendLength - 2 - j), modulus, mu);
				}
				else
					runningDividend.at(dividendLength - 1 - j)= runningDividend.at(dividendLength - 2 - j);

			}
		}

		for (usint i = 0, j = runs; i < divisorLength - 1; i++, j++) {
			result.at(i)= runningDividend.at(j);
		}


		return result;
	}

	std::vector<int> GetCyclotomicPolynomialRecursive(usint m) {
		std::vector<int> result;
		if (m == 1) {
			result = { -1,1 };
			return result;
		}
		if (m == 2) {
			result = { 1,1 };
			return result;
		}
		auto IsPrime = [](usint m) {
			bool flag = true;
			for (usint i = 2; i < m; i++) {
				if (m%i == 0) {
					flag = false;
					return flag;
				}
			}
			return flag;
		};
		if (IsPrime(m)) {
			result = std::vector<int>(m, 1);
			return result;
		}

		auto GetDivisibleNumbers = [](usint m) {
			std::vector<usint> div;
			for (usint i = 1; i < m; i++) {
				if (m%i == 0) {
					div.push_back(i);
				}
			}
			return div;
		};

		auto PolyMult = [](const std::vector<int> &a, const std::vector<int> &b) {
			usint degreeA = a.size() - 1;
			usint degreeB = b.size() - 1;

			usint degreeResultant = degreeA + degreeB;

			std::vector<int> result(degreeResultant + 1, 0);

			for (usint i = 0; i < a.size(); i++) {

				for (usint j = 0; j < b.size(); j++) {
					const auto &valResult = result.at(i + j);
					const auto &valMult = a.at(i)*b.at(j);
					result.at(i + j) = valMult + valResult;
				}
			}

			return result;
		};

		auto PolyQuotient = [](const std::vector<int> &dividend, const std::vector<int> &divisor) {
			usint divisorLength = divisor.size();
			usint dividendLength = dividend.size();

			usint runs = dividendLength - divisorLength + 1; //no. of iterations
			std::vector<int> result(runs + 1);

			auto mat = [](const int x, const int y, const int z) {
				int result = z - (x*y);
				return result;
			};

			std::vector<int> runningDividend(dividend);

			usint  divisorPtr;
			for (usint i = 0; i < runs; i++) {
				int divConst = (runningDividend.at(dividendLength - 1));//get the highest degree coeff
				divisorPtr = divisorLength - 1;
				for (usint j = 0; j < dividendLength - i - 1; j++) {
					if (divisorPtr > j) {
						runningDividend.at(dividendLength - 1 - j) = mat(divisor.at(divisorPtr - 1 - j), divConst, runningDividend.at(dividendLength - 2 - j));
					}
					else
						runningDividend.at(dividendLength - 1 - j) = runningDividend.at(dividendLength - 2 - j);

				}
				result.at(i + 1) = runningDividend.at(dividendLength - 1);
			}
			result.at(0) = 1;//under the assumption that both dividend and divisor are monic
			result.pop_back();

			return result;
		};
		auto divisibleNumbers = GetDivisibleNumbers(m);

		std::vector<int> product(1, 1);

		for (usint i = 0; i < divisibleNumbers.size(); i++) {
			auto P = GetCyclotomicPolynomialRecursive(divisibleNumbers[i]);
			product = PolyMult(product, P);
		}

		//make big poly = x^m - 1
		std::vector<int> bigPoly(m + 1, 0);
		bigPoly.at(0) = -1;
		bigPoly.at(m) = 1;

		result = PolyQuotient(bigPoly, product);

		return result;
	}

	template<typename IntVector>
	IntVector PolynomialMultiplication(const IntVector &a, const IntVector &b) {

		usint degreeA = a.GetLength() - 1;
		usint degreeB = b.GetLength() - 1;

		usint degreeResultant = degreeA + degreeB;

		const auto &modulus = a.GetModulus();

		IntVector result(degreeResultant + 1, modulus);

		for (usint i = 0; i < a.GetLength(); i++) {

			for (usint j = 0; j < b.GetLength(); j++) {
				const auto &valResult = result.at(i + j);
				const auto &valMult = a.at(i)*b.at(j);
				result.at(i + j)= (valMult + valResult).Mod(modulus);
			}
		}

		return result;

	}

	template<typename IntVector, typename IntType>
	IntVector GetCyclotomicPolynomial(usint m, const IntType &modulus) {

		auto intCP = GetCyclotomicPolynomialRecursive(m);
		IntVector result(intCP.size(), modulus);
		for (usint i = 0; i < intCP.size(); i++) {
			auto val = intCP.at(i);
			if (intCP.at(i) > -1)
				result.at(i)= IntType(val);
			else {
				val *= -1;
				result.at(i)= modulus - IntType(val);
			}

		}

		return result;

	}


	template<typename IntVector, typename IntType>
	IntType SyntheticRemainder(const IntVector &dividend, const IntType &a, const IntType &modulus) {
		auto val = dividend.at(dividend.GetLength() - 1);

		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(modulus);

		for (int i = dividend.GetLength() - 2; i > -1; i--) {
			val = dividend.at(i) + a*val;
			val = val.ModBarrett(modulus, mu);
		}

		return val;
	}

	template<typename IntVector, typename IntType>
	IntVector SyntheticPolyRemainder(const IntVector &dividend, const IntVector &aList, const IntType &modulus) {
		IntVector result(aList.GetLength(), modulus);
		for (usint i = 0; i < aList.GetLength(); i++) {
			result.at(i) = SyntheticRemainder(dividend, aList.at(i), modulus);
		}

		return result;
	}

	template<typename IntVector, typename IntType>
	IntVector PolynomialPower(const IntVector &input, usint power) {
		usint finalDegree = (input.GetLength() - 1)*power;
		IntVector finalPoly(finalDegree + 1, input.GetModulus());
		finalPoly.at(0)= input.at(0);
		for (usint i = 1; i < input.GetLength(); i++) {
			finalPoly.at(i*power)= input.at(i);
		}
		return finalPoly;
	}

	template<typename IntVector, typename IntType>
	IntVector SyntheticPolynomialDivision(const IntVector &dividend, const IntType &a, const IntType &modulus) {
		usint n = dividend.GetLength() - 1;
		IntVector result(n, modulus);

		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(modulus);

		result.at(n - 1)= dividend.at(n);
		auto val(dividend.at(n));
		for (int i = n - 1; i > 0; i--) {
			val = val*a + dividend.at(i);
			val = val.ModBarrett(modulus, mu);
			result.at(i - 1)= val;
		}

		return result;
	}

	template<typename IntType>
	IntType ComputeMu(const IntType& q)
	{
#if MATHBACKEND == 4 || MATHBACKEND == 6
		return IntType(1);
#else
		//Precompute the Barrett mu parameter
		IntType temp(1);
		temp <<= 2 * q.GetMSB() + 3;
		return temp.DividedBy(q);
#endif
	}

}
