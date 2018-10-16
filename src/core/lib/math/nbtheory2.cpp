/**
 * @file nbtheory2.cpp This code provides number theory utilities that are not templated by Integer or Vector
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

	//native NTL version
	NTL::myZZ RNG(const NTL::myZZ& modulus)
	{
		bool dbg_flag = false;
		DEBUG("in NTL RNG");
		return RandomBnd(modulus);

	}

	//define an NTL native implementation 
	NTL::myZZ GreatestCommonDivisor(const NTL::myZZ& a, const NTL::myZZ& b)
	{
		bool dbg_flag = false;
		DEBUG("NTL::GCD a " << a << " b " << b);
		return GCD(a, b);
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

	uint32_t FindAutomorphismIndex2n(int32_t i, uint32_t m) {

		uint32_t n = GetTotient(m);

		uint32_t f1, f2;

		if (i < 0)
		{
			f1 = NativeInteger(5).ModInverse(m).ConvertToInt();
			f2 = NativeInteger(m-1).ModInverse(m).ConvertToInt();
		}
		else
		{
			f1 = 5;
			f2 = m-1;
		}

		uint32_t i_unsigned = (uint32_t)std::abs(i);

		uint32_t g0 = f1;
		uint32_t g;

		if (i_unsigned < n/2)
		{
			g = f1;
			for (size_t j = 1; j < i_unsigned; j++)
				g = (g * g0) % m;
		}
		else
		{
			g = f2;
			for (size_t j = n/2; j < i_unsigned; j++)
				g = (g * g0) % m;
		}

		return g;

	}

	uint32_t FindAutomorphismIndexCyclic(int32_t i, uint32_t m, uint32_t g){

		int32_t n = GetTotient(m);

		int32_t i_signed = i % n;
		if (i_signed <= 0)
			i_signed += n;

		uint32_t i_unsigned = (uint32_t)i_signed;

		uint32_t k = g;

		for (size_t i = 2; i < i_unsigned; i++)
			k = (k * g) % m;

		return k;

	}

}
