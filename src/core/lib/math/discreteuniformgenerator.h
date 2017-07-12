/**
 * @file discreteuniformgenerator.h This code provides generation of uniform distibutions of discrete values. 
 * Discrete uniform generator relies on the built-in C++ generator for 32-bit unsigned integers defined in <random>.
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

#ifndef LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_

#include "backend.h"
#include "distributiongenerator.h"
#include <random>

namespace lbcrypto {

template<typename IntType, typename VecType>
class DiscreteUniformGeneratorImpl;

typedef DiscreteUniformGeneratorImpl<BigInteger,BigVector> DiscreteUniformGenerator;

/**
* @brief The class for Discrete Uniform Distribution generator over Zq.
*/
template<typename IntType, typename VecType>
class DiscreteUniformGeneratorImpl : public DistributionGenerator<IntType,VecType> {
public:
	/**
	* @brief         Constructs a new DiscreteUniformGenerator with the given modulus.
	*/
	DiscreteUniformGeneratorImpl ();

	/**
	* @brief         Sets the modulus. Overrides parent function
	* @param modulus The new modulus.
	*/
	void SetModulus (const IntType & modulus);

	/**
	* @brief Generates a random integer based on the modulus set for the Discrete Uniform Generator object.
	* Required by DistributionGenerator.
	*/
	IntType GenerateInteger () const;

	/**
	* @brief Generates a vector of random integers using GenerateInteger()
	*/
	VecType GenerateVector (const usint size) const;

private:
	// discrete uniform generator relies on the built-in C++ generator for 32-bit unsigned integers
	// the constants below set the parameters specific to 32-bit chunk configuration
	static const usint CHUNK_MIN = 0;
	static const usint CHUNK_WIDTH = std::numeric_limits<uint32_t>::digits;
	static const usint CHUNK_MAX = std::numeric_limits<uint32_t>::max();

	// number of 32-bit chunks in the modulus set for the discrete uniform generator object
	usint m_chunksPerValue;
	
	// built-in generator for 32-bit unsigned integers
	static std::uniform_int_distribution<uint32_t> m_distribution;

	/**
	* The modulus value that should be used to generate discrete values.
	*/
	IntType m_modulus;

};

} // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_
