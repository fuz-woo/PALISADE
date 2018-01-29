/*
 * @file ternaryuniformgenerator.cpp This code provides generation of a uniform distribution of binary values (modulus 2).
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
 
#include "ternaryuniformgenerator.h"
#include <random>

namespace lbcrypto {

template<typename IntType, typename VecType>
std::uniform_int_distribution<int> TernaryUniformGeneratorImpl<IntType,VecType>::m_distribution = std::uniform_int_distribution<int>(-1,1);

template<typename IntType, typename VecType>
VecType TernaryUniformGeneratorImpl<IntType,VecType>::GenerateVector (usint size, const IntType &modulus) const {
	
	VecType v(size);
	v.SetModulus(modulus);
	int32_t randomNumber;

	for (usint i = 0; i < size; i++) {
		randomNumber = m_distribution(PseudoRandomNumberGenerator::GetPRNG());
		if (randomNumber < 0)
			v[i] = modulus - IntType(1);
		else
			v[i] = IntType(randomNumber);
	}

	return v;
}

template<typename IntType, typename VecType>
std::shared_ptr<int32_t> TernaryUniformGeneratorImpl<IntType,VecType>::GenerateIntVector (usint size) const {
	
	std::shared_ptr<int32_t> ans( new int32_t[size], std::default_delete<int32_t[]>() );

	for (usint i = 0; i < size; i++) {
		(ans.get())[i] = m_distribution(PseudoRandomNumberGenerator::GetPRNG());		

	}

	return ans;
}

} // namespace lbcrypto
