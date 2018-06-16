/**
 * @file fractionalencoding.cpp EXPERIMENTAL FEATURE: Represents and defines a limited version of the fractional encoder.
 * Currently it is simply an extended version of integer encoding with division supported.
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

#include "fractionalencoding.h"

namespace lbcrypto {

template<typename P>
inline static void encodePoly(P& poly, int64_t value, const PlaintextModulus& ptm, size_t divisorBits) {
	uint32_t negvalue = ptm - 1;
	bool isNegative = value < 0;
	uint64_t entry = isNegative ? -value : value;

	poly.SetValuesToZero();

	if( log2((double)value) > (double)poly.GetLength() )
		PALISADE_THROW( config_error, "Plaintext value " + std::to_string(value) + " will not fit in encoding of length " + std::to_string(poly.GetLength()));

	size_t i = 0;

	while( entry > 0 ) {
		if( entry & 0x01 )
			poly[i] = isNegative ? negvalue : 1;
		i++;
		entry >>= 1;
	}

	if (divisorBits!=0)
	{
		size_t n = poly.GetLength();

		poly[n-divisorBits] = ptm-1;
	}
}

bool
FractionalEncoding::Encode() {
	if( this->isEncoded ) return true;
	PlaintextModulus mod = this->encodingParams->GetPlaintextModulus();

	if( mod < 2 ) {
		PALISADE_THROW( config_error, "Plaintext modulus must be 2 or more for fractional encoding");
	}

	if( mod >= UINT32_MAX ) {
		PALISADE_THROW( config_error, "Plaintext modulus must be less than " + std::to_string(UINT32_MAX) + " for fractional encoding");
	}

	if( m_integer <= LowBound() || m_integer > HighBound() )
		PALISADE_THROW( config_error, "Cannot encode integer " + std::to_string(m_integer) + " because it is out of range of plaintext modulus " + std::to_string(mod) );

	if( this->typeFlag == IsNativePoly ) {
		encodePoly(this->encodedNativeVector, m_integer, mod, m_separator);
	}
	else {
		encodePoly(this->encodedVector, m_integer, mod, m_separator);
	}

	if( this->typeFlag == IsDCRTPoly ) {
		this->encodedVectorDCRT = this->encodedVector;
	}

	this->isEncoded = true;
	return true;
}

template<typename P>
inline static int64_t decodePoly(const P& poly, const PlaintextModulus& ptm, size_t truncatedBits) {
	int64_t result = 0;
	int64_t powerFactor = 1;
	int64_t half = ptm/2;

	for (size_t i = 0; i < poly.GetLength()-truncatedBits; i++) {

		int64_t val = poly[i].ConvertToInt();

		if( val != 0 ) {
			if( val <= half )
				result += powerFactor * val;
			else
				result += powerFactor * (val - ptm);
		}

		// multiply the power factor by 2
		powerFactor <<= 1;
	}

	return result;
}

bool
FractionalEncoding::Decode() {
	auto modulus = this->encodingParams->GetPlaintextModulus();

	if( this->typeFlag == IsNativePoly )
		m_integer = decodePoly(this->encodedNativeVector, modulus, m_separator);
	else
		m_integer = decodePoly(this->encodedVector, modulus, m_separator);

	return true;
}


} /* namespace lbcrypto */
