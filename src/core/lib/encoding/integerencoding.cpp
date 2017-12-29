/**
 * @file integerencoding.h Represents and defines integer-encoded plaintext objects in Palisade.
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

#include "integerencoding.h"

namespace lbcrypto {

template<typename P>
inline static void encodePoly(P& poly, int64_t value, const PlaintextModulus& ptm) {
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
}

bool
IntegerEncoding::Encode() {
	if( this->isEncoded ) return true;
	PlaintextModulus mod = this->encodingParams->GetPlaintextModulus();

	if( mod < 2 ) {
		PALISADE_THROW( config_error, "Plaintext modulus must be 2 or more for integer encoding");
	}

	if( mod >= UINT32_MAX ) {
		PALISADE_THROW( config_error, "Plaintext modulus must be less than " + std::to_string(UINT32_MAX) + " for integer encoding");
	}

	if( value <= LowBound() || value > HighBound() )
		PALISADE_THROW( config_error, "Cannot encode integer " + std::to_string(value) + " because it is out of range of plaintext modulus " + std::to_string(mod) );

	if( this->typeFlag == IsNativePoly ) {
		encodePoly(this->encodedNativeVector, value, mod);
	}
	else {
		encodePoly(this->encodedVector, value, mod);
	}

	if( this->typeFlag == IsDCRTPoly ) {
		this->encodedVectorDCRT = this->encodedVector;
	}

	this->isEncoded = true;
	return true;
}

template<typename P>
inline static int64_t decodePoly(const P& poly, const PlaintextModulus& ptm) {
	int64_t result = 0;
	int64_t powerFactor = 1;
	int64_t half = ptm/2;

	for (size_t i = 0; i < poly.GetLength(); i++) {

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
IntegerEncoding::Decode() {
	auto modulus = this->encodingParams->GetPlaintextModulus();

	if( this->typeFlag == IsNativePoly )
		value = decodePoly(this->encodedNativeVector, modulus);
	else
		value = decodePoly(this->encodedVector, modulus);

	return true;
}


} /* namespace lbcrypto */
