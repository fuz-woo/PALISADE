/**
 * @file scalarencoding.cpp Represents and defines scalar-encoded plaintext objects in Palisade.
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

#include "scalarencoding.h"

namespace lbcrypto {

bool
ScalarEncoding::Encode() {
	if( this->isEncoded ) return true;
	PlaintextModulus mod = this->encodingParams->GetPlaintextModulus();

	if( value > INT32_MAX || value < INT32_MIN ) {
		PALISADE_THROW( config_error, "Cannot encode a scalar larger than 32 bits");
	}

	if( value <= LowBound() || value > HighBound() )
		PALISADE_THROW( config_error, "Cannot encode integer " + std::to_string(value) + " because it is out of range of plaintext modulus " + std::to_string(mod) );

	uint32_t entry = value;

	// map to -p/2 .. p/2
	if( value < 0 ) {
		entry += mod;
	}

	if( this->typeFlag == IsNativePoly ) {
		this->encodedNativeVector.SetValuesToZero();
		this->encodedNativeVector[0] = entry;
	}
	else {
		this->encodedVector.SetValuesToZero();
		this->encodedVector[0] = entry;
	}

	if( this->typeFlag == IsDCRTPoly ) {
		this->encodedVectorDCRT = this->encodedVector;
	}

	this->isEncoded = true;
	return true;
}

bool
ScalarEncoding::Decode() {

	this->value = this->typeFlag == IsNativePoly ? this->encodedNativeVector[0].ConvertToInt() : this->encodedVector[0].ConvertToInt();

	PlaintextModulus mod = this->encodingParams->GetPlaintextModulus();

	if( this->value > int64_t(mod/2) )
		this->value -= mod;

	return true;
}

} /* namespace lbcrypto */
