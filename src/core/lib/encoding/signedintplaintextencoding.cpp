/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Jerry Ryan <gwryan@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 *
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 * This code provides a signed int array abstraction.
 *
 */

#include "signedintplaintextencoding.h"

namespace lbcrypto {

template <typename IntType, typename VecType, typename Element>
void SignedIntPlaintextEncoding::doEncode(const BigInteger &modulus, Element *ilVector, size_t startFrom, size_t length) const
{
	size_t padlen = 0;
	int64_t mod = modulus.ConvertToInt();

	if( mod%2 != 0 )
		throw std::logic_error("Plaintext modulus must be an even number for SignedIntPlaintextEncoding");

	if( length == 0 ) length = this->size();

	// length is usually chunk size; if start + length would go past the end of the item, add padding
	if( (startFrom + length) > this->size() ) {
		padlen = (startFrom + length) - this->size();
		length = length - padlen;
	}

	VecType temp(ilVector->GetParams()->GetRingDimension(),ilVector->GetModulus());

	Format format = COEFFICIENT;

	for (size_t i = 0; i < length; i++) {
		int32_t entry = this->at(i + startFrom);
		if( entry < 0 ) entry = mod - entry;
		if( entry >= mod )
			throw std::logic_error("Cannot encode integer " + std::to_string(entry) + " at position " + std::to_string(i) + " because it is out of range of +/- plaintext modulus/2 " + std::to_string(mod));
		IntType Val( entry );
		temp.SetValAtIndex(i, Val);
	}

	for( size_t i=0; i<padlen; i++ ) {
		temp.SetValAtIndex(i+length, IntType(0));
	}

	ilVector->SetValues(temp,format);
}

void SignedIntPlaintextEncoding::Encode(const BigInteger &modulus, Poly *ilVector, size_t start_from, size_t length) const {
	doEncode<BigInteger,BigVector,Poly>(modulus,ilVector,start_from,length);
}

template <typename IntType, typename VecType, typename Element>
void SignedIntPlaintextEncoding::doDecode(const BigInteger &modulus, Element *ilVector) {

	uint64_t mod = modulus.ConvertToInt();
	int64_t lim = mod/2;
	for (usint i = 0; i<ilVector->GetValues().GetLength(); i++) {
		int32_t val = ilVector->GetValues().GetValAtIndex(i).ConvertToInt();
		if( val > lim ) val -= mod;
		this->push_back( val );
	}
}

void SignedIntPlaintextEncoding::Decode(const BigInteger &modulus, Poly *ilVector) {
	doDecode<BigInteger,BigVector,Poly>(modulus,ilVector);
}

size_t
SignedIntPlaintextEncoding::GetChunksize(const usint ring, const BigInteger&) const
{
	return ring;
}

} /* namespace lbcrypto */
