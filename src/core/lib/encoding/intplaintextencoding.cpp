/*
 * @file plaintext.h Represents and defines plaintext objects in Palisade.
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
#include "intplaintextencoding.h"

namespace lbcrypto
{

// Forms a binary array from an integer; represents the integer as a binary polynomial
IntPlaintextEncoding::IntPlaintextEncoding(uint32_t value)
{
	for (size_t i = 0; i < 32; i++) {
		// gets i-th bit of the 32-bit integer
		this->push_back((value >> i) & 1);
	}
}

template <typename IntType, typename VecType, typename Element>
void IntPlaintextEncoding::doEncode(const BigInteger &modulus, Element *ilVector, size_t startFrom, size_t length) const
{
	size_t padlen = 0;
	uint64_t mod = modulus.ConvertToInt();

	if( length == 0 ) length = this->size();

	// length is usually chunk size; if start + length would go past the end of the item, add padding
	if( (startFrom + length) > this->size() ) {
		padlen = (startFrom + length) - this->size();
		length = length - padlen;
	}

	VecType temp(ilVector->GetParams()->GetRingDimension(),ilVector->GetModulus());

	Format format = COEFFICIENT;

	for (size_t i = 0; i < length; i++) {
		uint32_t entry = this->at(i + startFrom);
		if( entry >= mod )
			throw std::logic_error("Cannot encode integer at position " + std::to_string(i) + " because it is >= plaintext modulus " + std::to_string(mod));
		IntType Val( entry );
		temp.SetValAtIndex(i, Val);
	}

	for( size_t i=0; i<padlen; i++ ) {
		temp.SetValAtIndex(i+length, IntType(0));
	}

	ilVector->SetValues(temp,format);
}

void IntPlaintextEncoding::Encode(const BigInteger &modulus, Poly *ilVector, size_t start_from, size_t length) const
{
	doEncode<BigInteger,BigVector,Poly>(modulus,ilVector,start_from,length);
}

template <typename IntType, typename VecType, typename Element>
void IntPlaintextEncoding::doDecode(const BigInteger &modulus, Element *ilVector)
{

	for (usint i = 0; i<ilVector->GetValues().GetLength(); i++) {
		this->push_back( ilVector->GetValues().GetValAtIndex(i).ConvertToInt() );
	}
}

void IntPlaintextEncoding::Decode(const BigInteger &modulus, Poly *ilVector)
{
	doDecode<BigInteger,BigVector,Poly>(modulus,ilVector);
}

size_t
IntPlaintextEncoding::GetChunksize(const usint ring, const BigInteger&) const
{
	return ring;
}

// Evaluates the array of integers as a polynomial at x = 2
int32_t IntPlaintextEncoding::EvalToInt(uint32_t modulus) const
{
	int32_t result = 0;
	uint32_t powerFactor = 1;
	uint32_t half(modulus >> 1);
	for (size_t i = 0; i < this->size(); i++) {

		// deal with unsigned representation
		if (this->at(i) < half)
			result += powerFactor * this->at(i);
		else
			result -= powerFactor * (modulus - this->at(i));

		// multiply the power factor by 2
		powerFactor <<= 1;
	}
	return result;
}

}
