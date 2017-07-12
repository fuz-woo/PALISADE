/*
 * @file byteplaintextencoding.cpp Represents and defines plaintext objects in Palisade 
 * that encodes bytes of data, notionally chars.
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

#include "byteplaintextencoding.h"

namespace lbcrypto {

BytePlaintextEncoding::BytePlaintextEncoding(const char* cstr) {
	std::string s(cstr);
	*this = s;
}

BytePlaintextEncoding::BytePlaintextEncoding(const char* cstr, usint len) {
	std::string s(cstr, len);
	*this = s;
}

BytePlaintextEncoding& BytePlaintextEncoding::operator=(const std::string& s) {
	BytePlaintextEncoding rhs(s);
	operator=(rhs);
	return *this;
}

BytePlaintextEncoding& BytePlaintextEncoding::operator=(const char* cstr) {
	std::string s(cstr);
	operator=(s);
	return *this;
}

template<typename IntType, typename VecType, typename ElementType>
static void
doEncode(const BytePlaintextEncoding& item, const BigInteger &modulus, ElementType *ilVector, size_t startFrom, size_t length)
{
	size_t		padlen = 0;

	// default values mean "do it all"
	if( length == 0 ) length = item.size();

	// length is usually chunk size; if start + length would go past the end of the item, add padding
	if( (startFrom + length) > item.size() ) {
		padlen = (startFrom + length) - item.size();
		length = length - padlen;
	}

	uint64_t mod = modulus.ConvertToInt();

	if( mod != 2 && mod != 4 && mod != 16 && mod != 256 )
		throw std::logic_error("Cannot encode byte array with a plaintext modulus of " + std::to_string(mod)
			+ ", must choose {2,4,16,256}");

	usint p = ceil((float)log((double)255) / log((double)mod));

	usint vsize = p*(length+padlen);
	VecType temp(vsize);
	temp.SetModulus(ilVector->GetModulus());
	Format format = COEFFICIENT;

	for (usint i = 0; i<length; i++) {
		size_t actualPos = i + startFrom;
		size_t actualPosP = i * p;
		size_t Num = item.at(actualPos);
		size_t exp = mod, Rem = 0;
		for (size_t j = 0; j<p; j++) {
			Rem = Num%exp;
			temp.SetValAtIndex(actualPosP + j, IntType((Rem / (exp / mod))));
			Num -= Rem;
			exp *= mod;
		}
	}

	size_t Num = 0x80;
	for( size_t i=0; i<padlen; i++ ) {
		size_t actualPos = (i + length) * p;
		size_t exp = mod, Rem = 0;
		for (usint j = 0; j<p; j++) {
			Rem = Num%exp;
			temp.SetValAtIndex(actualPos + j, IntType((Rem / (exp / mod))));
			Num -= Rem;
			exp *= mod;
		}
		Num = 0x00;
	}

	ilVector->SetValues(temp,format);
}

template<typename IntType, typename ElementType>
static void
doDecode(BytePlaintextEncoding& item, const IntType &modulus, ElementType *ilVector)
{
    uint64_t mod = modulus.ConvertToInt();
    uint64_t p = ceil((float)log((double)255) / log((double)mod));
	unsigned char resultant_char;

	for (usint i = 0; i<ilVector->GetValues().GetLength(); i = i + p) {
	  usint exp = 1;
		resultant_char = 0;
		for (usint j = 0; j<p; j++) {
			resultant_char += ilVector->GetValues().GetValAtIndex(i + j).ConvertToInt()*exp;
			exp *= mod;
		}
		item.push_back(resultant_char);
	}
}

void BytePlaintextEncoding::Encode(const BigInteger &modulus, Poly *ilVector, size_t start_from, size_t length) const {
	doEncode<BigInteger,BigVector,Poly>(*this, modulus, ilVector, start_from, length);
}

void BytePlaintextEncoding::Decode(const BigInteger &modulus, Poly *ilVector) {
	doDecode(*this, modulus, ilVector);
}

void
BytePlaintextEncoding::Unpad(const BigInteger &)
{
	usint nPadding = 0;
	for (sint i = this->size() - 1; i >= 0; --i) { //todo: warning conversion from size_t
		nPadding++;
		if (this->at(i) == 0x80) {
			break;
		}
	}
	this->resize(this->size() - nPadding, 0);
}

size_t
BytePlaintextEncoding::GetChunksize(const usint ring, const BigInteger& ptm) const
{
	return (ring / 8) * log2(ptm.ConvertToInt());
}


}
