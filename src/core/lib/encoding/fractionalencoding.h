/**
 * @file fractionalencoding.h EXPERIMENTAL FEATURE: Defines a limited version of the fractional encoder.
 * Currently it is simply an extended version of integer encoding. In addition to integer encoding operations,
 * it supports integer division by another integer (with the fractional part being truncated during decryption).
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

#ifndef SRC_CORE_LIB_ENCODING_FRACTIONALENCODING_H_
#define SRC_CORE_LIB_ENCODING_FRACTIONALENCODING_H_

#include "plaintext.h"

namespace lbcrypto {

class FractionalEncoding: public PlaintextImpl {
	// integer part
	int64_t		m_integer;
	// number of bits reserved for the fractional part (index from the end)
	size_t 		m_separator;
	// m_numerator and m_denominator are not currently used
	uint64_t		m_numerator;
	uint64_t		m_denominator;

public:
	// these two constructors are used inside of Decrypt
	FractionalEncoding(shared_ptr<Poly::Params> vp, EncodingParams ep) :
		PlaintextImpl(vp,ep), m_integer(0), m_separator(0), m_numerator(0), m_denominator(0) {}

	FractionalEncoding(shared_ptr<NativePoly::Params> vp, EncodingParams ep) :
		PlaintextImpl(vp,ep), m_integer(0), m_separator(0), m_numerator(0), m_denominator(0)  {}

	FractionalEncoding(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep) :
		PlaintextImpl(vp,ep), m_integer(0), m_separator(0), m_numerator(0), m_denominator(0) {}

	FractionalEncoding(shared_ptr<Poly::Params> vp, EncodingParams ep, int64_t scalar, size_t divisorBits = 0) :
		PlaintextImpl(vp,ep), m_integer(scalar), m_separator(divisorBits), m_numerator(0), m_denominator(0) {}

	FractionalEncoding(shared_ptr<NativePoly::Params> vp, EncodingParams ep, int64_t scalar, size_t divisorBits = 0) :
		PlaintextImpl(vp,ep), m_integer(scalar), m_separator(divisorBits), m_numerator(0), m_denominator(0)  {}

	FractionalEncoding(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep, int64_t scalar, size_t divisorBits = 0) :
		PlaintextImpl(vp,ep), m_integer(scalar), m_separator(divisorBits), m_numerator(0), m_denominator(0) {}

	virtual ~FractionalEncoding() {}

	/**
	 * GetScalarValue
	 * @return the un-encoded scalar
	 */
	const int64_t GetIntegerValue() const { return m_integer; }

	/**
	 * SetFractionalValues
	 * @param scalar actual scalar value
	 * @param divisorBits bit cutoff
	 */
	void SetFractionalValues(int64_t scalar, size_t divisorBits = 0) { m_integer = scalar; m_separator = divisorBits; }

	// these methods are placeholders until the members are used
	uint64_t	 GetNumerator() const { return m_numerator; }
	uint64_t GetDenominator() const { return m_denominator; }

	/**
	 * Encode the plaintext into the Poly
	 * @return true on success
	 */
	bool Encode();

	/**
	 * Decode the Poly into the string
	 * @return true on success
	 */
	bool Decode();

	/**
	 * GetEncodingType
	 * @return this is an Integer encoding
	 */
	PlaintextEncodings GetEncodingType() const { return Fractional; }

	/**
	 * Get length of the plaintext
	 *
	 * @return number of elements in this plaintext
	 */
	size_t GetLength() const { return 1; }

	/**
	 * Method to compare two plaintext to test for equivalence
	 * Testing that the plaintexts are of the same type done in operator==
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const PlaintextImpl& other) const {
		const FractionalEncoding& oth = dynamic_cast<const FractionalEncoding&>(other);
		return oth.m_integer == this->m_integer;
	}

	/**
	 * PrintValue - used by operator<< for this object
	 * @param out
	 */
	void PrintValue(std::ostream& out) const { out << m_integer; }
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_INTEGERENCODING_H_ */
