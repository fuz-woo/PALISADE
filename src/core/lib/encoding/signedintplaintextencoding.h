/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>,
 *	Kevin King <4kevinking@gmail.com>
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

#ifndef SRC_CORE_LIB_ENCODING_SIGNEDINTPLAINTEXTENCODING_H_
#define SRC_CORE_LIB_ENCODING_SIGNEDINTPLAINTEXTENCODING_H_

#include "inttypes.h"
#include <vector>
#include <initializer_list>
#include "plaintext.h"

namespace lbcrypto {

class SignedIntPlaintextEncoding : public Plaintext, public std::vector<int32_t> {
public:
	SignedIntPlaintextEncoding(std::vector<int32_t>::const_iterator sIter, std::vector<int32_t>::const_iterator eIter)
		: std::vector<int32_t>(std::vector<int32_t>(sIter, eIter)) {}

	SignedIntPlaintextEncoding(const std::vector<int32_t> &rhs) : std::vector<int32_t>(rhs) {}

	SignedIntPlaintextEncoding(std::initializer_list<int32_t> arr) : std::vector<int32_t>(arr) {}

    SignedIntPlaintextEncoding() : std::vector<int32_t>() {}

	/** Interface for the operation of converting from current plaintext encoding to Poly.
	*
	* @param  modulus - used for encoding.
	* @param  *ilVector encoded plaintext - output argument.
	*/
	void Encode(const BigInteger &modulus, Poly *ilVector, size_t start_from=0, size_t length=0) const;

	/** Interface for the operation of converting from Poly to current plaintext encoding.
	*
	* @param  modulus - used for encoding.
	* @param  *ilVector encoded plaintext - input argument.
	*/
	void Decode(const BigInteger &modulus, Poly *ilVector);

	void Unpad(const BigInteger &modulus) {} // a null op; no padding in int

	size_t GetChunksize(const usint ring, const BigInteger& ptm) const;

	size_t GetLength() const { return this->size(); }

	bool CompareTo(const Plaintext& other) const {
		const std::vector<int32_t>& lv = dynamic_cast<const std::vector<int32_t>&>(*this);
		const std::vector<int32_t>& rv = dynamic_cast<const std::vector<int32_t>&>(other);
		return lv == rv;
	}

	friend std::ostream& operator<<(std::ostream& out, const SignedIntPlaintextEncoding& item) {
		for( size_t i=0; i<item.size(); i++ )
			out << "\t" << item.at(i);
		return out;
	}

private:
    template <typename IntType, typename VecType, typename Element>
	void doEncode(const BigInteger &modulus, Element *ilVector, size_t start_from, size_t length) const;

    template <typename IntType, typename VecType, typename Element>
	void doDecode(const BigInteger &modulus, Element *ilVector);
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_SIGNEDINTPLAINTEXTENCODING_H_ */
