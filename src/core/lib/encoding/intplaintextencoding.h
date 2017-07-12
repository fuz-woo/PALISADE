/**
 * @file intplaintextencoding.h Represents and defines plaintext objects in Palisade that encodes integers.
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
#ifndef LBCRYPTO_UTILS_INTPLAINTEXTENCODING_H
#define LBCRYPTO_UTILS_INTPLAINTEXTENCODING_H

#include "inttypes.h"
#include <vector>
#include <initializer_list>
#include "plaintext.h"

namespace lbcrypto
{

/**
 * @class IntPlaintextEncoding
 * @brief Type used for representing IntArray types.
 * Provides conversion functions to encode and decode plaintext data as type vector<uint32_t>.
 */
class IntPlaintextEncoding : public Plaintext, public std::vector<uint32_t>
{
public:

	/**
	 * @brief Constructor method.
	 * Constructs a container with as many elements as the range [first,last),
	 * with each element emplace-constructed
	 * from its corresponding element in that range, in the same order.
	 * @param sIter Input iterators to the initial and final positions in a range.
	 * The range used is [first,last), which includes all the elements between first
	 * and last, including the element pointed by first but not the element pointed by last.
	 * The function template argument InputIterator shall be an input iterator type that
	 * points to elements of a type from which value_type objects can be constructed.
	 * @param eIter Input iterators to the initial and final positions in a range.
	 * The range used is [first,last), which includes all the elements between first
	 * and last, including the element pointed by first but not the element pointed by last.
	 * The function template argument InputIterator shall be an input iterator type that
	 * points to elements of a type from which value_type objects can be constructed.
	 */
	IntPlaintextEncoding(std::vector<uint32_t>::const_iterator sIter, std::vector<uint32_t>::const_iterator eIter)
		: std::vector<uint32_t>(std::vector<uint32_t>(sIter, eIter)) {}
	/**
	 * @brief Constructs a container with a copy of each of the elements in rhs, in the same order.
	 * @param rhs - The input object to copy.
	 */
	IntPlaintextEncoding(const std::vector<uint32_t> &rhs) : std::vector<uint32_t>(rhs) {}

	/**
	 * @brief Constructs a container with a copy of each of the elements in il, in the same order.
	 * @param arr the list to copy.
	 */
	IntPlaintextEncoding(std::initializer_list<uint32_t> arr) : std::vector<uint32_t>(arr) {}

	/** Forms a binary array from an integer;
	 * Represents the integer as a binary polynomial
	 *
	 * @param  value - integer to be converted to binary polynomial representation
	 */
	IntPlaintextEncoding(uint32_t value);

	/**
	 * @brief Default empty constructor with empty uninitialized data elements.
	 */
	IntPlaintextEncoding() : std::vector<uint32_t>() {}

	/**
	 * Interface for the operation of converting from current plaintext encoding to Poly.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - output argument.
	 * @param  start_from - location to start from.  Defaults to 0.
	 * @param  length - length of data to encode.  Defaults to 0.
	*/
	void Encode(const BigInteger &modulus, Poly *ilVector, size_t start_from=0, size_t length=0) const;

	/**
	 * Interface for the operation of converting from Poly to current plaintext encoding.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - input argument.
	 */
	void Decode(const BigInteger &modulus, Poly *ilVector);

	/**
	 * Interface for the operation of stripping away unneeded trailing zeros to pad out a short plaintext until one with entries
	 * for all dimensions.
	 *
	 * @param  &modulus - used for encoding.
	 */
	void Unpad(const BigInteger &modulus) {} // a null op; no padding in int

	/**
	 * Getter for the ChunkSize data.
	 *
	 * @param  ring - the ring dimension.
	 * @param  ptm - the plaintext modulus.
	 * @return ring - the chunk size.
	 */
	size_t GetChunksize(const usint ring, const BigInteger& ptm) const;

	/**
	 * Get method to return the length of plaintext
	 *
	 * @return the length of the plaintext in terms of the number of bits.
	 */
	size_t GetLength() const {
		return this->size();
	}

	/**
	 * Method to compare two plaintext to test for equivalence.  This method does not test that the plaintext are of the same type.
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const Plaintext& other) const {
		const std::vector<uint32_t>& lv = dynamic_cast<const std::vector<uint32_t>&>(*this);
		const std::vector<uint32_t>& rv = dynamic_cast<const std::vector<uint32_t>&>(other);
		return lv == rv;
	}

	/**
	 * Evaluates the array of integers as a polynomial at x = 2.
	 *  Used together with IntPlaintextEncoding(uint32_t)
	 *
	 * @param  modulus - the modulus that is used to represend the unsigned coefficients
	 */
	int32_t EvalToInt(uint32_t modulus) const;

	/**
	 * Output stream operator.
	 *
	 * @param out - the output stream.
	 * @param item - the int plaintext to encode with.
	 * @return an output stream.
	 */
	friend std::ostream& operator<<(std::ostream& out, const IntPlaintextEncoding& item) {
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

}

#endif
