/**
 * @file interface.h This file contains the interfaces for math data types
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
 

#ifndef LBCRYPTO_MATH_INTERFACE_H
#define LBCRYPTO_MATH_INTERFACE_H

#include "utils/inttypes.h"

namespace lbcrypto {

	template<typename T>
	class BigIntegerInterface
	{
	public:
		// CONSTRUCTORS

		// Constructors must be implemented in the derived classes
		// There are no base class constructors that need to be called

		// The derived classes should implement constructors from uint64_t, NativeInteger, and strings
		// There should be copy and move constructors, as well as copy and move assignment

		// ACCESSORS

		/**
		 * Set from a string
		 *
		 * @param str is the string representation of the value
		 */
		void SetValue(const std::string& str);

		//// ADDITION

		/**
		 * + operation.
		 *
		 * @param b is the value to add.
		 * @return result of the addition
		 */
		T Plus(const T& b) const;

		/**
		 * += operation.
		 *
		 * @param b is the value to add.
		 * @return reference the result of the addition
		 */
		const T& PlusEq(const T& b);

		/**
		 * Scalar modulus addition.
		 *
		 * @param &b is the scalar to add.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus addition operation.
		 */
		T ModAdd(const T& b, const T& modulus) const;

		/**
		 * Scalar modulus addition where operands are < modulus
		 *
		 * @param &b is the scalar to add.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus addition operation.
		 */
		T ModAddFast(const T& b, const T& modulus) const;

		/**
		 * Scalar modulus= addition.
		 *
		 * @param &b is the scalar to add.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus addition operation.
		 */
		const T& ModAddEq(const T& b, const T& modulus);

		inline friend T operator+(const T& a, const T& b) { return a.Plus(b); }
		inline friend const T& operator+=(T& a, const T& b) { return a.PlusEq(b); }

		//// SUBTRACTION

		/**
		 * - operation.
		 *
		 * @param b is the value to subtract.
		 * @return is the result of the subtraction operation.
		 */
		T Minus(const T& b) const;

		/**
		 * -= operation.
		 *
		 * @param b is the value to subtract.
		 * @return is the result of the subtraction operation.
		 */
		const T& MinusEq(const T& b);

		/**
		 * Scalar modulus subtraction.
		 *
		 * @param &b is the scalar to subtract.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus subtraction operation.
		 */
		T ModSub(const T& b, const T& modulus) const;

		/**
		 * Scalar modulus subtraction where operands are < modulus
		 *
		 * @param &b is the scalar to subtract.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus subtraction operation.
		 */
		T ModSubFast(const T& b, const T& modulus) const;

		/**
		 * Scalar modulus= subtraction.
		 *
		 * @param &b is the scalar to subtract.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus subtraction operation.
		 */
		const T& ModSubEq(const T& b, const T& modulus);

		inline friend T operator-(const T& a, const T& b) { return a.Minus(b); }
		inline friend const T& operator-=(T& a, const T& b) { return a.MinusEq(b); }

		//// MULTIPLICATION

		/**
		 * * operation.
		 *
		 * @param b is the value to multiply with.
		 * @return is the result of the multiplication operation.
		 */
		T Times(const T& b) const;

		/**
		 * *= operation.
		 *
		 * @param b is the value to multiply with.
		 * @return is the result of the multiplication operation.
		 */
		const T& TimesEq(const T& b);

		/**
		 * Scalar modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus multiplication operation.
		 */
		T ModMul(const T& b, const T& modulus) const;

		/**
		 * Scalar modulus multiplication that assumes the operands are < modulus
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus multiplication operation.
		 */
		T ModMulFast(const T& b, const T& modulus) const;

		/**
		 * Scalar modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus multiplication operation.
		 */
		const T& ModMulEq(const T& b, const T& modulus);

		inline friend T operator*(const T& a, const T& b) { return a.Times(b); }
		inline friend const T& operator*=(T& a, const T& b) { return a.TimesEq(b); }

		//// DIVISION

		/**
		 * / operation.
		 *
		 * @param b is the value to divide by.
		 * @return is the result of the division operation.
		 */
		T DividedBy(const T& b) const;

		/**
		 * /= operation.
		 *
		 * @param b is the value to divide by.
		 * @return is the result of the division operation.
		 */
		const T& DividedByEq(const T& b);

		inline friend T operator/(const T& a, const T& b) { return a.DividedBy(b); }
		inline friend const T& operator/=(T& a, const T& b) { return a.DividedByEq(b); }

		//// MODULUS

		/**
		 * % operation
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus operation.
		 */
		T Mod(const T& modulus) const;

		/**
		 * %= operation
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus operation.
		 */
		const T& ModEq(const T& modulus);

		inline friend T operator%(const T& a, const T& b) { return a.Mod(b); }
		inline friend const T& operator%=(T& a, const T& b) { return a.ModEq(b); }

		/**
		 * Scalar modulus exponentiation.
		 *
		 * @param &b is the scalar to exponentiate at all locations.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus exponentiation operation.
		 */
		T ModExp(const T& b, const T& modulus) const;
			// FIXME there is no ModExpEq -- is it needed?

		/**
		 * returns the modulus inverse with respect to the input value.
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus inverse operation.
		 */
		T ModInverse(const T& modulus) const;
			// FIXME there is no ModInverseEq -- is it needed?

		/**
		 * returns the Barrett modulus with respect to the input modulus and the Barrett value.
		 *
		 * @param modulus is the modulus to perform.
		 * @param mu is the Barrett value.
		 * @return is the result of the modulus operation.
		 */
		T ModBarrett(const T& modulus, const T& mu) const;
			// FIXME there is no ModBarrettEq -- is it needed?

		/**
		 * Scalar Barrett modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @param mu is the Barrett value.
		 * @return is the result of the modulus multiplication operation.
		 */
		T ModBarrettMul(const T& b, const T& modulus,const T& mu) const;
			// FIXME there is no ModBarrettMulEq -- is it needed?

		////bit shifting operators

		/**
		 * << operation
		 *
		 * @param shift # of bits
		 * @return result of the shift operation.
		 */
		T LShift(usshort shift) const;

		/**
		 * <<= operation
		 *
		 * @param shift # of bits
		 * @return result of the shift operation.
		 */
		const T& LShiftEq(usshort shift);

		inline friend T operator<<(const T& a, usshort shift) { return a.LShift(shift); }
		inline friend const T& operator<<=(T& a, usshort shift) { return a.LShiftEq(shift); }

		/**
		 * >> operation
		 *
		 * @param shift # of bits
		 * @return result of the shift operation.
		 */
		T RShift(usshort shift) const;

		/**
		 * >>= operation
		 *
		 * @param shift # of bits
		 * @return result of the shift operation.
		 */
		const T& RShiftEq(usshort shift);

		inline friend T operator>>(const T& a, usshort shift) { return a.RShift(shift); }
		inline friend const T& operator>>=(T& a, usshort shift) { return a.RShiftEq(shift); }

		// The derived classes MAY implement std::ostream& operator<< but are not required to

		/**
		 * Convert this integer into a std::string, for serialization
		 *
		 * @return the value of this T as a string.
		 */
		const std::string ToString() const;

		/**
		 * Returns the MSB location of the value.
		 *
		 * @return the index of the most significant bit.	  
		 */
		usint GetMSB() const;

		/**
		 * Get the number of digits using a specific base - support for arbitrary base may be needed.
		 *
		 * @param base is the base with which to determine length in.
		 * @return the length of the representation in a specific base.	  
		 */
		usint GetLengthForBase(usint base) const;

		/**
		 * Get the number of digits using a specific base - support for arbitrary base may be needed.
		 *
		 * @param index is the location to return value from in the specific base.
		 * @param base is the base with which to determine length in.
		 * @return the length of the representation in a specific base.	  
		 */
		usint GetDigitAtIndexForBase(usint index, usint base) const;

		/**
		 * Convert the value to an int.
		 *
		 * @return the int representation of the value.	  
		 */
		uint64_t ConvertToInt() const;

		/**
		 * Compares the current BigInteger to BigInteger a.
		 *
		 * @param a is the BigInteger to be compared with.
		 * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
		 */
		int Compare(const T& a) const;

		//// relational operators, using Compare
		inline friend bool operator==(const T& a, const T& b) {return a.Compare(b) == 0;}
		inline friend bool operator!=(const T& a, const T& b) {return a.Compare(b) != 0;}

		inline friend bool operator> (const T& a, const T& b) {return a.Compare(b) >  0;}
		inline friend bool operator>=(const T& a, const T& b) {return a.Compare(b) >= 0;}
		inline friend bool operator< (const T& a, const T& b) {return a.Compare(b) <  0;}
		inline friend bool operator<=(const T& a, const T& b) {return a.Compare(b) <= 0;}
	}; 

	template<typename T, typename I>
	class BigVectorInterface{
	public:
		typedef I Integer;

		// CONSTRUCTORS

		// Constructors should be implemented in the derived classes
		// The derived classes should implement constructors from initializer lists of integers and strings

		// The following assignment operators must be provided

		/**
		* Assignment operator from Vector
		*
		* @param &rhs is the vector to be assigned from.
		* @return this
		*/
		const T& operator=(const T& rhs);

		/**
		* Move assignment operator from Vector
		*
		* @param &&rhs is the native vector to be moved.
		* @return this
		*/
		const T& operator=(T &&rhs);

		/**
		* Assignment from initializer list of unsigned integers
		*
		* @param &&rhs is the list of integers
		* @return this
		*/
		const T& operator=(std::initializer_list<uint64_t> rhs);

		/**
		* Assignment from initializer list of strings
		*
		* @param &&rhs is the list of strings
		* @return this
		*/
		const T& operator=(std::initializer_list<std::string> rhs);

		/**
		 * Assignment to assign value val to first entry, 0 for the rest of entries.
		 * @param val
		 * @return this
		 */
		const T& operator=(uint64_t val);

		/**
		* Equals to operator
		*
		* @param b is vector to be compared.
		* @return true if equal and false otherwise.
		*/
		friend inline bool operator==(const T& a, const T& b) {
			if (a.GetLength() != b.GetLength())
				return false;
			if (a.GetModulus() != b.GetModulus())
				return false;
			for (size_t i = 0; i < a.GetLength(); ++i) {
				if (a[i] != b[i]) {
					return false;
				}
			}
			return true;
		}

		/**
		* Not equal to operator
		*
		* @param b is vector to be compared.
		* @return true if not equal and false otherwise.
		*/
		friend inline bool operator!=(const T& a, const T& b) {
			return !(a == b);
		}

		//ACCESSORS

		// The derived class must implement at and operator[]
		I& at(size_t idx);
		const I& at(size_t idx) const;
		void atMod(size_t idx, const I &val);
		void atMod(size_t idx, const std::string& val);
		I& operator[](size_t idx);
		const I& operator[](size_t idx) const;

		/**
		 * Sets the vector modulus.
		 *
		 * @param value is the value to set.
		 * @param value is the modulus value to set.
		 */
		void SetModulus(const I& value);

		/**
		 * Sets the vector modulus and changes the values to match the new modulus.
		 *
		 * @param value is the value to set.
		 */
		void SwitchModulus(const I& value);

		/**
		 * Gets the vector modulus.
		 *
		 * @return the vector modulus.
		 */
		const I& GetModulus() const;

		/**
		 * Gets the vector length.
		 *
		 * @return vector length.
		 */
		virtual size_t GetLength() const = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		T ModAdd(const I &b) const;

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		const T& ModAddEq(const I &b);

		/**
		 * Scalar modulus addition at a particular index.
		 *
		 * @param &b is the scalar to add.
		 * @param i is the index of the entry to add.
		 * @return is the result of the modulus addition operation.
		 */
		T ModAddAtIndex(usint i, const I &b) const;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		T ModAdd(const T &b) const;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		const T& ModAddEq(const T &b);

		// inlines for overloaded operators
		inline friend T operator+(const T& a, const I& b) { return a.ModAdd(b); }
		inline friend const T& operator+=(T& a, const I& b) { return a.ModAddEq(b); }
		inline friend T operator+(const T& a, const T& b) { return a.ModAdd(b); }
		inline friend const T& operator+=(T& a, const T& b) { return a.ModAddEq(b); }

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		T ModSub(const I &b) const;

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		const T& ModSubEq(const I &b);

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		T ModSub(const T &b) const;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		const T& ModSubEq(const T &b);

		// inlines for overloaded operator unary minus
		inline friend T operator-(const T& a) { return a.ModMul(I(-1)); }

		// inlines for overloaded operators
		inline friend T operator-(const T& a, const I& b) { return a.ModSub(b); }
		inline friend const T& operator-=(T& a, const I& b) { return a.ModSubEq(b); }
		inline friend T operator-(const T& a, const T& b) { return a.ModSub(b); }
		inline friend const T& operator-=(T& a, const T& b) { return a.ModSubEq(b); }

		/**
		 * Scalar modular multiplication.
		 *
		 * @param &b is the scalar to multiply at all locations.
		 * @return is the result of the modulus multiplication operation.
		 */
		T ModMul(const I &b) const;

		/**
		 * Scalar modular multiplication.
		 *
		 * @param &b is the scalar to multiply at all locations.
		 * @return is the result of the modulus multiplication operation.
		 */
		const T& ModMulEq(const I &b);

		/**
		 * Vector modulus multiplication.
		 *
		 * @param &b is the vector to multiply.
		 * @return is the result of the modulus multiplication operation.
		 */
		T ModMul(const T &b) const;

		/**
		 * Vector modulus multiplication.
		 *
		 * @param &b is the vector to multiply.
		 * @return is the result of the modulus multiplication operation.
		 */
		const T& ModMulEq(const T &b);

		// inlines for overloaded operators
		inline friend T operator*(const T& a, const I& b) { return a.ModMul(b); }
		inline friend const T& operator*=(T& a, const I& b) { return a.ModMulEq(b); }
		inline friend T operator*(const T& a, const T& b) { return a.ModMul(b); }
		inline friend const T& operator*=(T& a, const T& b) { return a.ModMulEq(b); }

		/**
		 * Vector Modulus operator.
		 *
		 * @param modulus is the modulus to perform on the current vector entries.
		 * @return a new vector after the modulus operation on current vector.
		 */
		T Mod(const I& modulus) const;

		/**
		 * Vector Modulus operator.
		 *
		 * @param modulus is the modulus to perform on the current vector entries.
		 * @return a new vector after the modulus operation on current vector.
		 */
		const T& ModEq(const I& modulus);

		/**
		 * Scalar modulus exponentiation.
		 *
		 * @param &b is the scalar to exponentiate at all locations.
		 * @return a new vector which is the result of the modulus exponentiation operation.
		 */
		T ModExp(const I& b) const;
			// FIXME there is no ModExpEq -- is it needed?

		// inlines for overloaded operators
		inline friend T operator%(const T& a, const I& b) { return a.Mod(b); }
		inline friend const T& operator%=(T& a, const I& b) { return a.ModEq(b); }

		/**
		 * Modulus inverse.
		 *
		 * @return a new vector which is the result of the modulus inverse operation.
		 */
		T ModInverse() const;
			// FIXME there is no ModInverseEq -- is it needed?

		//Vector Operations

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return a new vector which is the return value of the modulus by 2, also the least significant bit.
		*/
		T ModByTwo() const;

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return a new vector which is the return value of the modulus by 2, also the least significant bit.
		*/
		const T& ModByTwoEq();

		/**
		* Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where [] is the rounding operation.
		*
		* @param p is the numerator to be multiplied.
		* @param q is the denominator to be divided.
		* @return the result of multiply and round.
		*/
		T MultiplyAndRound(const I& p, const I& q) const;

		/**
		* Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is the rounding operation.
		*
		* @param q is the denominator to be divided.
		* @return the result of divide and round.
		*/
		T DivideAndRound(const I& q) const;

		/**
		 * Returns a vector of digits at a specific index for all entries for a given number base.
		 *
		 * @param index is the index to return the digit from in all entries.
		 * @param base is the base to use for the operation.
		 * @return is the resulting vector.
		 */
		T GetDigitAtIndexForBase(usint index, usint base) const;
	};

	// TODO
	class BigMatrixInterface{};

} // namespace lbcrypto ends

#endif
