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
		virtual ~BigIntegerInterface() {}

		// CONSTRUCTORS

		// Constructors must be implemented in the derived classes
		// There are no base class constructors that need to be called

		// The derived classes should implement constructors from integers and strings
		// There should be copy and move constructors, as well as copy and move assignment

		// ACCESSORS

		/**
		 * Set from a string
		 *
		 * @param str is the string representation of the value
		 */
		virtual void SetValue(const std::string& str) = 0;

		//// ADDITION

		/**
		 * + operation.
		 *
		 * @param b is the value to add.
		 * @return result of the addition
		 */
		virtual T Plus(const T& b) const = 0;

		/**
		 * += operation.
		 *
		 * @param b is the value to add.
		 * @return reference the result of the addition
		 */
		virtual const T& PlusEq(const T& b) = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * @param &b is the scalar to add.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus addition operation.
		 */
		virtual T ModAdd(const T& b, const T& modulus) const = 0;

		/**
		 * Scalar modulus= addition.
		 *
		 * @param &b is the scalar to add.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus addition operation.
		 */
		virtual const T& ModAddEq(const T& b, const T& modulus) = 0;

		friend T operator+(const T& a, const T& b) { return a.Plus(b); }
		const T& operator+=(const T& b) { return this->PlusEq(b); }

		//// SUBTRACTION

		/**
		 * - operation.
		 *
		 * @param b is the value to subtract.
		 * @return is the result of the subtraction operation.
		 */
		virtual T Minus(const T& b) const = 0;

		/**
		 * -= operation.
		 *
		 * @param b is the value to subtract.
		 * @return is the result of the subtraction operation.
		 */
		virtual const T& MinusEq(const T& b) = 0;

		/**
		 * Scalar modulus subtraction.
		 *
		 * @param &b is the scalar to subtract.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus subtraction operation.
		 */
		virtual T ModSub(const T& b, const T& modulus) const = 0;

		/**
		 * Scalar modulus= subtraction.
		 *
		 * @param &b is the scalar to subtract.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus subtraction operation.
		 */
		virtual const T& ModSubEq(const T& b, const T& modulus) = 0;

		friend T operator-(const T& a, const T& b) { return a.Minus(b); }
		const T& operator-=(const T& b) { return this->MinusEq(b); }

		//// MULTIPLICATION

		/**
		 * * operation.
		 *
		 * @param b is the value to multiply with.
		 * @return is the result of the multiplication operation.
		 */
		virtual T Times(const T& b) const = 0;

		/**
		 * *= operation.
		 *
		 * @param b is the value to multiply with.
		 * @return is the result of the multiplication operation.
		 */
		virtual const T& TimesEq(const T& b) = 0;

		/**
		 * Scalar modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual T ModMul(const T& b, const T& modulus) const = 0;

		/**
		 * Scalar modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual const T& ModMulEq(const T& b, const T& modulus) = 0;

		friend T operator*(const T& a, const T& b) { return a.Times(b); }
		const T& operator*=(const T& b) { return this->TimesEq(b); }

		//// DIVISION

		/**
		 * / operation.
		 *
		 * @param b is the value to divide by.
		 * @return is the result of the division operation.
		 */
		virtual T DividedBy(const T& b) const = 0;

		/**
		 * /= operation.
		 *
		 * @param b is the value to divide by.
		 * @return is the result of the division operation.
		 */
		virtual const T& DividedByEq(const T& b) = 0;

		friend T operator/(const T& a, const T& b) { return a.DividedBy(b); }
		const T& operator/=(const T& b) { return this->DividedByEq(b); }

		//// MODULUS

		/**
		 * % operation
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus operation.
		 */
		virtual T Mod(const T& modulus) const = 0;

		/**
		 * %= operation
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus operation.
		 */
		virtual const T& ModEq(const T& modulus) = 0;

		friend T operator%(const T& a, const T& b) { return a.Mod(b); }
		const T& operator%=(const T& b) { return this->ModEq(b); }

		/**
		 * Scalar modulus exponentiation.
		 *
		 * @param &b is the scalar to exponentiate at all locations.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus exponentiation operation.
		 */
		virtual T ModExp(const T& b, const T& modulus) const = 0;
			// FIXME there is no ModExpEq -- is it needed?

		/**
		 * returns the modulus inverse with respect to the input value.
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus inverse operation.
		 */
		virtual T ModInverse(const T& modulus) const = 0;
			// FIXME there is no ModInverseEq -- is it needed?

		/**
		 * returns the Barrett modulus with respect to the input modulus and the Barrett value.
		 *
		 * @param modulus is the modulus to perform.
		 * @param mu is the Barrett value.
		 * @return is the result of the modulus operation.
		 */
		virtual T ModBarrett(const T& modulus, const T& mu) const = 0;
			// FIXME there is no ModBarrettEq -- is it needed?

		/**
		 * Scalar Barrett modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @param mu is the Barrett value.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual T ModBarrettMul(const T& b, const T& modulus,const T& mu) const = 0;
			// FIXME there is no ModBarrettMulEq -- is it needed?

		////bit shifting operators

		/**
		 * << operation
		 *
		 * @param shift # of bits
		 * @return result of the shift operation.
		 */
		virtual T LShift(usshort shift) const = 0;

		/**
		 * <<= operation
		 *
		 * @param shift # of bits
		 * @return result of the shift operation.
		 */
		virtual const T& LShiftEq(usshort shift) = 0;

		friend T operator<<(const T& a, usshort shift) { return a.LShift(shift); }
		const T& operator<<=(usshort shift) { return this->LShiftEq(shift); }

		/**
		 * >> operation
		 *
		 * @param shift # of bits
		 * @return result of the shift operation.
		 */
		virtual T RShift(usshort shift) const = 0;

		/**
		 * >>= operation
		 *
		 * @param shift # of bits
		 * @return result of the shift operation.
		 */
		virtual const T& RShiftEq(usshort shift) = 0;

		friend T operator>>(const T& a, usshort shift) { return a.RShift(shift); }
		const T& operator>>=(usshort shift) { return this->RShiftEq(shift); }

		// The derived classes MAY implement std::ostream& operator<< but are not required to

		/**
		 * Convert this integer into a std::string, for serialization
		 *
		 * @return the value of this T as a string.
		 */
		virtual const std::string ToString() const = 0;

		/**
		 * Returns the MSB location of the value.
		 *
		 * @return the index of the most significant bit.	  
		 */
		virtual usint GetMSB() const = 0;

		/**
		 * Get the number of digits using a specific base - support for arbitrary base may be needed.
		 *
		 * @param base is the base with which to determine length in.
		 * @return the length of the representation in a specific base.	  
		 */
		virtual usint GetLengthForBase(usint base) const = 0;

		/**
		 * Get the number of digits using a specific base - support for arbitrary base may be needed.
		 *
		 * @param index is the location to return value from in the specific base.
		 * @param base is the base with which to determine length in.
		 * @return the length of the representation in a specific base.	  
		 */
		virtual usint GetDigitAtIndexForBase(usint index, usint base) const = 0;

		/**
		 * Convert the value to an int.
		 *
		 * @return the int representation of the value.	  
		 */
		virtual uint64_t ConvertToInt() const = 0;

		/**
	    * Compares the current BigInteger to BigInteger a.
	    *
	    * @param a is the BigInteger to be compared with.
	    * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
	    */
	    virtual int Compare(const T& a) const = 0;

		//// relational operators, using Compare
	    bool operator==(const T& b) const {return this->Compare(b) == 0;}
	    bool operator!=(const T& b) const {return this->Compare(b) != 0;}

		bool operator> (const T& b) const {return this->Compare(b) >  0;}
		bool operator>=(const T& b) const {return this->Compare(b) >= 0;}
		bool operator< (const T& b) const {return this->Compare(b) <  0;}
		bool operator<=(const T& b) const {return this->Compare(b) <= 0;}
	}; 

	template<typename T, typename I>
	class BigVectorInterface{
public:
		virtual ~BigVectorInterface() {}

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
		virtual const T& operator=(const T& rhs) = 0;

		/**
		* Move assignment operator from Vector
		*
		* @param &&rhs is the native vector to be moved.
		* @return this
		*/
		virtual const T& operator=(T &&rhs) = 0;

		/**
		* Assignment from initializer list of unsigned integers
		*
		* @param &&rhs is the list of integers
		* @return this
		*/
		virtual const T& operator=(std::initializer_list<uint64_t> rhs) = 0;

		/**
		* Assignment from initializer list of strings
		*
		* @param &&rhs is the list of strings
		* @return this
		*/
		virtual const T& operator=(std::initializer_list<std::string> rhs) = 0;

		/**
		 * Assignment to assign value val to first entry, 0 for the rest of entries.
		 * @param val
		 * @return this
		 */
		virtual const T& operator=(uint64_t val) = 0;

		/**
		* Equals to operator
		*
		* @param b is vector to be compared.
		* @return true if equal and false otherwise.
		*/
		bool operator==(const T &b) const {
	        if (this->GetLength() != b.GetLength())
	            return false;
	        if (this->GetModulus() != b.GetModulus())
	        	return false;
	        for (size_t i = 0; i < this->GetLength(); ++i) {
	            if ((*this)[i] != b[i]) {
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
	    bool operator!=(const T &b) const {
	        return !(*this == b);
	    }

		//ACCESSORS

	    // The derived class must implement at and operator[]
		virtual I& at(size_t idx) = 0;
		virtual const I& at(size_t idx) const = 0;
		virtual I& operator[](size_t idx) = 0;
		virtual const I& operator[](size_t idx) const = 0;

		/**
		 * Sets the vector modulus.
		 *
		 * @param value is the value to set.
		 * @param value is the modulus value to set.
		 */
		virtual void SetModulus(const I& value) = 0;

		/**
		 * Sets the vector modulus and changes the values to match the new modulus.
		 *
		 * @param value is the value to set.
		 */
		virtual void SwitchModulus(const I& value) = 0;

		/**
		 * Gets the vector modulus.
		 *
		 * @return the vector modulus.
		 */
		virtual const I& GetModulus() const = 0;

		/**
		 * Gets the vector length.
		 *
		 * @return vector length.
		 */
		virtual usint GetLength() const = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual T ModAdd(const I &b) const = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual const T& ModAddEq(const I &b) = 0;

		/**
		 * Scalar modulus addition at a particular index.
		 *
		 * @param &b is the scalar to add.
		 * @param i is the index of the entry to add.
		 * @return is the result of the modulus addition operation.
		 */
		virtual T ModAddAtIndex(usint i, const I &b) const = 0;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual T ModAdd(const T &b) const = 0;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual const T& ModAddEq(const T &b) = 0;

		// inlines for overloaded operators
		T operator+(const I &b) const { return this->ModAdd(b); }
		const T& operator+=(const I &b) { return this->ModAddEq(b); }
		T operator+(const T &b) const { return this->ModAdd(b); }
		const T& operator+=(const T &b) { return this->ModAddEq(b); }

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual T ModSub(const I &b) const = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * After addition modulus operation is performed with the current vector modulus.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual const T& ModSubEq(const I &b) = 0;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual T ModSub(const T &b) const = 0;

		/**
		 * vector modulus addition.
		 *
		 * @param &b is the vector to add at all locations.
		 * @return a new vector which is the result of the modulus addition operation.
		 */
		virtual const T& ModSubEq(const T &b) = 0;

		// inlines for overloaded operator unary minus
		T operator-() const { return this->ModMul(I(-1)); }

		// inlines for overloaded operators
		T operator-(const I &b) const { return this->ModSub(b); }
		const T& operator-=(const I &b) { return this->ModSubEq(b); }
		T operator-(const T &b) const { return this->ModSub(b); }
		const T& operator-=(const T &b) { return this->ModSubEq(b); }

		/**
		 * Scalar modular multiplication.
		 *
		 * @param &b is the scalar to multiply at all locations.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual T ModMul(const I &b) const = 0;

		/**
		 * Scalar modular multiplication.
		 *
		 * @param &b is the scalar to multiply at all locations.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual const T& ModMulEq(const I &b) = 0;

		/**
		 * Vector modulus multiplication.
		 *
		 * @param &b is the vector to multiply.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual T ModMul(const T &b) const = 0;

		/**
		 * Vector modulus multiplication.
		 *
		 * @param &b is the vector to multiply.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual const T& ModMulEq(const T &b) = 0;

		// inlines for overloaded operators
		T operator*(const I &b) const { return this->ModMul(b); }
		const T& operator*=(const I &b) { return this->ModMulEq(b); }
		T operator*(const T &b) const { return this->ModMul(b); }
		const T& operator*=(const T &b) { return this->ModMulEq(b); }

		/**
		 * Vector Modulus operator.
		 *
		 * @param modulus is the modulus to perform on the current vector entries.
		 * @return a new vector after the modulus operation on current vector.
		 */
		virtual T Mod(const I& modulus) const = 0;
			// FIXME there is no ModEq -- is it needed?

		/**
		 * Scalar modulus exponentiation.
		 *
		 * @param &b is the scalar to exponentiate at all locations.
		 * @return a new vector which is the result of the modulus exponentiation operation.
		 */
		virtual T ModExp(const I& b) const = 0;
			// FIXME there is no ModExpEq -- is it needed?

		/**
		 * Modulus inverse.
		 *
		 * @return a new vector which is the result of the modulus inverse operation.
		 */
		virtual T ModInverse() const = 0;
			// FIXME there is no ModInverseEq -- is it needed?

		//Vector Operations

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return a new vector which is the return value of the modulus by 2, also the least significant bit.
		*/
		virtual T ModByTwo() const = 0;
			// FIXME there is no ModByTwoEq -- is it needed?

		// FIXME this method does not seem to be used -- is it needed?
		/**
		 * Vector multiplication without applying the modulus operation.
		 *
		 * @param &b is the vector to multiply.
		 * @return is the result of the multiplication operation.
		 */
		virtual T MultWithOutMod(const T &b) const = 0;

		/**
		* Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where [] is the rounding operation.
		*
		* @param p is the numerator to be multiplied.
		* @param q is the denominator to be divided.
		* @return the result of multiply and round.
		*/
		virtual T MultiplyAndRound(const I& p, const I& q) const = 0;

		/**
		* Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is the rounding operation.
		*
		* @param q is the denominator to be divided.
		* @return the result of divide and round.
		*/
		virtual T DivideAndRound(const I& q) const = 0;

		/**
		 * Returns a vector of digits at a specific index for all entries for a given number base.
		 *
		 * @param index is the index to return the digit from in all entries.
		 * @param base is the base to use for the operation.
		 * @return is the resulting vector.
		 */
		virtual T GetDigitAtIndexForBase(usint index, usint base) const = 0;
	};

	// TODO
	class BigMatrixInterface{};

} // namespace lbcrypto ends

#endif
