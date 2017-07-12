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

namespace lbcrypto {

	template<typename BigInteger>
	class BigIntegerInterface
	{
	public:

		//Constructors - cannot be added to the Interface directly

		/**
		 * Basic constructor.	  	  
		 */
		// BigInteger() = 0;

		/**
		 * Basic constructor for initializing big binary integer from an unsigned integer.
		 *
		 * @param init is the initial integer.	  	  
		 */
		// explicit BigInteger(usint init);

		/**
		 * Basic constructor for specifying the integer.
		 *
		 * @param str is the initial integer represented as a string.	  	  
		 */
		// explicit BigInteger(const std::string& str);

		/**
		 * Basic constructor for copying a big binary integer
		 *
		 * @param bigInteger is the big binary integer to be copied.  	  
		 */
		// explicit BigInteger(const BigInteger& bigInteger);

		/**
		 * Basic constructor for move copying a big binary integer
		 *
		 * @param &&bigInteger is the big binary integer to be copied.  	  
		 */
		// BigInteger(BigInteger &&bigInteger);//move copy constructor


		/**
		 * ???
		 *
		 * @param &rhs is the big binary integer to test equality with.  
		 * @return the return value.	  
		 */
		virtual BigInteger& operator=(const BigInteger &rhs) = 0;

		/**
		 * ???
		 *
		 * @param &&rhs is the big binary integer to test equality with.  
		 * @return the return value.	  
		 */
		virtual BigInteger&  operator=(BigInteger &&rhs) = 0;

		/**
		 * Destructor.	  
		 */
		// ~BigInteger();

		//ACCESSORS

		/**
		 * Basic set method for setting the value of a big binary integer
		 *
		 * @param str is the string representation of the big binary integer to be copied.  	  
		 */
		virtual void SetValue(const std::string& str) = 0;

		//METHODS

		////regular aritmethic operations

		/**
		 * Addition operation.
		 *
		 * @param b is the value to add.
		 * @return is the result of the addition operation.
		 */
		virtual BigInteger Plus(const BigInteger& b) const = 0;

		///**
		// * Subtraction operation.
		// *
		// * @param b is the value to subtract.
		// * @return is the result of the subtraction operation.
		// */
		virtual BigInteger Minus(const BigInteger& b) const = 0;

		///**
		// * Multiplication operation.
		// *
		// * @param b is the value to multiply with.
		// * @return is the result of the multiplication operation.
		// */
		virtual BigInteger Times(const BigInteger& b) const = 0;

		///**
		// * Division operation.
		// *
		// * @param b is the value to divide by.
		// * @return is the result of the division operation.
		// */
		virtual BigInteger DividedBy(const BigInteger& b) const = 0;

		//modular arithmetic operations

		/**
		 * returns the modulus with respect to the input value.
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus operation.
		 */
		virtual BigInteger Mod(const BigInteger& modulus) const = 0;

		//Barrett modular reduction algorithm - used in NTT

		/**
		 * returns the Barret modulus with respect to the input modulus and the Barrett value.
		 *
		 * @param modulus is the modulus to perform.
		 * @param mu is the Barrett value.
		 * @return is the result of the modulus operation.
		 */
		virtual BigInteger ModBarrett(const BigInteger& modulus, const BigInteger& mu) const = 0;

		/**
		 * returns the modulus inverse with respect to the input value.
		 *
		 * @param modulus is the modulus to perform.
		 * @return is the result of the modulus inverse operation.
		 */
		virtual BigInteger ModInverse(const BigInteger& modulus) const = 0;

		/**
		 * Scalar modulus addition.
		 *
		 * @param &b is the scalar to add.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus addition operation.
		 */
		virtual BigInteger ModAdd(const BigInteger& b, const BigInteger& modulus) const = 0;

		/**
		 * Scalar modulus subtraction.
		 *
		 * @param &b is the scalar to subtract.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus subtraction operation.
		 */
		virtual BigInteger ModSub(const BigInteger& b, const BigInteger& modulus) const = 0;

		/**
		 * Scalar modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual BigInteger ModMul(const BigInteger& b, const BigInteger& modulus) const = 0;

		/**
		 * Scalar Barrett modulus multiplication.
		 *
		 * @param &b is the scalar to multiply.
		 * @param modulus is the modulus to perform operations with.
		 * @param mu is the Barrett value.
		 * @return is the result of the modulus multiplication operation.
		 */
		virtual BigInteger ModBarrettMul(const BigInteger& b, const BigInteger& modulus,const BigInteger& mu) const = 0;

		/**
		 * Scalar modulus exponentiation.
		 *
		 * @param &b is the scalar to exponentiate at all locations.
		 * @param modulus is the modulus to perform operations with.
		 * @return is the result of the modulus exponentiation operation.
		 */
		virtual BigInteger ModExp(const BigInteger& b, const BigInteger& modulus) const = 0;

		/**
		 * Addition accumulator.
		 *
		 * @param &b is the value to add.
		 * @return is the result of the addition operation.
		 */
		virtual const BigInteger& operator+=(const BigInteger &b) = 0;

		/**
		 * Subtraction accumulator.
		 *
		 * @param &b is the value to subtract.
		 * @return is the result of the subtraction operation.
		 */
		virtual const BigInteger& operator-=(const BigInteger &b) = 0;

		////bit shifting operators

		/**
		 * Left shift operator and creates a new variable as output.
		 *
		 * @param shift is the amount to shift.
		 * @return the result of the shift.	  
		 */
		virtual BigInteger  operator<<(usshort shift) const = 0;

		/**
		 * Right shift operator and creates a new variable as output.
		 *
		 * @param shift is the amount to shift.
		 * @return the result of the shift.	  
		 */
		virtual BigInteger  operator>>(usshort shift) const = 0;

		/**
		 * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
		 *
		 * @param shift is the amount to shift.
		 * @return the result of the shift.	  
		 */
		virtual const BigInteger& operator<<=(usshort shift) = 0;

		/**
		 * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
		 *
		 * @param shift is the amount to shift.
		 * @return the result of the shift.	  
		 */
		virtual const BigInteger& operator>>=(usshort shift) = 0;

		//virtual friend methods are not allowed in abstract classes
		//input/output operators
		/**
		 * ???
		 *
		 * @param os the output stream.
		 * @param &ptr_obj ???.
		 * @return the return value.	  
		 */
		//virtual friend std::ostream& operator<<(std::ostream& os, const BigInteger &ptr_obj);

		/**
		 * Stores the value of this BigInteger in a string object and returns it.
		 * Added by Arnab Deb Gupta <ad479@njit.edu> on 9/21/15.
		 *
		 * @return the value of this BigInteger as a string.
		 */
		virtual std::string ToString() const = 0;

		/**
		 * Returns the MSB location of the value.
		 *
		 * @return the index of the most significant bit.	  
		 */
		virtual usint GetMSB()const = 0;

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
		virtual usint ConvertToInt() const = 0;

		//static methods cannot be added to the interface
		/**
		 * Convert a value from an int to a BigInteger.
		 *
		 * @param the value to convert from.
		 * @return the int represented as a big binary int.	  
		 */
		//static BigInteger intToBigIntegereger(usint m);

		////constant definations

		/**
		 * Constant zero.	  
		 */
		//const static BigInteger ZERO;

		/**
		 * Constant one.	  
		 */
		//const static BigInteger ONE;

		/**
		 * Constant two.	  
		 */
		//const static BigInteger TWO;

		/**
		 * Test equality of the inputs.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the inputs are equal.	  
		 */
		//friend bool operator==(const BigInteger& a, const BigInteger& b);

		/**
		 * Test inequality of the inputs.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the inputs are inequal.	  
		 */
		//friend bool operator!=(const BigInteger& a, const BigInteger& b);

		/**
		 * Test if first input is great than the second input.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the first inputs is greater.
		 */
		//friend bool operator> (const BigInteger& a, const BigInteger& b);

		/**
		 * Test if first input is great than or equal to the second input.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the first inputs is greater than or equal to the second input.
		 */
		//friend bool operator>=(const BigInteger& a, const BigInteger& b);

		/**
		 * Test if first input is less than the second input.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the first inputs is lesser.
		 */
		//friend bool operator< (const BigInteger& a, const BigInteger& b);

		/**
		 * Test if first input is less than or equal to the second input.
		 *
		 * @param a first value to test.
		 * @param b second value to test.
		 * @return true if the first inputs is less than or equal to the second input.
		 */
		//friend bool operator<=(const BigInteger& a, const BigInteger& b);

	}; 

	//overloaded binary operators based on integer arithmetic and comparison functions
	/**
		* Addition operation.
		*
		* @param a is the value to add.
		* @param b is the value to add.
		* @return is the result of the addition operation.
	*/
	//inline BigIntegeregerInterface operator+(const BigIntegeregerInterface &a, const BigIntegeregerInterface &b) {return a.Plus(b);}

	/**
		* Subtraction operation.
		*
		* @param a is the value to subtract from.
		* @param b is the value to subtract.
		* @return is the result of the subtraction operation.
	*/
	//inline BigIntegeregerInterface operator-(const BigIntegeregerInterface &a, const BigIntegeregerInterface &b) {return a.Minus(b);}

	/**
		* Multiplication operation.
		*
		* @param a is the value to multiply with.
		* @param b is the value to multiply with.
		* @return is the result of the multiplication operation.
	*/
	//inline BigIntegeregerInterface operator*(const BigIntegeregerInterface &a, const BigIntegeregerInterface &b) {return a.Times(b);}

	/**
		* Division operation.
		*
		* @param a is the value to divide.
		* @param b is the value to divide by.
		* @return is the result of the division operation.
	*/
	//inline BigIntegeregerInterface operator/(const BigIntegeregerInterface &a, const BigIntegeregerInterface &b) {return a.DividedBy(b);}


	class BigVectorInterface{}; //will be defined later; all methods will be pure virtual
	class BigMatrixInterface{}; //will be defined later; all methods will be pure virtual

} // namespace lbcrypto ends

#endif
