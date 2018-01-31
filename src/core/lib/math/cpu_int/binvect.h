/**
 * @file binvect.h This file contains the vector manipulation functionality.
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
/*
 * This file contains the vector manipulation functionality.
 */

#ifndef LBCRYPTO_MATH_CPUINT_BINVECT_H
#define LBCRYPTO_MATH_CPUINT_BINVECT_H

#include <iostream>

#include "../../utils/serializable.h"
#include "../../utils/inttypes.h"
#include "../cpu_int/binint.h"

#include <initializer_list>

/**
 * @namespace cpu8bit
 * The namespace of cpu8bit
 */
namespace cpu_int {
	


/**
 * @brief The class for representing vectors of big binary integers.
 */

template <class IntegerType>
class BigVectorImpl : public lbcrypto::BigVectorInterface<BigVectorImpl<IntegerType>,IntegerType>, public lbcrypto::Serializable
{
public:
	/**
	 * Basic constructor.	  	  
	 */
	BigVectorImpl();

    static inline BigVectorImpl Single(const IntegerType& val, const IntegerType& modulus) {
        BigVectorImpl vec(1, modulus);
        vec[0] = val;
        return vec;
    }

	/**
	 * Basic constructor for specifying the length of the vector and the modulus.
	 *
	 * @param length is the length of the big binary vector, in terms of the number of entries.	
	 * @param modulus is the modulus of the ring.
	 */
	BigVectorImpl(usint length, const IntegerType& modulus = 0);

	/**
	 * Basic constructor for specifying the length of the vector
	 * the modulus and an initializer list.
	 *
	 * @param length is the length of the big binary vector, in terms of the number of entries.	
	 * @param modulus is the modulus of the ring.
	 * @param rhs is an initializer list of usint
	 */
	BigVectorImpl(usint length, const IntegerType& modulus, std::initializer_list<usint> rhs);

	/**
	 * Basic constructor for specifying the length of the vector
	 * the modulus and an initializer list.
	 *
	 * @param length is the length of the big binary vector, in terms of the number of entries.	
	 * @param modulus is the modulus of the ring.
	 * @param rhs is an initializer list of strings
	 */

	BigVectorImpl(usint length, const IntegerType& modulus, std::initializer_list<std::string> rhs);


	/**
	 * Basic constructor for copying a vector
	 *
	 * @param bigVector is the big binary vector to be copied.  	  
	 */
	BigVectorImpl(const BigVectorImpl& bigVector);

	/**
	 * Basic move constructor for moving a vector
	 *
	 * @param &&bigVector is the big binary vector to be moved.  	  
	 */
	BigVectorImpl(BigVectorImpl &&bigVector);//move copy constructor

	/**
	* Assignment operator to assign value from rhs
	*
	* @param &rhs is the big binary vector to be assigned from.
	* @return Assigned BigVectorImpl.	  
	*/
	const BigVectorImpl& operator=(const BigVectorImpl &rhs);

	/**
	* Move assignment operator
	*
	* @param &&rhs is the big binary vector to be moved.
	* @return moved BigVectorImpl object  
	*/
	const BigVectorImpl&  operator=(BigVectorImpl &&rhs);

	/**
	* Initializer list for BigVectorImpl.
	*
	* @param &&rhs is the list of integers to be assigned to the BBV.
	* @return BigVectorImpl object 
	*/
	const BigVectorImpl& operator=(std::initializer_list<uint64_t> rhs);

	/**
	* Initializer list for BigVectorImpl.
	*
	* @param &&rhs is the list of strings containing integers to be assigned to the BBV.
	* @return BigVectorImpl object 
	*/
	const BigVectorImpl& operator=(std::initializer_list<std::string> rhs);

    /**
	* Assignment operator to assign value val to first entry, 0 for the rest of entries.
	*
	* @param val is the value to be assigned at the first entry.
	* @return Assigned BigVectorImpl.
	*/
    const BigVectorImpl& operator=(uint64_t val) {
        this->m_data[0] = val;
    		if( this->m_modulus != 0 )
    			this->m_data[0] %= this->m_modulus;
        for (size_t i = 1; i < GetLength(); ++i) {
            this->m_data[i] = 0;
        }
        return *this;
    }

	/**
	* Destructor.	  
	*/
	virtual ~BigVectorImpl();

	//ACCESSORS

	/**
	* ostream operator to output vector values to console
	*
	* @param os is the std ostream object.
	* @param &ptr_obj is the BigVectorImpl object to be printed.
	* @return std ostream object which captures the vector values.
	*/
	template<class IntegerType_c>
	friend std::ostream& operator<<(std::ostream& os, const BigVectorImpl<IntegerType_c> &ptr_obj) {
		auto len = ptr_obj.m_length;
		os<<"[";
		for(usint i=0;i<len;i++){
			os<< ptr_obj.m_data[i];
			os << ((i == (len-1))?"]":" ");
		}
		return os;
	}

	/**
	 * Sets/gets a value at an index.
	 *
	 * @param index is the index to set a value at.
	 */

	IntegerType& at(size_t i) {
	  if(!this->IndexCheck(i)) {
		  PALISADE_THROW(lbcrypto::palisade_error, "BigVector index out of range");
	  }
	  return this->m_data[i];
	  }

	const IntegerType& at(size_t i) const {
 	  if(!this->IndexCheck(i)) {
		  PALISADE_THROW(lbcrypto::palisade_error, "BigVector index out of range");
	  }
	  return this->m_data[i];
	}

	void atMod(size_t i, const IntegerType &val) {
	  if(!this->IndexCheck(i)) {
		  PALISADE_THROW(lbcrypto::palisade_error, "BigVector index out of range");
	  }
	  this->m_data[i]=val%m_modulus;
	  return;
	}

	void atMod(size_t i, const std::string& val) {
 	  if(!this->IndexCheck(i)) {
		  PALISADE_THROW(lbcrypto::palisade_error, "BigVector index out of range");
	  }
	  IntegerType tmp(val);
	  this->m_data[i]=tmp%m_modulus;
	  return;
	}
	
	/**
	* operators to get a value at an index.
	* @param idx is the index to get a value at.
	* @return is the value at the index.
	*/
	IntegerType& operator[](size_t idx) { return (this->m_data[idx]); }
	const IntegerType& operator[](size_t idx) const { return (this->m_data[idx]); }

	/**
	 * Sets the vector modulus.
	 *
	 * @param value is the value to set.
	 * @param value is the modulus value to set.
	 */
	void SetModulus(const IntegerType& value);

	/**
	 * Sets the vector modulus and changes the values to match the new modulus.
	 *
	 * @param value is the value to set.
	 */
	void SwitchModulus(const IntegerType& value);

	/**
	 * Gets the vector modulus.
	 *
	 * @return the vector modulus.
	 */
	const IntegerType& GetModulus() const { return this->m_modulus; }

	/**
	 * Gets the vector length.
	 *
	 * @return vector length.
	 */
	size_t GetLength() const { return this->m_length; }
	
	//METHODS

	/**
	 * Vector Modulus operator.
	 *
	 * @param modulus is the modulus to perform on the current vector entries.
	 * @return a new vector after the modulus operation on current vector.
	 */
	BigVectorImpl Mod(const IntegerType& modulus) const;
	
	/**
	 * Vector Modulus operator.
	 *
	 * @param modulus is the modulus to perform on the current vector entries.
	 * @return a new vector after the modulus operation on current vector.
	 */
	const BigVectorImpl& ModEq(const IntegerType& modulus);

	//scalar operations

	/**
	 * Scalar modulus addition at a particular index.
	 *
	 * @param &b is the scalar to add.
	 * @param i is the index of the entry to add.
	 * @return is the result of the modulus addition operation.
	 */
	BigVectorImpl ModAddAtIndex(usint i, const IntegerType &b) const;

	/**
	 * Scalar modulus addition.
	 *
	 * After addition modulus operation is performed with the current vector modulus.
	 * @return a new vector which is the result of the modulus addition operation.
	 */
	BigVectorImpl ModAdd(const IntegerType &b) const;	

	/**
	 * Scalar modulus addition.
	 *
	 * After addition modulus operation is performed with the current vector modulus.
	 * @return a new vector which is the result of the modulus addition operation.
	 */
	const BigVectorImpl& ModAddEq(const IntegerType &b);

	/**
	 * Scalar modulus subtraction.
	 * After substraction modulus operation is performed with the current vector modulus.
	 * @param &b is the scalar to subtract from all locations.
	 * @return a new vector which is the result of the modulus substraction operation.
	 */
	BigVectorImpl ModSub(const IntegerType &b) const;

	/**
	 * Scalar modulus subtraction.
	 * After substraction modulus operation is performed with the current vector modulus.
	 * @param &b is the scalar to subtract from all locations.
	 * @return a new vector which is the result of the modulus substraction operation.
	 */
	const BigVectorImpl& ModSubEq(const IntegerType &b);

	/**
	 * Scalar modular multiplication. Generalized Barrett modulo reduction algorithm. 
	 * See the comments in the cpp files for details of the implementation.
	 *
	 * @param &b is the scalar to multiply at all locations.
	 * @return is the result of the modulus multiplication operation.
	 */
	BigVectorImpl ModMul(const IntegerType &b) const;

	/**
	 * Scalar modular multiplication. Generalized Barrett modulo reduction algorithm.
	 * See the comments in the cpp files for details of the implementation.
	 *
	 * @param &b is the scalar to multiply at all locations.
	 * @return is the result of the modulus multiplication operation.
	 */
	const BigVectorImpl& ModMulEq(const IntegerType &b);

	/**
	 * Scalar modulus exponentiation.
	 *
	 * @param &b is the scalar to exponentiate at all locations.
	 * @return a new vector which is the result of the modulus exponentiation operation.
	 */
	BigVectorImpl ModExp(const IntegerType &b) const;
	//BigVectorImpl& ScalarExp(const BigInteger &a) const;
	

	/**
	 * Modulus inverse.
	 *
	 * @return a new vector which is the result of the modulus inverse operation.
	 */
	BigVectorImpl ModInverse() const;

	//Vector Operations

	//component-wise addition
	/**
	 * vector modulus addition.
	 *
	 * @param &b is the vector to add at all locations.
	 * @return a new vector which is the result of the modulus addition operation.
	 */
	BigVectorImpl ModAdd(const BigVectorImpl &b) const;

	/**
	 * vector modulus addition.
	 *
	 * @param &b is the vector to add at all locations.
	 * @return a new vector which is the result of the modulus addition operation.
	 */
	const BigVectorImpl& ModAddEq(const BigVectorImpl &b);

	/**
	* Perform a modulus by 2 operation.  Returns the least significant bit.
	*
	* @return a new vector which is the return value of the modulus by 2, also the least significant bit.
	*/
	BigVectorImpl ModByTwo() const;

	/**
	* Perform a modulus by 2 operation.  Returns the least significant bit.
	*
	* @return a new vector which is the return value of the modulus by 2, also the least significant bit.
	*/
	const BigVectorImpl& ModByTwoEq();

	//component-wise subtraction

	/**
	 * Vector Modulus subtraction.
	 *
	 * @param &b is the vector to subtract.
	 * @return a new vector which is the result of the modulus subtraction operation.
	 */
	BigVectorImpl ModSub(const BigVectorImpl &b) const;

	/**
	 * Vector Modulus subtraction.
	 *
	 * @param &b is the vector to subtract.
	 * @return a new vector which is the result of the modulus subtraction operation.
	 */
	const BigVectorImpl& ModSubEq(const BigVectorImpl &b);

	//component-wise multiplication

	/**
	 * Vector modulus multiplication.
	 *
	 * @param &b is the vector to multiply.
	 * @return is the result of the modulus multiplication operation.
	 */
	BigVectorImpl ModMul(const BigVectorImpl &b) const;

	/**
	 * Vector modulus multiplication.
	 *
	 * @param &b is the vector to multiply.
	 * @return is the result of the modulus multiplication operation.
	 */
	const BigVectorImpl& ModMulEq(const BigVectorImpl &b);

	/**
	 * Vector multiplication without applying the modulus operation.
	 *
	 * @param &b is the vector to multiply.
	 * @return is the result of the multiplication operation.
	 */
	BigVectorImpl MultWithOutMod(const BigVectorImpl &b) const;

	/**
	* Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where [] is the rounding operation.
	*
	* @param p is the numerator to be multiplied.
	* @param q is the denominator to be divided.
	* @return the result of multiply and round.
	*/
	BigVectorImpl MultiplyAndRound(const IntegerType &p, const IntegerType &q) const;

	/**
	* Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is the rounding operation.
	*
	* @param q is the denominator to be divided.
	* @return the result of divide and round.
	*/
	BigVectorImpl DivideAndRound(const IntegerType &q) const;

	//matrix operations
	
	//matrix product - used in FFT and IFFT; new_vector = A*this_vector

	/**
	 * Returns a vector of digits at a specific index for all entries for a given number base.
	 *
	 * @param index is the index to return the digit from in all entries.
	 * @param base is the base to use for the operation.
	 * @return is the resulting vector.
	 */
	BigVectorImpl GetDigitAtIndexForBase(usint index, usint base) const;


	/**
	* Serialize the object into a Serialized
	* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	* @return true if successfully serialized
	*/
	bool Serialize(lbcrypto::Serialized* serObj) const;

	/**
	* Populate the object from the deserialization of the Serialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	bool Deserialize(const lbcrypto::Serialized& serObj);

private:
	//m_data is a pointer to the vector
	IntegerType *m_data;
	//m_length stores the length of the vector
	usint m_length;
	//m_modulus stores the internal modulus of the vector.
	IntegerType m_modulus = 0;

	//function to check if the index is a valid index.
	bool IndexCheck(size_t length) const {
		if(length>this->m_length)
			return false;
		return true;
	}
};

extern template class BigVectorImpl<BigInteger<integral_dtype,BigIntegerBitLength>>;

//template<typename IntegerType>
//inline BigVectorImpl<IntegerType> operator-(const BigVectorImpl<IntegerType> &a) { return BigVectorImpl<IntegerType>(0) - a; }

//BINARY OPERATORS

///**
// * Modulus scalar addition.
// *
// * @param &a is the input vector to add.
// * @param &i is the input integer to add at all entries.
// * @return a new vector which is the result of the modulus addition operation.
// */
//template<class IntegerType>
//inline BigVectorImpl<IntegerType> operator+(const BigVectorImpl<IntegerType> &a, const IntegerType &i) {return a.ModAdd(i);}

///**
//* Modulus scalar substraction.
//*
//* @param &a is the input vector to substract from.
//* @param &i is the input integer to substract at all entries.
//* @return a new vector which is the result of the modulus substraction operation.
//*/
//template<class IntegerType>
//inline BigVectorImpl<IntegerType> operator-(const BigVectorImpl<IntegerType> &a, const IntegerType &i) {return a.ModSub(i);}

///**
// * Modulus scalar multiplication.
// *
// * @param &a is the input vector to multiply.
// * @param &i is the input integer to multiply at all entries.
// * @return a new vector which is the result of the modulus multiplication operation.
// */
//template<class IntegerType>
//inline BigVectorImpl<IntegerType> operator*(const BigVectorImpl<IntegerType> &a, const IntegerType &i) {return a.ModMul(i);}
//
///**
// * Modulus vector addition.
// *
// * @param &a is the first input vector to add.
// * @param &b is the second input vector to add.
// * @return is the result of the modulus addition operation.
// */
//template<class IntegerType>
//inline BigVectorImpl<IntegerType> operator+(const BigVectorImpl<IntegerType> &a, const BigVectorImpl<IntegerType> &b) {return a.ModAdd(b);}


///**
// * Modulus vector substraction.
// *
// * @param &a is the first input vector.
// * @param &b is the second input vector.
// * @return is the result of the modulus substraction operation.
// */
// template<class IntegerType>
// inline BigVectorImpl<IntegerType> operator-(const BigVectorImpl<IntegerType> &a, const BigVectorImpl<IntegerType> &b) {return a.ModSub(b);}
 
// /**
//  * Modulus vector multiplication.
//  *
//  * @param &a is the first input vector to multiply.
//  */
// template<class IntegerType>
// inline BigVectorImpl<IntegerType> operator*(const BigVectorImpl<IntegerType> &a, const BigVectorImpl<IntegerType> &b) {return a.ModMul(b);}


} // namespace lbcrypto ends

#endif
