/**
 * @file binint.h This file contains the main class for native integers.
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
 * This file contains the main class for native integers.
 * It implements the same methods as other mathematical backends.
 */

#ifndef LBCRYPTO_MATH_NATIVE_BININT_H
#define LBCRYPTO_MATH_NATIVE_BININT_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <limits>
#include <fstream>
#include <stdexcept>
#include <functional>
#include <cstdlib>
#include <memory>
#include "../interface.h"
#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include "../../utils/memory.h"
#include "../../utils/palisadebase64.h"
#include "../../utils/exception.h"
#include "../nbtheory.h"

namespace native_int {

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template<typename utype>
struct DoubleDataType{
	typedef void T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 64 bit if integral datatype is 32bit
 */
template<>
struct DoubleDataType<uint32_t>{
	typedef uint64_t T;
};

/**
* @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
* sets T as of type unsigned integer 128 bit if integral datatype is 64bit
*/
template<>
struct DoubleDataType<uint64_t>{
	typedef unsigned __int128 T;
};

const double LOG2_10 = 3.32192809;	//!< @brief A pre-computed constant of Log base 2 of 10.
const usint BARRETT_LEVELS = 8;		//!< @brief The number of levels (precomputed values) used in the Barrett reductions.


/**
 * @brief Main class for big integers represented as an array of native (primitive) unsigned integers
 * @tparam uint_type native unsigned integer type
 * @tparam BITLENGTH maximum bitdwidth supported for big integers
 */
template<typename uint_type>
class NativeInteger : public lbcrypto::BigIntegerInterface<NativeInteger<uint_type>>
{

public:
	/**
	 * Default constructor.
	 */
	NativeInteger() : m_value(0) {}

	/**
	 * Basic constructor for specifying the integer.
	 *
	 * @param str is the initial integer represented as a string.
	 */
	NativeInteger(const std::string& str) {
		AssignVal(str);
	}

	/**
	 * Basic constructor for initializing from an unsigned integer.
	 *
	 * @param init is the initial integer.
	 */
	NativeInteger(const uint_type& init) : m_value(init) {}

	/**
	 * Basic constructor for copying 
	 *
	 * @param bigInteger is the integer to be copied.
	 */
	NativeInteger(const NativeInteger& nInteger) : m_value(nInteger.m_value) {}

	/**
	 * Assignment operator
	 *
	 * @param &rhs is the integer to be assigned from.
	 * @return assigned ref.
	 */
	const NativeInteger&  operator=(const NativeInteger &rhs) {
		this->m_value = rhs.m_value;
		return *this;
	}

	/**
	 * Assignment operator
	 *
	 * @param &rhs is the integer to be assigned from.
	 * @return assigned BigInteger ref.
	 */
	const NativeInteger&  operator=(const NativeInteger &&rhs) {
		this->m_value = rhs.m_value;
		return *this;
	}

	/**
	 * Assignment operator from unsigned integer
	 *
	 * @param val is the unsigned integer value that is assigned.
	 * @return the assigned BigInteger ref.
	 */
	const NativeInteger& operator=(const uint_type& val) {
		this->m_value = val;
		return *this;
	}

	vector<NativeInteger> GetInternalRepresentation() {
	  vector<NativeInteger> ret;
	  ret.push_back(m_value);
	  return ret;
	}

	/**
	 * Basic set method for setting the value of an integer
	 *
	 * @param str is the string representation of the integer to be copied.
	 */
	void SetValue(const std::string& str) {
		AssignVal(str);
	}

	/**
	 * Basic set method for setting the value of an integer
	 *
	 * @param a is the big binary integer representation of the big binary integer to be assigned.
	 */
	void SetValue(const NativeInteger& a) {
		m_value = a.m_value;
	}


	/**
	 * Returns the MSB location of the value.
	 *
	 * @return the index of the most significant bit.
	 */
	usint GetMSB() const { return lbcrypto::GetMSB64(this->m_value); }

	/**
	 * Converts the value to an int.
	 *
	 * @return the int representation of the value as usint.
	 */
	uint64_t ConvertToInt() const {
		return m_value;
	}

	/**
	 * Converts the value to an double.
	 *
	 * @return double representation of the value.
	 */
	double ConvertToDouble() const {
		return m_value;
	}

	//Arithmetic Operations

	/**
	 * Addition operation.
	 *
	 * @param b is the value to add of type BigInteger.
	 * @return result of the addition operation of type BigInteger.
	 */
	NativeInteger Plus(const NativeInteger& b) const {
		uint_type newv = m_value + b.m_value;
		if( newv < m_value || newv < b.m_value ) {
			PALISADE_THROW( lbcrypto::math_error, "Overflow");
		}
		return newv;
	}

	/**
	 * Addition operation.
	 *
	 * @param b is the value to add of type BigInteger.
	 * @return result of the addition operation of type BigInteger.
	 */
	const NativeInteger& PlusEq(const NativeInteger& b) {
		uint_type oldv = m_value;
		m_value += b.m_value;
		if( m_value < oldv ) {
			PALISADE_THROW( lbcrypto::math_error, "Overflow");
		}
		return *this;
	}

	/**
	 * Subtraction operation.
	 *
	 * @param b is the value to subtract of type BigInteger.
	 * @return result of the subtraction operation of type BigInteger.
	 */
	NativeInteger Minus(const NativeInteger& b) const {
		return m_value <= b.m_value ? 0 : m_value - b.m_value;
	}

	/**
	 * Subtraction operation.
	 *
	 * @param b is the value to subtract of type BigInteger.
	 * @return result of the subtraction operation of type BigInteger.
	 */
	const NativeInteger& MinusEq(const NativeInteger& b) {
		m_value -= m_value <= b.m_value ? m_value : b.m_value;
		return *this;
	}

	/**
	 * Multiplication operation.
	 *
	 * @param b of type BigInteger is the value to multiply with.
	 * @return result of the multiplication operation.
	 */
	NativeInteger Times(const NativeInteger& b) const {
		uint_type prod = m_value * b.m_value;
		if( prod > 0 && (prod < m_value || prod < b.m_value) )
			PALISADE_THROW( lbcrypto::math_error, "Overflow");
		return prod;
	}

	/**
	 * Multiplication operation.
	 *
	 * @param b of type BigInteger is the value to multiply with.
	 * @return result of the multiplication operation.
	 */
	const NativeInteger& TimesEq(const NativeInteger& b) {
		uint_type oldval = m_value;
		m_value *= b.m_value;
		if( m_value < oldval )
			PALISADE_THROW( lbcrypto::math_error, "Overflow");
		return *this;
	}

	/**
	 * Division operation.
	 *
	 * @param b of type NativeInteger is the value to divide by.
	 * @return result of the division operation.
	 */
	NativeInteger DividedBy(const NativeInteger& b) const {
		if( b.m_value == 0 )
			PALISADE_THROW( lbcrypto::math_error, "Divide by zero");
		return this->m_value / b.m_value;
	}

	/**
	 * Division operation.
	 *
	 * @param b of type NativeInteger is the value to divide by.
	 * @return result of the division operation.
	 */
	const NativeInteger& DividedByEq(const NativeInteger& b) {
		if( b.m_value == 0 )
			PALISADE_THROW( lbcrypto::math_error, "Divide by zero");
		this->m_value /= b.m_value;
		return *this;
	}

	//modular arithmetic operations

	/**
	 * returns the modulus with respect to the input value
	 *
	 * @param modulus is value of the modulus to perform
	 * @return NativeInteger that is the result of the modulus operation.
	 */
	NativeInteger Mod(const NativeInteger& modulus) const {
		return m_value % modulus.m_value;
	}

	/**
	 * performs %=
	 *
	 * @param modulus is value of the modulus to perform
	 * @return NativeInteger that is the result of the modulus operation.
	 */
	const NativeInteger& ModEq(const NativeInteger& modulus) {
		m_value %= modulus.m_value;
		return *this;
	}

	/**
	 * returns the modulus with respect to the input value.
	 * Included here for compatibility with backend 2.
	 *
	 * @param modulus is the modulus to perform.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus operation.
	 */
	NativeInteger ModBarrett(const NativeInteger& modulus, const NativeInteger& mu) const {
		return this->m_value%modulus.m_value;
	}

	/**
	* returns the modulus with respect to the input value - In place version.
	* Included here for compatibility with backend 2.
	*
	* @param modulus is the modulus to perform.
	* @param mu is the Barrett value.
	* @return is the result of the modulus operation.
	*/
	void ModBarrettInPlace(const NativeInteger& modulus, const NativeInteger& mu) {
		this->m_value %= modulus.m_value;
		return;
	}

	/**
	 * returns the modulus with respect to the input value.
	 * Included here for compatibility with backend 2.
	 *
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return result of the modulus operation.
	 */
	NativeInteger ModBarrett(const NativeInteger& modulus, const NativeInteger mu_arr[BARRETT_LEVELS+1]) const {
		return this->m_value%modulus.m_value;
	}

	/**
	 * returns the modulus inverse with respect to the input value.
	 *
	 * @param modulus is the modulus to perform.
	 * @return result of the modulus inverse operation.
	 */
	NativeInteger ModInverse(const NativeInteger& mod) const {

		uint_type result = 0;
		uint_type modulus = mod.m_value;

		std::vector<uint_type> mods;
		std::vector<uint_type> quotient;
		mods.push_back(modulus);
		if (this->m_value > modulus)
			mods.push_back(this->m_value%modulus);
		else
			mods.push_back(this->m_value);

		uint_type first(mods[0]);
		uint_type second(mods[1]);
		if(mods[1]==1){
			result = 1;
			return result;
		}

		//Zero does not have a ModInverse
		if(second == 0) {
			throw std::logic_error("Zero does not have a ModInverse");
		}


		//NORTH ALGORITHM
		while(true){
			mods.push_back(first%second);
			quotient.push_back(first/second);
			if(mods.back()==1)
				break;
			if(mods.back()==0){
				std::string msg = std::to_string(m_value) + " does not have a ModInverse using " + std::to_string(modulus);
				throw std::logic_error(msg);
			}

			first = second;
			second = mods.back();
		}

		mods.clear();
		mods.push_back(0);
		mods.push_back(1);

		first = mods[0];
		second = mods[1];

		//SOUTH ALGORITHM
		for(int i=quotient.size()-1;i>=0;i--){
			mods.push_back(quotient[i]*second + first);
			first = second;
			second = mods.back();
		}


		if(quotient.size()%2==1){
			result = (modulus - mods.back());
		}
		else{
			result = mods.back();
		}

		return result;
	}

	/**
	 * Scalar modular addition.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus addition operation.
	 */
	NativeInteger ModAdd(const NativeInteger& b, const NativeInteger& modulus) const {
		Duint_type modsum = (Duint_type)m_value;
		modsum += b.m_value;
		if (modsum >= modulus.m_value)
			modsum %= modulus.m_value;
		return (uint_type)modsum;
	}

	/**
	 * Scalar modular addition.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus addition operation.
	 */
	const NativeInteger& ModAddEq(const NativeInteger& b, const NativeInteger& modulus) {
		Duint_type modsum = (Duint_type)m_value;
		modsum += b.m_value;
		if (modsum >= modulus.m_value)
			modsum %= modulus.m_value;
		this->m_value = (uint_type)modsum;
		return *this;
	}

	/**
	 * Fast scalar modular addition. Minimizes the number of modulo reduction operations.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus addition operation.
	 */
	inline NativeInteger ModAddFast(const NativeInteger& b, const NativeInteger& modulus) const {
		Duint_type modsum = (Duint_type)m_value;
		modsum += b.m_value;
		modsum %= modulus.m_value;
		if( modsum > m_uintMax )
			PALISADE_THROW( lbcrypto::math_error, "Overflow");
		return (uint_type)modsum;
	}


	/**
	 * Modular addition where Barrett modulo reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus addition operation.
	 */
	NativeInteger ModBarrettAdd(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->Plus(b).ModBarrett(modulus,mu_arr);
	}

	/**
	 * Modular addition where Barrett modulo reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is one precomputed Barrett value.
	 * @return is the result of the modulus addition operation.
	 */
	NativeInteger ModBarrettAdd(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger& mu) const {
		return this->Plus(b).ModBarrett(modulus,mu);
	}

	/**
	 * Scalar modular subtraction.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus subtraction operation.
	 */
	NativeInteger ModSub(const NativeInteger& b, const NativeInteger& modulus) const {
		Duint_type av = m_value;
		Duint_type bv = b.m_value;
		Duint_type mod = modulus.m_value;

		//reduce this to a value lower than modulus
		if(av >= mod) {
			av %= mod;
		}
		//reduce b to a value lower than modulus
		if(bv >= mod){
			bv %= mod;
		}

		if(av >= bv){
			return uint_type((av - bv) % mod);
		}
		else{
			return uint_type((av + mod) - bv);
		}
	}

	/**
	 * Scalar modular subtraction.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus subtraction operation.
	 */
	const NativeInteger& ModSubEq(const NativeInteger& b, const NativeInteger& modulus) {
		Duint_type bv = b.m_value;
		Duint_type mod = modulus.m_value;

		//reduce this to a value lower than modulus
		if(m_value >= mod) {
			m_value %= mod;
		}
		//reduce b to a value lower than modulus
		if(bv >= mod){
			bv %= mod;
		}

		if(m_value >= bv){
			m_value = uint_type((m_value - bv) % mod);
		}
		else{
			m_value = uint_type((m_value + mod) - bv);
		}

		return *this;
	}

	/**
	 * Fast scalar modular subtraction. ModSubFast assumes b < modulus.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus subtraction operation.
	 */
	inline NativeInteger ModSubFast(const NativeInteger& b, const NativeInteger& modulus) const {
		Duint_type av = m_value;
		Duint_type bv = b.m_value;
		Duint_type mod = modulus.m_value;
	
		if(av >= bv){
			return uint_type((av - bv) % mod);
		}
		else{
			return uint_type((av + mod) - bv);
		}
	}


	/**
	 * Scalar modular subtraction where Barrett modular reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus subtraction operation.
	 */
	NativeInteger ModBarrettSub(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& mu) const {
		return this->ModSub(b,modulus);
	}

	/**
	 * Scalar modular subtraction where Barrett modular reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus subtraction operation.
	 */
	NativeInteger ModBarrettSub(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->ModSub(b,modulus);
	}

	/**
	 * Scalar modulus multiplication.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModMul(const NativeInteger& b, const NativeInteger& modulus) const {
		Duint_type av = m_value;
		Duint_type bv = b.m_value;

		if( av >= modulus.m_value ) av = av%modulus.m_value;
		if( bv >= modulus.m_value ) bv = bv%modulus.m_value;

		return uint_type((av*bv)%modulus.m_value);
	}

	/**
	 * Scalar modulus multiplication.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	const NativeInteger& ModMulEq(const NativeInteger& b, const NativeInteger& modulus) {
		Duint_type av = m_value;
		Duint_type bv = b.m_value;

		if( av >= modulus.m_value ) av = av%modulus.m_value;
		if( bv >= modulus.m_value ) bv = bv%modulus.m_value;

		this->m_value = uint_type((av*=bv)%=modulus.m_value);

		return *this;
	}

	/**
	 * Scalar modulus multiplication. Fast version, assumes inputs are
	 * already < modulus. 
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModMulFast(const NativeInteger& b, const NativeInteger& modulus) const {
		Duint_type av = m_value;
		Duint_type bv = b.m_value;
		return (uint_type)((av*bv)%modulus.m_value);
	}

	/**
	 * Scalar modulus multiplication.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	const NativeInteger& ModMulFastEq(const NativeInteger& b, const NativeInteger& modulus) {
		Duint_type av = m_value;
		Duint_type bv = b.m_value;

		this->m_value = (uint_type)((av*=bv)%=modulus.m_value);

		return *this;
	}

	/**
	 * Scalar modular multiplication where Barrett modular reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the precomputed Barrett value.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModBarrettMul(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger& mu) const {
		return this->ModMul(b,modulus);
	}

	/**
	* Scalar modular multiplication where Barrett modular reduction is used - In-place version
	* Included here for compatibility with backend 2.
	*
	* @param b is the scalar to multiply.
	* @param modulus is the modulus to perform operations with.
	* @param mu is the precomputed Barrett value.
	* @return is the result of the modulus multiplication operation.
	*/
	void ModBarrettMulInPlace(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& mu) {
		*this = this->ModMulFast(b,modulus);
		return;
	}

	/**
	 * Scalar modular multiplication where Barrett modular reduction is used.
	 * Included here for compatibility with backend 2.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModBarrettMul(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->ModMul(b,modulus);
	}

	/**
	 * Scalar modular exponentiation. Square-and-multiply algorithm is used.
	 *
	 * @param &b is the scalar to exponentiate.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus exponentiation operation.
	 */
	NativeInteger ModExp(const NativeInteger& b, const NativeInteger& mod) const {
		Duint_type exp = b.m_value;
		Duint_type product = 1;
		Duint_type modulus = mod.m_value;
		Duint_type mid = m_value % modulus;

		while( true ) {
			if( exp%2 == 1 )
				product = product * mid;

			//running product is calculated
			if(product >= modulus){
				product = product % modulus;
			}

			//divide by 2 and check even to odd to find bit value
			exp >>= 1;
			if(exp == 0)
				break;

			//mid calculates mid^2%q
			mid = mid*mid;

			mid = mid % modulus;
		}
		return (uint_type)product;
	}

	//Shift Operators

	/**
	 * Left shift operator
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	NativeInteger  LShift(usshort shift) const {
		return m_value << shift;
	}

	/**
	 * Left shift operator uses in-place algorithm and operates on the same variable.
	 *
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	const NativeInteger&  LShiftEq(usshort shift) {
		m_value <<= shift;
		return *this;
	}

	/**
	 * Right shift operator
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	NativeInteger  RShift(usshort shift) const {
		return m_value >> shift;
	}

	/**
	 * Right shift operator uses in-place algorithm and operates on the same variable.
	 *
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	const NativeInteger&  RShiftEq(usshort shift) {
		m_value >>= shift;
		return *this;
	}

	/**
	 * Stores the based 10 equivalent/Decimal value of the NativeInteger in a string object and returns it.
	 *
	 * @return value of this NativeInteger in base 10 represented as a string.
	 */
	const std::string ToString() const {
		return std::to_string(m_value);
	}

	// note that for efficiency, we use [De]Serialize[To|From]String when serializing
	// BigVectors, and [De]Serialize otherwise (to work the same as all
	// other serialized objects.
	// Serialize using the modulus; convert value to signed, then serialize to string
	const std::string SerializeToString(const NativeInteger& modulus = 0) const {
		// numbers go from high to low -1, -2, ... +modulus/2, modulus/2 - 1, ... ,1, 0
		bool isneg = false;
		NativeInteger signedVal;
		if( modulus.m_value == 0 || m_value < modulus.m_value/2 )
			signedVal = m_value;
		else {
			signedVal = modulus.m_value - m_value;
			isneg = true;
		}

		std::string ser = "";
		if( isneg ) ser += "-";
		unsigned char len = signedVal.GetMSB();
		ser += lbcrypto::value_to_base64(len);
		for( int i=len; i>0; i-=6 )
			ser += lbcrypto::value_to_base64(signedVal.Get6BitsAtIndex(i));
		return ser;
	}

	//deserialize from string
	const char * DeserializeFromString(const char * str, const NativeInteger& modulus = 0) {
		bool isneg = false;
		if( *str == '-' ) {
			++str;
			isneg = true;
		}
		usint len = lbcrypto::base64_to_value(*str);
		uint64_t value = 0;

		for( ; len > 6 ; len -= 6 )
			value = (value<<6)|lbcrypto::base64_to_value(*++str);

		if( len )
			value = (value<<len) | (lbcrypto::base64_to_value(*++str));

		str++;

		if( isneg )
			value = (modulus.m_value - value);

		m_value = value;
		return str;
	}
	/**
	* Serialize the object into a Serialized
	* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	* @return true if successfully serialized
	*/
	bool Serialize(lbcrypto::Serialized* serObj) const{

	  if( !serObj->IsObject() )
	    return false;
	  
	  lbcrypto::SerialItem bbiMap(rapidjson::kObjectType);
	  
	  bbiMap.AddMember("IntegerType", IntegerTypeName(), serObj->GetAllocator());
	  bbiMap.AddMember("Value", this->ToString(), serObj->GetAllocator());
	  serObj->AddMember("BigIntegerImpl", bbiMap, serObj->GetAllocator());
	  return true;
	  
	};
	
	/**
	* Populate the object from the deserialization of the Serialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	bool Deserialize(const lbcrypto::Serialized& serObj){
	  //find the outer name
	  lbcrypto::Serialized::ConstMemberIterator mIter = serObj.FindMember("BigIntegerImpl");
	  if( mIter == serObj.MemberEnd() )//not found, so fail
	    return false;
	  
	  lbcrypto::SerialItem::ConstMemberIterator vIt; //interator within name
	  
	  //is this the correct integer type?
	  if( (vIt = mIter->value.FindMember("IntegerType")) == mIter->value.MemberEnd() )
	    return false;
	  if( IntegerTypeName() != vIt->value.GetString() )
	    return false;
	  
	  //find the value
	  if( (vIt = mIter->value.FindMember("Value")) == mIter->value.MemberEnd() )
	    return false;
	  //assign the value found
	  AssignVal(vIt->value.GetString());
	  return true;
	};
	
    static const std::string IntegerTypeName() { return "NativeI"; }

	/**
	 * Get the number of digits using a specific base - support for arbitrary base may be needed.
	 *
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetLengthForBase(usint base) const {return GetMSB();}

	/**
	* Get a specific digit at "digit" index; big integer is seen as an array of digits, where a 0 <= digit < base
	*
	* @param index is the "digit" index of the requested digit
	* @param base is the base with which to determine length in.
	* @return is the requested digit
	*/
	usint GetDigitAtIndexForBase(usint index, usint base) const {

		usint DigitLen = ceil(log2(base));

		usint digit = 0;
		usint newIndex = 1 + (index - 1)*DigitLen;
		for (usint i = 1; i < base; i = i * 2)
		{
			digit += GetBitAtIndex(newIndex)*i;
			newIndex++;
		}
		return digit;

	}

	/**
	 * Convert a string representation of a binary number to a decimal BigInteger.
	 *
	 * @param bitString the binary num in string.
	 * @return the binary number represented as a big binary int.
	 */
	static NativeInteger BitStringToBigInteger(const std::string& bitString) {
		if( bitString.length() > m_uintBitLength ) {
			throw std::logic_error("Bit string is too long to fit in a native_int");
		}

		uint_type v = 0;
		for( size_t i=0 ; i < bitString.length() ; i++ ) {
			int n = bitString[i] - '0';
			if( n < 0 || n > 1 ) {
				throw std::logic_error("Bit string must contain only 0 or 1");
			}

			v <<= 1;
			v |= n;
		}

		return v;
	}

	/**
	 * Exponentiation. Returns x^p
	 *
	 * @param p the exponent.
	 * @return the integer x^p.
	 */
	NativeInteger Exp(usint p) const {
		if (p == 0) return 1;
		if (p == 1) return *this;

		NativeInteger tmp = (*this).Exp(p/2);
		if (p%2 == 0) return tmp * tmp;
		else return tmp * tmp * (*this);
	}

	/**
	 * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding operation.
	 *
	 * @param p is the numerator to be multiplied.
	 * @param q is the denominator to be divided.
	 * @return the result of multiply and round.
	 */
	NativeInteger MultiplyAndRound(const NativeInteger &p, const NativeInteger &q) const {
		NativeInteger ans = m_value*p.m_value;
		return ans.DivideAndRound(q);
	}

	/**
	 * Computes the quotient of x*p/q, where x,p,q are all uint_type numbers, x is the current value; uses Duint_type arithmetic
	 *
	 * @param p is the multiplicand
	 * @param q is the divisor
	 * @return the quotient
	 */
	NativeInteger MultiplyAndDivideQuotient(const NativeInteger &p, const NativeInteger &q) const {
		Duint_type xD = m_value;
		Duint_type pD = p.m_value;
		Duint_type qD = q.m_value;
		return (uint_type)(xD*pD/qD);
	}

	/**
	 * Computes the remainder of x*p/q, where x,p,q are all uint_type numbers, x is the current value; uses Duint_type arithmetic
	 *
	 * @param p is the multiplicand
	 * @param q is the divisor
	 * @return the remainder
	 */
	NativeInteger MultiplyAndDivideRemainder(const NativeInteger &p, const NativeInteger &q) const {
		Duint_type xD = m_value;
		Duint_type pD = p.m_value;
		Duint_type qD = q.m_value;
		return (uint_type)((xD*pD)%qD);
	}

	/**
	 * Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is the rounding operation.
	 *
	 * @param q is the denominator to be divided.
	 * @return the result of divide and round.
	 */
	NativeInteger DivideAndRound(const NativeInteger &q) const {

		if( q == 0 )
			PALISADE_THROW( lbcrypto::math_error, "Divide by zero");

		uint_type ans = m_value/q.m_value;
		uint_type rem = m_value%q.m_value;
		uint_type halfQ = q.m_value >> 1;

		if (!(rem <= halfQ)) {
			ans += 1;
		}

		return ans;
	}

	//overloaded binary operators based on integer arithmetic and comparison functions
	NativeInteger operator-() const { return NativeInteger(0).Minus(*this); }

	/**
	 * Console output operation.
	 *
	 * @param os is the std ostream object.
	 * @param ptr_obj is NativeInteger to be printed.
	 * @return is the ostream object.
	 */
	friend std::ostream& operator<<(std::ostream& os, const NativeInteger &ptr_obj) {
		os << ptr_obj.m_value;
		return os;
	}

	/**
	 * Gets the bit at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return resulting bit.
	 */
	uschar GetBitAtIndex(usint index) const {
		if(index==0) {
			throw std::logic_error("Zero index in GetBitAtIndex");
		}

		return (m_value >> (index-1)) & 0x01;
	}

	/**
	 * Gets the 6 bits at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return 6 bit pattern
	 */
	uschar Get6BitsAtIndex(usint index) const {
		return lbcrypto::get_6bits_atoffset(m_value, index);
	}

	/**
	 * Compares the current NativeInteger to NativeInteger a.
	 *
	 * @param a is the NativeInteger to be compared with.
	 * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
	 */
	int Compare(const NativeInteger& a) const {
		if( this->m_value < a.m_value )
			return -1;
		else if( this->m_value > a.m_value )
			return 1;
		return 0;
	}

	/**
	 *  Set this int to 1.
	 *  Note some compilers don't like using the ONE constant, above :(
	 */
	void SetIdentity() { this->m_value = 1; };

	/**
	 * A zero allocator that is called by the Matrix class.
	 * It is used to initialize a Matrix of NativeInteger objects.
	 */
	static unique_ptr<NativeInteger<uint_type>> Allocator();

protected:

	/**
	 * Converts the string v into base-r integer where r is equal to 2^bitwidth of integral data type.
	 *
	 * @param v The input string
	 */
	void AssignVal(const std::string& str) {
		uint_type test_value = 0;
		m_value = 0;
		for( size_t i=0; i<str.length(); i++ ) {
			int v = str[i] - '0';
			if( v < 0 || v > 9 ) {
				throw std::logic_error("String contains a non-digit");
			}
			m_value *= 10;
			m_value += v;

			if( m_value < test_value ) {
				throw std::logic_error(str + " is too large to fit in this native integer object");
			}
			test_value = m_value;
		}
	}

private:

	// representation as a
	uint_type m_value;

	//variable to store the bit width of the integral data type.
	static const uschar m_uintBitLength = sizeof(uint_type)*8;

	//variable to store the maximum value of the integral data type.
	static const uint_type m_uintMax = std::numeric_limits<uint_type>::max();

	// Duint_type has double the bits in the integral data type.
	typedef typename DoubleDataType<uint_type>::T Duint_type;
};

}//namespace ends

#endif
