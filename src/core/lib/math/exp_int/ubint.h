/**
 * @file ubint.h  This file contains the main class for unsigned big integers: ubint. Big
 * integers are represented as arrays of machine native unsigned integers. The
 * native integer type is supplied as a template parameter.  Currently
 * implementation based on uint32_t and uint64_t is
 * supported. a native double the base integer size is also needed.
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

#ifndef LBCRYPTO_MATH_EXPINT_UBINT_H
#define LBCRYPTO_MATH_EXPINT_UBINT_H

#define NO_BARRETT //currently barrett is slower than mod


#include <iostream>
#include <string>
#include <vector>
#include <type_traits>
#include <typeinfo>
#include <limits>
#include <fstream>
#include <stdexcept>
#include <functional>
#include <memory>
#include "../../utils/inttypes.h"
#include "../../utils/memory.h"
#include "../nbtheory.h"

#ifdef UBINT_64

#undef int128_t
#define int128_t our_int128_t
#undef uint128_t
#define uint128_t our_uint128_t

#if HAVE___INT128
typedef __int128                int128_t;
typedef unsigned __int128       uint128_t;
#elif HAVE_INT128
typedef int128                  int128_t;
typedef unsigned int128         uint128_t;
#else /* HAVE__INT128_T */
typedef __int128_t              int128_t;
typedef __uint128_t             uint128_t;
#endif

#define UINT128_MAX             ((uint128_t)-1)

#endif //UBINT_64


/**
 *@namespace exp_int
 * The namespace of this code
 */
namespace exp_int{

/**The following structs are needed for initialization of ubint at
 *the preprocessing stage.  The structs compute certain values using
 *template metaprogramming approach and mostly follow recursion to
 *calculate value(s).
 */

/**
 * @brief  Struct to find log value of N.
 *Needed in the preprocessing step of ubint to determine bitwidth.
 *
 * @tparam N bitwidth.
 */

template <usint N>
struct Log2{
	const static usint value = 1 + Log2<N/2>::value;
};

/**
 * @brief Struct to find log 2 value of N.
 *Base case for recursion.
 *Needed in the preprocessing step of ubint to determine bitwidth.
 */
template<>
struct Log2<2>{
	const static usint value = 1;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t, uint128_t}
 *
 * @tparam Dtype primitive datatype.
 */
template<typename Dtype>
struct DataTypeChecker{
	const static bool value = false ;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t, uint128_t}.
 * sets value true if datatype is unsigned integer 8 bit.
 */
template<>
struct DataTypeChecker<uint8_t>{
	const static bool value = true ;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t, uint128_t}.
 * sets value true if datatype is unsigned integer 16 bit.
 */
template<>
struct DataTypeChecker<uint16_t>{
	const static bool value = true ;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t, uint128_t}.
 * sets value true if datatype is unsigned integer 32 bit.
 */
template<>
struct DataTypeChecker<uint32_t>{
	const static bool value = true ;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t, uint128_t}.
 * sets value true if datatype is unsigned integer 64 bit.
 */
template<>
struct DataTypeChecker<uint64_t>{
	const static bool value = true ;
};

#ifdef UBINT_64
/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t, uint128_t}.
 * sets value true if datatype is unsigned integer 64 bit.
 */
template<>
struct DataTypeChecker<uint128_t>{
	const static bool value = true ;
};
#endif

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
 * Sets T as of type unsigned integer 16 bit if limb datatype is 8bit
 */
template<> struct DoubleDataType<uint8_t>{typedef uint16_t T;};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 32 bit if limb datatype is 16bit
 */
template<> struct DoubleDataType<uint16_t>{typedef uint32_t T; };

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 64 bit if limb datatype is 32bit
 */
template<> struct DoubleDataType<uint32_t>{typedef uint64_t T; };

#ifdef UBINT_64
/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 128 bit if limb datatype is 64bit
 */
template<> struct DoubleDataType<uint64_t>{typedef uint128_t T; };
#endif

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template<typename utype> struct SignedDataType{typedef void T; };

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * Sets T as of type signed integer 8 bit if limb datatype is 8bit
 */
template<> struct SignedDataType<uint8_t>{ typedef int8_t T; };

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * sets T as of type signed integer 16 bit if limb datatype is 16bit
 */
template<>  struct SignedDataType<uint16_t>{ typedef int16_t T; };

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * sets T as of type signed integer 32 bit if limb datatype is 32bit
 */
template<> struct SignedDataType<uint32_t>{ typedef int32_t T; };

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * sets T as of type signed integer 64 bit if limb datatype is 64bit
 */
template<> struct SignedDataType<uint64_t>{ typedef int64_t T; };

/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as utype.
 * sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template<typename utype>
struct SignedDoubleDataType{
	typedef void T;
};

/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as utype.
 * Sets T as of type unsigned integer 16 bit if limb datatype is 8bit
 */
template<> struct SignedDoubleDataType<uint8_t>{typedef int16_t T;};

/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 32 bit if limb datatype is 16bit
 */
template<> struct SignedDoubleDataType<uint16_t>{typedef int32_t T; };

/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 64 bit if limb datatype is 32bit
 */
template<> struct SignedDoubleDataType<uint32_t>{typedef int64_t T; };

#ifdef UBINT_64
/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 128 bit if limb datatype is 64bit
 */
template<> struct SignedDoubleDataType<uint64_t>{typedef int128_t T; };
#endif

const double LOG2_10 = 3.32192809;	//!< @brief A pre-computed constant of Log base 2 of 10.

//todo: the following will be deprecated
const usint BARRETT_LEVELS = 8;		//!< @brief The number of levels (precomputed values) used in the Barrett reductions.

//////////////////////////////////////////////////////////////////////////////////////////////////
// Definition starts here
//////////////////////////////////////////////////////////////////////////////////////////////////
template<typename limb_t>
class ubint : public lbcrypto::BigIntegerInterface<ubint<limb_t>>
{

public:

	/**
	 * Default constructor.
	 */
	ubint();

	/**
	 * Basic constructor for specifying the ubint.
	 *
	 * @param str is the initial integer represented as a string.
	 */
	explicit ubint(const std::string& str);

	/**
	 * Basic constructor for initializing big integer from a uint64_t.
	 *
	 * @param init is the initial 64 bit unsigned integer.
	 */
	ubint(const uint64_t init);

	/**
	 * Basic constructor for copying a ubint
	 *
	 * @param rhs is the ubint to be copied.
	 */
	ubint(const ubint& rhs);

	/**
	 * Basic constructor for move copying a ubint
	 *
	 * @param &&rhs is the ubint to be moved from.
	 */
	explicit ubint(ubint&& rhs);

	/**
	 * Construct from a NativeInteger
	 * @param n
	 */
	ubint(const NativeInteger& n) : ubint(n.ConvertToInt()) {}

	/**
	 * Destructor.
	 */
	~ubint();

	/**
	 * Assignment operator (copy)
	 *
	 * @param &rhs is the ubint to be assigned from.
	 * @return assigned ubint ref.
	 */
	const ubint&  operator=(const ubint &rhs);

	/**
	 * Assignment operator from unsigned integer
	 *
	 * @param val is the unsigned integer value that is assigned.
	 * @return the assigned ubint ref.
	 */
	const ubint& operator=(const uint64_t val) {
		*this = ubint(val);
		return *this;
	}

	/**
	 * Assignment operator from string
	 *
	 * @param val is the string value that is assigned.
	 * @return the assigned ubint ref.
	 */
	const ubint& operator=(const std::string val) {
		*this = ubint(val);
		return *this;
	}

	//Auxillary Functions

	/**
	 * Delivers value of the internal limb storage
	 * Used primarily for debugging
	 * @return STL vector of uint_type
	 */
	vector<limb_t> GetInternalRepresentation(void) const {
		vector<limb_t> ret = m_value;
		return ret;
	}

	/**
	 * Basic set method for setting the value of a ubint
	 *
	 * @param str is the string representation of the ubint to be copied.
	 */
	void SetValue(const std::string& str);

	/**
	 * Basic set method for setting the value of a ubint
	 *
	 * @param a is the ubint representation of the ubint to be assigned.
	 */
	void SetValue(const ubint& a);

	/**
	 * Returns the MSB location of the value.
	 *
	 * @return the index of the most significant bit.
	 */
	usint GetMSB()const;

	/**
	 * Returns the size of the underlying vector of Limbs
	 *
	 * @return the size
	 */
	usint GetNumberOfLimbs()const;

	/**
	 * Converts the value to a usint.
	 * if the ubint is uninitialized std::logic_error is thrown
	 * if the ubint is larger than the max value representable
	 * it is truncated to the least significant bits that fit
	 * @return the int representation of the value as usint.
	 */
	usint ConvertToUsint() const;

	/**
	 * Converts the value to a usint. Soon to be DEPRECATED, because Int is not usint
	 * if the ubint is uninitialized std::logic_error is thrown
	 * if the ubint is larger than the max value representable
	 * it is truncated to the least significant bits that fit
	 * @return the int representation of the value as usint.
	 */
	uint64_t ConvertToInt() const;

	/**
	 * Converts the value to a uint32_t.
	 * if the ubint is uninitialized std::logic_error is thrown
	 * if the ubint is larger than the max value representable
	 * it is truncated to the least significant bits that fit
	 * @return the int representation of the value as uint32_t
	 */
	uint32_t ConvertToUint32() const;

	/**
	 * Converts the value to a uint64_t.
	 * if the ubint is uninitialized std::logic_error is thrown
	 * if the ubint is larger than the max value representable
	 * it is truncated to the least significant bits that fit
	 * @return the int representation of the value as uint64_t
	 */
	uint64_t ConvertToUint64() const;

	/**
	 * Converts the value to a float
	 * if the ubint is uninitialized std::logic_error is thrown
	 * if the ubint is larger than the max value representable
	 * or if conversion fails, and error is reported to cerr
	 *
	 * @return float representation of the value.
	 */
	float ConvertToFloat() const;

	/**
	 * Converts the value to an double.
	 * if the ubint is uninitialized std::logic_error is thrown
	 * if the ubint is larger than the max value representable
	 * std::out_of_range is thrown
	 * if conversion fails std::invalid_argment is thrown
	 *
	 * @return double representation of the value.
	 */
	double ConvertToDouble() const;


	/**
	 * Converts the value to an long double.
	 * if the ubint is uninitialized std::logic_error is thrown
	 * if the ubint is larger than the max value representable
	 * std::out_of_range is thrown
	 * if conversion fails std::invalid_argment is thrown
	 *
	 * @return long double representation of the value.
	 */
	long double ConvertToLongDouble() const;

	/**
	 * Convert a value from an unsigned int to a ubint.
	 *
	 * @param m the value to convert from.
	 * @return int represented as a ubint.
	 */
	static ubint UsintToUbint(usint m);

	//Arithemetic Operations

	/**
	 * Addition operation.
	 *
	 * @param b is the value to add of type ubint.
	 * @return result of the addition operation of type ubint.
	 */
	ubint Plus(const ubint& b) const;

	const ubint& PlusEq(const ubint& b);

	/**
	 * Subtraction operation.
	 *
	 * @param b is the value to subtract of type ubint.
	 * @return result of the subtraction operation of type ubint.
	 */
	ubint Minus(const ubint& b) const;

	const ubint& MinusEq(const ubint& b);

	/**
	 * Multiplication operation.
	 *
	 * @param b of type ubint is the value to multiply with.
	 * @return result of the multiplication operation.
	 */
	ubint Times(const ubint& b) const;

	const ubint& TimesEq(const ubint& b);

	/**
	 * Division operation.
	 *
	 * @param b of type ubint is the value to divide by.
	 * @return result of the division operation.
	 *
	 */
	ubint DividedBy(const ubint& b) const;

	const ubint& DividedByEq(const ubint& b);

	/**
	 * Exponentiation of a bigInteger x. Returns x^p
	 *
	 * @param p the exponent.
	 * @return the ubint x^p.
	 */
	ubint Exp(usint p) const;

	//modular arithmetic operations

	/**
	 * returns the modulus with respect to the input value. Classical modular reduction algorithm is used.
	 *
	 * @param modulus is value of the modulus to perform. Its of type ubint.
	 * @return ubint that is the result of the modulus operation.
	 */
	ubint Mod(const ubint& modulus) const;

	const ubint& ModEq(const ubint& modulus);

	/**
	 * returns the modulus with respect to the input value.
	 * Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
	 * Deprecated mu is ignored, calls Mod()
	 *
	 * @param modulus is the modulus to perform.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus operation.
	 */
	ubint ModBarrett(const ubint& modulus, const ubint& mu) const;

	/**
	 * returns the modulus with respect to the input value. In-place version.
	 * Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
	 * Deprecated mu is ignored, calls Mod()
	 *
	 * @param modulus is the modulus to perform.
	 * @param mu is the Barrett value.
	 */
	void ModBarrettInPlace(const ubint& modulus, const ubint& mu);


	/**
	 * returns the modulus with respect to the input value.
	 * Implements generalized Barrett modular reduction algorithm. Uses an array of precomputed values \mu.
	 * Deprecated mu_arr is ignored, calls Mod()
	 *
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return result of the modulus operation.
	 */
	ubint ModBarrett(const ubint& modulus, const ubint mu_arr[BARRETT_LEVELS+1]) const;


	/**
	 * returns the modulus inverse with respect to the input value.
	 *
	 * @param modulus is the modulus to perform.
	 * @return result of the modulus inverse operation.
	 */
	ubint ModInverse(const ubint& modulus) const;

	/**
	 * Scalar modular addition.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus addition operation.
	 */
	ubint ModAdd(const ubint& b, const ubint& modulus) const;

	ubint ModAddFast(const ubint& b, const ubint& modulus) const;

	const ubint& ModAddEq(const ubint& b, const ubint& modulus);

	// this is wrapper for modadd
	inline ubint ModBarrettAdd(const ubint& b, const ubint& modulus,const ubint& mu) const {
		return this->ModAdd(b, modulus);
	};


	/**
	 * Scalar modular subtraction.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus subtraction operation.
	 */
	ubint ModSub(const ubint& b, const ubint& modulus) const;

	ubint ModSubFast(const ubint& b, const ubint& modulus) const;

	const ubint& ModSubEq(const ubint& b, const ubint& modulus);

	// this is wrapper for modsub
	inline ubint ModBarrettSub(const ubint& b, const ubint& modulus,const ubint& mu) const {
		return this->ModSub(b, modulus);
	};


	/**
	 * Scalar modulus multiplication.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	ubint ModMul(const ubint& b, const ubint& modulus) const;

	ubint ModMulFast(const ubint& b, const ubint& modulus) const;

	const ubint& ModMulEq(const ubint& b, const ubint& modulus);


	/**
	 * Scalar modular multiplication where Barrett modular reduction is used.
	 * Implements generalized Barrett modular reduction algorithm (no interleaving between multiplication and modulo).
	 * Uses one precomputed value \mu.
	 * NOTE this actually just calls ModMul, mu is ignored
	 *
	 * @param b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the precomputed Barrett value.
	 * @return is the result of the modulus multiplication operation.
	 */
	ubint ModBarrettMul(const ubint& b, const ubint& modulus,const ubint& mu) const;

	/**
	 * Scalar modular multiplication where Barrett modular reduction is used - In-place version
	 * Implements generalized Barrett modular reduction algorithm (no interleaving between multiplication and modulo).
	 * Uses one precomputed value \mu.
	 * See the cpp file for details of the implementation.
	 *
	 * @param b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the precomputed Barrett value.
	 */
	void ModBarrettMulInPlace(const ubint& b, const ubint& modulus, const ubint& mu);

	/**
	 * Scalar modular multiplication where Barrett modular reduction is used.
	 * NOTE this actually just calls ModMul, mu_arr is ignored
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus multiplication operation.
	 */
	ubint ModBarrettMul(const ubint& b, const ubint& modulus,const ubint mu_arr[BARRETT_LEVELS]) const;

	/**
	 * Scalar modular exponentiation. Square-and-multiply algorithm is used.
	 *
	 * @param &b is the scalar to exponentiate.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus exponentiation operation.
	 */
	ubint ModExp(const ubint& b, const ubint& modulus) const;

	/**
	 * << operation
	 *
	 * @param shift # of bits
	 * @return result of the shift operation.
	 */
	ubint LShift(usshort shift) const;

	/**
	 * <<= operation
	 *
	 * @param shift # of bits
	 * @return result of the shift operation.
	 */
	const ubint& LShiftEq(usshort shift);

	/**
	 * >> operation
	 *
	 * @param shift # of bits
	 * @return result of the shift operation.
	 */
	ubint RShift(usshort shift) const;

	/**
	 * >>= operation
	 *
	 * @param shift # of bits
	 * @return result of the shift operation.
	 */
	const ubint& RShiftEq(usshort shift);

	/**
	 * Stores the based 10 equivalent/Decimal value of the ubint in a string object and returns it.
	 *
	 * @return value of this ubint in base 10 represented as a string.
	 */
	const std::string ToString() const;

	//Serialization functions
	const std::string SerializeToString(const ubint& mod = 0) const;
	const char * DeserializeFromString(const char * str, const ubint& mod = 0);


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

	// helper functions

	/**
	 * Tests whether the ubint is a power of 2.
	 *
	 * @param m_numToCheck is the value to check.
	 * @return true if the input is a power of 2, false otherwise.
	 */
	bool isPowerOfTwo(const ubint& m_numToCheck);

	/**
	 * Get the number of digits using a specific base - support for arbitrary base may be needed.
	 *
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetLengthForBase(usint base) const {return GetMSB();}

	/**
	 * Get the number of digits using a specific base - only power-of-2 bases are currently supported.
	 *
	 * @param index is the location to return value from in the specific base.
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetDigitAtIndexForBase(usint index, usint base) const;

	/**
	 * Convert a string representation of a binary number to a ubint.
	 * Note: needs renaming to a generic form since the variable type name is
	 * embedded in the function name. Suggest FromBinaryString()
	 * @param bitString the binary num in string.
	 * @return the  number represented as a ubint.
	 */
	static ubint BinaryStringToUbint(const std::string& bitString);
	static ubint BitStringToBigInteger(const std::string& bitString);

	/**
	 * Multiply and Rounding operation on a ubint x.
	 * Returns [x*p/q] where [] is the rounding operation.
	 *
	 * @param p is the numerator to be multiplied.
	 * @param q is the denominator to be divided.
	 * @return the result
	 */
	ubint MultiplyAndRound(const ubint &p, const ubint &q) const;

	// this is a negation operator which really doesn't make sense for an unsinged
	ubint operator-() const {
		return ubint(0).Minus(*this);
	}

	/**
	 * Divide and Rounding operation on a ubint x.
	 * Returns [x*p/q] where [] is the rounding operation.
	 *
	 * @param p is the numerator to be multiplied.
	 * @param q is the denominator to be divided.
	 * @return the result
	 */
	ubint DivideAndRound(const ubint &q) const;

	/**
	 * ostream output << operator
	 *
	 * @param os is the std ostream object.
	 * @param ptr_obj is ubint to be printed.
	 * @return is the returned ostream object.
	 */
	friend std::ostream& operator<<(std::ostream& os, const ubint &ptr_obj) {
		//&&&

		//Algorithm used is double and add
		//http://www.wikihow.com/Convert-from-Binary-to-Decimal

		//todo: get rid of m_numDigitInPrintval and make dynamic
		//create reference for the object to be printed
		ubint *print_obj;

		usint counter;

		//initiate to object to be printed
		print_obj = new ubint(ptr_obj);  //todo smartpointer

		//print_obj->PrintValueInDec();

		//print_VALUE array stores the decimal value in the array
		uschar *print_VALUE = new uschar[ptr_obj.m_numDigitInPrintval];  //todo smartpointer

		//reset to zero
		for(usint i=0;i<ptr_obj.m_numDigitInPrintval;i++)
			*(print_VALUE+i)=0;

		//starts the conversion from base r to decimal value
		for(usint i=print_obj->m_MSB;i>0;i--){

			//print_VALUE = print_VALUE*2
			ubint::double_bitVal(print_VALUE);

			//adds the bit value to the print_VALUE
			ubint::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));
		}

		//find the first occurence of non-zero value in print_VALUE
		for(counter=0;counter<ptr_obj.m_numDigitInPrintval-1;counter++){
			if(print_VALUE[counter]!=0)break;
		}

		//start inserting values into the ostream object
		for(;counter<ptr_obj.m_numDigitInPrintval;counter++){
			os<<(int)print_VALUE[counter];
		}

		//os<<endl;
		delete [] print_VALUE;
		//deallocate the memory since values are inserted into the ostream object
		delete print_obj;
		return os;
	}

private:
	static inline limb_t base64_to_value(const char &b64);

public:
#ifdef UBINT_32
	static const std::string IntegerTypeName() { return "UBINT_32"; }
#endif
#ifdef UBINT_64
	static const std::string IntegerTypeName() { return "UBINT_64"; }
#endif

	/**
	 * Compares the current ubint to ubint a.
	 *
	 * @param a is the ubint to be compared with.
	 * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
	 */
	int Compare(const ubint& a) const;

	/**
	 *  Set this int to 1.
	 */
	inline void SetIdentity() { *this = 1; };

	/**
	 * A zero allocator that is called by the Matrix class. It is used to initialize a Matrix of ubint objects.
	 */
	static unique_ptr<ubint> Allocator();

	/**
	 * Gets the state of the ubint from the internal value.
	 */
	const std::string GetState()const;

	/**
	 * function that returns the ubint after multiplication by b.
	 * @param b is the number to be multiplied.
	 * @return the ubint after the multiplication.
	 */
	inline ubint MulIntegerByLimb(limb_t b) const; //todo rename to ubint


	/**
	 * documentation function, prints sizes of constats.
	 * @param none
	 * @return none
	 */
	void PrintIntegerConstants(void);

	/**
	 * Gets the bit at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return resulting bit.
	 */
	uschar GetBitAtIndex(usint index) const;


protected:

	/**
	 * Converts the string v into base-r integer where r is equal to 2^bitwidth of limb data type.
	 *
	 * @param v The input string
	 */
	void AssignVal(const std::string& v);

	/**
	 * Sets the MSB to the correct value as computed from the internal value.
	 */
	void SetMSB();

	/**
	 * Sets the MSB to the correct value from the ubint.
	 * @param guessIdxChar is the hint of the MSB position.
	 */
	void SetMSB(usint guessIdxChar);



private:

	/**
	 * Normalize limb storage of the ubint by making sure the most
	 * significant limb is non-zero (all higher zero limbs are
	 * removed).
	 *
	 * @return resulting bit.
	 */
	void NormalizeLimbs(void);



	/**
	 * Sets the limb value at the specified index.
	 *
	 * @param index is the index of the limb to set in the ubint storage.
	 * //todo should be renamed SetLimbAtIndex();
	 */
	void SetIntAtIndex(usint idx, limb_t value);


	/**
	 * helper function for Div
	 * @param defined in ubint.cpp
	 */

	int divqr_vect(ubint& q, ubint& r, const ubint& u, const ubint& v) const;

	int divr_vect(ubint& r, const ubint& u, const ubint& v) const;
	int divq_vect(ubint& q, const ubint& u, const ubint& v) const;

private:
	//vector storing the native integers. stored little endian
	vector<limb_t> m_value;

private:
	//variable that stores the MOST SIGNIFICANT BIT position in the
	size_t m_MSB;

	//variable to store the bitlength of the limb data type.
	static const usint m_limbBitLength;

	//variable to store the maximum value of the limb data type.
	static const limb_t m_MaxLimb;

	//variable to store the log(base 2) of the number of bits in the limb data type.
	static const usint m_log2LimbBitLength;

	//variable to store the size of the data array.
	static const usint m_nSize;

	//The maximum number of digits in biginteger. It is used by the cout(ostream) function for printing the bignumber.
	//Todo remove this limitation
	static const usint m_numDigitInPrintval=1500; //todo get rid of m_numDigitInPrintval

	/**
	 * function to return the ceiling of the input number divided by
	 * the number of bits in the limb data type.  DBC this is to
	 * determine how many limbs are needed for an input bitsize.
	 * @param Number is the number to be divided.
	 * @return the ceiling of Number/(bits in the limb data type)
	 */
	static usint ceilIntByUInt(const limb_t Number); //todo rename to MSB2NLimbs()

	//currently unused array
	static const ubint *m_modChain;


private:
	/**
	 * function to return the MSB of number.
	 * @param x is the number.
	 * @return the MSB position in the number x.Note MSB(1) is 1 NOT zero!!!!!
	 */

	inline static usint GetMSBlimb_t(limb_t x) { return lbcrypto::GetMSB64(x); }

	//Dlimb_t is the data type that has twice as many bits in the limb data type.
	typedef typename DoubleDataType<limb_t>::T Dlimb_t;

	//Slimb_t is the data type that as many bits in the limb data type but is signed.
	typedef typename SignedDataType<limb_t>::T Slimb_t;

	//Slimb_t is the data type that as many bits in the limb data type but is signed.
	typedef typename SignedDoubleDataType<limb_t>::T Sdlimb_t;


	//enum defination to represent the state of the ubint.
	enum State{
		INITIALIZED,GARBAGE
	};

	/**
	 * function to return the MSB of number that is of type Dlimb_t.
	 * @param x is the number.
	 * @return the MSB position in the number x. Note MSB(1) is 1 NOT zero!!!!!
	 */
	inline static usint GetMSBDlimb_t(Dlimb_t x) { return lbcrypto::GetMSB64(x); }

	//enum to store the state of the
	State m_state;


	/**
	 * function that returns the decimal value from the binary array a.
	 * @param a is a pointer to the binary array.
	 * @return the decimal value.
	 */
	static limb_t UintInBinaryToDecimal(uschar *a);

	/**
	 * function that mutiplies by 2 to the binary array.
	 * @param a is a pointer to the binary array.
	 */
	static void double_bitVal(uschar *a);

	/**
	 * function that adds bit b to the binary array.
	 * @param a is a pointer to the binary array.
	 * @param b is a bit value to be added.
	 */
	static void add_bitVal(uschar* a,uschar b);
};

// stream helper function for vector of objects
template < typename limb_t >
inline std::ostream& operator << (std::ostream& os, const std::vector<limb_t>& v) {
	os << "[";
	for (const auto& itr : v){
		os << " " << itr;
	}
	os << " ]";
	return os;
};

}//namespace ends

#endif //LBCRYPTO_MATH_EXPINT_UBINT_H

