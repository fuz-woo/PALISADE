/**
 * @file binint.h This file contains the vector manipulation functionality.
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
 * This file contains the main class for big integers: BigInteger. Big integers are represented
 * as arrays of native usigned integers. The native integer type is supplied as a template parameter.
 * Currently implementations based on uint8_t, uint16_t, and uint32_t are supported. The second template parameter
 * is the maximum bitwidth for the big integer.
 */

#ifndef LBCRYPTO_MATH_CPUINT_BININT_H
#define LBCRYPTO_MATH_CPUINT_BININT_H

#include <iostream>
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
#include "../../utils/inttypes.h"
#include "../../utils/memory.h"
#include "../../utils/palisadebase64.h"
#include "../native_int/binint.h"

/**
*@namespace cpu_int
* The namespace of cpu_int
*/
namespace cpu_int{

	/**The following structs are needed for initialization of BigInteger at the preprocessing stage.
	*The structs compute certain values using template metaprogramming approach and mostly follow recursion to calculate value(s).
	*/

    /**
    * @brief  Struct to find log value of N.
    *Needed in the preprocessing step of BigInteger to determine bitwidth.
	*
	* @tparam N bitwidth.
    */
	template <usint N>
	struct Log2{
		const static usint value = 1 + Log2<N/2>::value;
	};
    
    /**
    * @brief Struct to find log value of N.
	*Base case for recursion.
    *Needed in the preprocessing step of BigInteger to determine bitwidth.
    */
	template<>
	struct Log2<2>{
		const static usint value = 1;
	};
    
    /**
    * @brief Struct to find log value of U where U is a primitive datatype.
    *Needed in the preprocessing step of BigInteger to determine bitwidth.
	*
	* @tparam U primitive data type.
    */
	template <typename U>
	struct LogDtype{
		const static usint value = Log2<8*sizeof(U)>::value;
	};
    
    /**
    * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}
    *
	* @tparam Dtype primitive datatype.
    */
	template<typename Dtype>
	struct DataTypeChecker{
		 const static bool value = false ;
	};

    /**
    * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}. 
    * sets value true if datatype is unsigned integer 8 bit.
    */
	template<>
	struct DataTypeChecker<uint8_t>{
		const static bool value = true ;
	};

    /**
    * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}. 
    * sets value true if datatype is unsigned integer 16 bit.
    */
	template<>
	struct DataTypeChecker<uint16_t>{
		const static bool value = true ;	
	};

    /**
    * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}.
    * sets value true if datatype is unsigned integer 32 bit.
    */
	template<>
	struct DataTypeChecker<uint32_t>{
		const static bool value = true ;	
	};

    /**
    * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}.
    * sets value true if datatype is unsigned integer 64 bit.
    */
	template<>
	struct DataTypeChecker<uint64_t>{
		const static bool value = true ;	
	};

	/**
    * @brief Struct for calculating bit width from data type. 
	* Sets value to the bitwidth of uint_type
	*
	* @tparam uint_type native integer data type.
    */
	template <typename uint_type>
	struct UIntBitWidth{
		const static int value = 8*sizeof(uint_type);
	};

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
    * Sets T as of type unsigned integer 16 bit if integral datatype is 8bit
    */
	template<>
	struct DoubleDataType<uint8_t>{
		typedef uint16_t T;
	};

    /**
    * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
    * sets T as of type unsigned integer 32 bit if integral datatype is 16bit
    */
    template<>
	struct DoubleDataType<uint16_t>{
		typedef uint32_t T;
	};

    /**
    * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
    * sets T as of type unsigned integer 64 bit if integral datatype is 32bit
    */
	template<>
	struct DoubleDataType<uint32_t>{
		typedef uint64_t T;
	};

//this is to support the multiprecision backend running over uint64_t limbs
//__uint128_t is not supported by VC++
#if !defined(_MSC_VER)
    /**
    * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
    * sets T as of type unsigned integer 128 bit if integral datatype is 64bit
    */
	template<>
	struct DoubleDataType<uint64_t>{
		typedef __uint128_t T;
	};
#endif



    const double LOG2_10 = 3.32192809;	//!< @brief A pre-computed constant of Log base 2 of 10.
    const usint BARRETT_LEVELS = 8;		//!< @brief The number of levels (precomputed values) used in the Barrett reductions.


	/**
	 * @brief Main class for big integers represented as an array of native (primitive) unsigned integers
	 * @tparam uint_type native unsigned integer type
	 * @tparam BITLENGTH maximum bitdwidth supported for big integers
	 */
	template<typename uint_type,usint BITLENGTH>
	class BigInteger
	{

	public:

    /**
    * Default constructor.
    */
    BigInteger();

    /**
    * Basic constructor for specifying the integer.
    *
    * @param str is the initial integer represented as a string.
    */
    explicit BigInteger(const std::string& str);

    /**
    * Basic constructor for initializing big binary integer from an unsigned integer.
    *
    * @param init is the initial integer.
    */
    BigInteger(uint64_t init);

    /**
    * Basic constructor for copying a big binary integer
    *
    * @param bigInteger is the big binary integer to be copied.
    */
    BigInteger(const BigInteger& bigInteger);
   
    /**
    * Destructor.
    */
    ~BigInteger();
        
    /**
    * Assignment operator
    *
    * @param &rhs is the big binary integer to be assigned from.
    * @return assigned BigInteger ref.
    */
    const BigInteger&  operator=(const BigInteger &rhs);

	/**
    * Assignment operator from unsigned integer
    *
    * @param val is the unsigned integer value that is assigned.
    * @return the assigned BigInteger ref.
    */
    inline const BigInteger& operator=(usint val) {
        *this = intToBigInteger(val);
        return *this;
    }

	
//Shift Operators
   
	/**
    * Left shift operator of big binary integer
    * @param shift is the amount to shift of type usshort.
    * @return the object of type BigInteger
    */
	BigInteger  operator<<(usshort shift) const;

    /**
    * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
    *
    * @param shift is the amount to shift of type usshort.
    * @return the object of type BigInteger
    */
    const BigInteger&  operator<<=(usshort shift);
        
    /**
    * Right shift operator of big binary integer
    * @param shift is the amount to shift of type usshort.
    * @return the object of type BigInteger
    */
    BigInteger  operator>>(usshort shift) const;

    /**
    * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
    *
    * @param shift is the amount to shift of type usshort.
    * @return the object of type BigInteger
    */
    BigInteger&  operator>>=(usshort shift);

//Auxillary Functions

    /**
    * Prints the value of the internal limb storage
    * in decimal format. Used primarily for debugging
    */
    void PrintLimbsInDec() const;

    /**
    * Prints the value of the internal limb storage
    * in hexadecimal format. Used primarily for debugging
    */
    void PrintLimbsInHex() const;

    /**
    * Basic set method for setting the value of a big binary integer
    *
    * @param str is the string representation of the big binary integer to be copied.
    */
    void SetValue(const std::string& str);
        
	//FIXME this is not implemented
    /**
    * Basic set method for setting the value of a big binary integer
    *
    * @param a is the big binary integer representation of the big binary integer to be assigned.
    */
    void SetValue(const BigInteger& a);

    /**
    * Returns the MSB location of the value.
    *
    * @return the index of the most significant bit.
    */
    usshort GetMSB()const;

    /**
    * Converts the value to an int.
    *
    * @return the int representation of the value as uint64_t.
    */
    uint64_t ConvertToInt() const;
    
	/**
    * Converts the value to an double.
    *
    * @return double representation of the value.
    */
    double ConvertToDouble() const;

	/**
	 * Convert a value from an int to a BigInteger.
	 *
	 * @param m the value to convert from.
	 * @return int represented as a big binary int.
	 */
	static BigInteger intToBigInteger(usint m);

//Arithmetic Operations

    /**
    * Addition operation.
    *
    * @param b is the value to add of type BigInteger.
    * @return result of the addition operation of type BigInteger.
    */
    BigInteger Plus(const BigInteger& b) const;

		
    /**
    * Addition accumulator.
    *
    * @param &b is the value to add of type BigInteger.
    * @return result of the addition operation of type BigInteger.
    */
    const BigInteger& operator+=(const BigInteger &b);

		
    /**
    * Subtraction accumulator.
    *
    * @param &b is the value to subtract of type BigInteger.
    * @return result of the subtraction operation of type BigInteger.
    */
    const BigInteger& operator-=(const BigInteger &b);

    /**
    * Subtraction operation.
    *
    * @param b is the value to subtract of type BigInteger.
    * @return result of the subtraction operation of type BigInteger.
    */
    BigInteger Minus(const BigInteger& b) const;
      
    /**
    * Multiplication operation. Pointer is used to minimize the number of BigInteger instantiations.
    *
    * @param b of type BigInteger is the value to multiply with.
	* @param *ans - stores the result
    * @return result of the multiplication operation.
    */
    void Times(const BigInteger& b, BigInteger *ans) const;

    /**
    * Division operation.
    *
    * @param b of type BigInteger is the value to divide by.
    * @return result of the division operation.
    */
    BigInteger DividedBy(const BigInteger& b) const;

//modular arithmetic operations
		
    /**
    * returns the modulus with respect to the input value. Classical modular reduction algorithm is used.
    *
    * @param modulus is value of the modulus to perform. Its of type BigInteger.
    * @return BigInteger that is the result of the modulus operation.
    */
    BigInteger Mod(const BigInteger& modulus) const;
    
    /**
    * returns the modulus with respect to the input value.
	* Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
	* See the cpp file for details of the implementation. 
    *
    * @param modulus is the modulus to perform.
    * @param mu is the Barrett value.
    * @return is the result of the modulus operation.
    */
    BigInteger ModBarrett(const BigInteger& modulus, const BigInteger& mu) const;

	/**
	* returns the modulus with respect to the input value - In place version.
	* Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
	* See the cpp file for details of the implementation.
	*
	* @param modulus is the modulus to perform.
	* @param mu is the Barrett value.
	* @return is the result of the modulus operation.
	*/
	void ModBarrettInPlace(const BigInteger& modulus, const BigInteger& mu);

    /**
    * returns the modulus with respect to the input value.
	* Implements generalized Barrett modular reduction algorithm. Uses an array of precomputed values \mu.
	* See the cpp file for details of the implementation. 
    *
    * @param modulus is the modulus to perform operations with.
    * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
    * @return result of the modulus operation.
    */
    BigInteger ModBarrett(const BigInteger& modulus, const BigInteger mu_arr[BARRETT_LEVELS+1]) const;

    /**
    * returns the modulus inverse with respect to the input value.
    *
    * @param modulus is the modulus to perform.
    * @return result of the modulus inverse operation.
    */
    BigInteger ModInverse(const BigInteger& modulus) const;

    /**
    * Scalar modular addition.
    *
    * @param &b is the scalar to add.
    * @param modulus is the modulus to perform operations with.
    * @return result of the modulus addition operation.
    */
    BigInteger ModAdd(const BigInteger& b, const BigInteger& modulus) const;

    /**
    * Modular addition where Barrett modulo reduction is used.
    *
    * @param &b is the scalar to add.
    * @param modulus is the modulus to perform operations with.
    * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
    * @return is the result of the modulus addition operation.
    */
    BigInteger ModBarrettAdd(const BigInteger& b, const BigInteger& modulus,const BigInteger mu_arr[BARRETT_LEVELS]) const;

    /**
    * Modular addition where Barrett modulo reduction is used.
    *
    * @param &b is the scalar to add.
    * @param modulus is the modulus to perform operations with.
    * @param mu is one precomputed Barrett value.
    * @return is the result of the modulus addition operation.
    */
    BigInteger ModBarrettAdd(const BigInteger& b, const BigInteger& modulus,const BigInteger& mu) const;

    /**
    * Scalar modular subtraction.
    *
    * @param &b is the scalar to subtract.
    * @param modulus is the modulus to perform operations with.
    * @return result of the modulus subtraction operation.
    */
    BigInteger ModSub(const BigInteger& b, const BigInteger& modulus) const;

    /**
    * Scalar modular subtraction where Barrett modular reduction is used.
    *
    * @param &b is the scalar to subtract.
    * @param modulus is the modulus to perform operations with.
    * @param mu is the Barrett value.
    * @return is the result of the modulus subtraction operation.
    */
    BigInteger ModBarrettSub(const BigInteger& b, const BigInteger& modulus,const BigInteger& mu) const;

    /**
    * Scalar modular subtraction where Barrett modular reduction is used.
    *
    * @param b is the scalar to subtract.
    * @param modulus is the modulus to perform operations with.
    * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
    * @return is the result of the modulus subtraction operation.
    */
    BigInteger ModBarrettSub(const BigInteger& b, const BigInteger& modulus,const BigInteger mu_arr[BARRETT_LEVELS]) const;

    /**
    * Scalar modulus multiplication.
    *
    * @param &b is the scalar to multiply.
    * @param modulus is the modulus to perform operations with.
    * @return is the result of the modulus multiplication operation.
    */
    BigInteger ModMul(const BigInteger& b, const BigInteger& modulus) const;

    /**
    * Scalar modular multiplication where Barrett modular reduction is used.
	* Implements generalized Barrett modular reduction algorithm (no interleaving between multiplication and modulo). 
	* Uses one precomputed value \mu.
	* See the cpp file for details of the implementation. 
    *
    * @param b is the scalar to multiply.
    * @param modulus is the modulus to perform operations with.
    * @param mu is the precomputed Barrett value.
    * @return is the result of the modulus multiplication operation.
    */
    BigInteger ModBarrettMul(const BigInteger& b, const BigInteger& modulus,const BigInteger& mu) const;

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
	void ModBarrettMulInPlace(const BigInteger& b, const BigInteger& modulus, const BigInteger& mu);

    /**
    * Scalar modular multiplication where Barrett modular reduction is used.
    *
    * @param &b is the scalar to multiply.
    * @param modulus is the modulus to perform operations with.
    * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
    * @return is the result of the modulus multiplication operation.
    */
    BigInteger ModBarrettMul(const BigInteger& b, const BigInteger& modulus,const BigInteger mu_arr[BARRETT_LEVELS]) const;

    /**
    * Scalar modular exponentiation. Square-and-multiply algorithm is used.
    *
    * @param &b is the scalar to exponentiate.
    * @param modulus is the modulus to perform operations with.
    * @return is the result of the modulus exponentiation operation.
    */
    BigInteger ModExp(const BigInteger& b, const BigInteger& modulus) const;

    /**
    * Stores the based 10 equivalent/Decimal value of the BigInteger in a string object and returns it.
    *
    * @return value of this BigInteger in base 10 represented as a string.
    */
    const std::string ToString() const;		

    const std::string Serialize(const BigInteger& mod = BigInteger::ZERO) const;
    const char * Deserialize(const char * str, const BigInteger& mod = BigInteger::ZERO);
    static const std::string IntegerTypeName() { return "BBI"; }


    /**
    * Tests whether the BigInteger is a power of 2.
    *
    * @param m_numToCheck is the value to check.
    * @return true if the input is a power of 2, false otherwise.
    */
    bool CheckIfPowerOfTwo(const BigInteger& m_numToCheck);

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
	* Convert a string representation of a binary number to a decimal BigInteger.
	*
	* @param bitString the binary num in string.
	* @return the binary number represented as a big binary int.
	*/
    static BigInteger BitStringToBigInteger(const std::string& bitString);

	/**
	* Exponentiation of a BigInteger x. Returns x^p
	*
	* @param p the exponent.
	* @return the big binary integer x^p.
	*/
    BigInteger Exp(usint p) const;

	/**
	* Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where [] is the rounding operation.
	*
	* @param p is the numerator to be multiplied.
	* @param q is the denominator to be divided.
	* @return the result of multiply and round.
	*/
	BigInteger MultiplyAndRound(const BigInteger &p, const BigInteger &q) const;

	/**
	* Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is the rounding operation.
	*
	* @param q is the denominator to be divided.
	* @return the result of divide and round.
	*/
	BigInteger DivideAndRound(const BigInteger &q) const;

    /**
    * Test equality of the inputs.
    *
    * @param a second value to test.
    * @return true if the inputs are equal.
    */
    bool operator==(const BigInteger& a) const;

    /**
    * Test inequality of the inputs.
    *
    * @param a second value to test.
    * @return true if the inputs are inequal.
    */
    bool operator!=(const BigInteger& a) const;

    /**
    * Test if first input is great than the second input.
    *
    * @param a second value to test.
    * @return true if the first inputs is greater.
    */
    bool operator> (const BigInteger& a) const;

    /**
    * Test if first input is great than or equal to the second input.
    *
    * @param a second value to test.
    * @return true if the first inputs is greater than or equal to the second input.
    */
    bool operator>=(const BigInteger& a) const;

    /**
    * Test if first input is less than the second input.
    *
    * @param a second value to test.
    * @return true if the first inputs is lesser.
    */
    bool operator< (const BigInteger& a) const;

    /**
    * Test if first input is less than or equal to the second input.
    *
    * @param a second value to test.
    * @return true if the first inputs is less than or equal to the second input.
    */
    bool operator<=(const BigInteger& a) const;

	/**
	 * Unary minus on a lattice
	 * @return
	 */
    BigInteger operator-() const {
		return BigInteger(0).Minus(*this);
	}


    //overloaded binary operators based on integer arithmetic and comparison functions
    /**
    * Addition operation.
    *
    * @param a is the value to add.
    * @return is the result of the addition operation.
    */
    inline BigInteger operator+(const BigInteger &a) const {return this->Plus(a);}

    /**
    * Subtraction operation.
    *
    * @param a is the value to subtract.
    * @return is the result of the subtraction operation.
    */
    inline BigInteger operator-(const BigInteger &a) const {return this->Minus(a);}

    /**
    * Multiplication operation.
    *
    * @param a is the value to multiply with.
    * @return is the result of the multiplication operation.
    */
	inline BigInteger operator*(const BigInteger &a) const;

    /**
    * Modulo operation. Classical modular reduction algorithm is used.
    *
    * @param a is the value to Mod.
    * @return is the result of the modulus operation.
    */
    inline BigInteger operator%(const BigInteger &a) const {return this->Mod(a);}

	/**
	 * Division operation.
	 *
	 * @param a is the value to divide.
	 * @param b is the value to divide by.
	 * @return is the result of the integral part after division operation.
	 */
	inline BigInteger operator/ (const BigInteger &a) const {return this->DividedBy(a);}


	inline BigInteger operator/=(const BigInteger &a); 

	/**
	 * Console output operation.
	 *
	 * @param os is the std ostream object.
	 * @param ptr_obj is BigInteger to be printed.
	 * @return is the ostream object.
	 */
    template<typename uint_type_c,usint BITLENGTH_c>
	friend std::ostream& operator<<(std::ostream& os, const BigInteger<uint_type_c,BITLENGTH_c> &ptr_obj);
    
    void PrintValues() const { std::cout << *this; }

	/**
    * Gets the bit at the specified index.
    *
    * @param index is the index of the bit to get.
    * @return resulting bit.
    */
    uschar GetBitAtIndex(usint index) const;

	/**
    * Gets the 6 bits at the specified index. Right fill with 0
    *
    * @param index is the index of the bit to get.
    * @return resulting bit.
    */
    uschar Get6BitsAtIndex(usint index) const;

	/**
	* Sets the int value at the specified index.
	*
	* @param index is the index of the int to set in the uint array.
	*/
	void SetIntAtIndex(usint idx, uint_type value);
        
    //constant definations
        
    /**
    * Constant zero.
    */
    static const BigInteger ZERO;

    /**
    * Constant one.
    */
    static const BigInteger ONE;

    /**
    * Constant two.
    */
    static const BigInteger TWO;

    /**
    * Constant three.
    */
    static const BigInteger THREE;

    /**
    * Constant four.
    */
    static const BigInteger FOUR;

    /**
    * Constant five.
    */
    static const BigInteger FIVE;
    
	/**
    * Compares the current BigInteger to BigInteger a.
    *
    * @param a is the BigInteger to be compared with.
    * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
    */
    sint Compare(const BigInteger& a) const;

    /**
     *  Set this int to 1.
     */
	inline void SetIdentity() { *this = BigInteger::ONE; };

	/**
	* A zero allocator that is called by the Matrix class. It is used to initialize a Matrix of BigInteger objects.
	*/
	static unique_ptr<BigInteger> Allocator();

    protected:
    
	/**
    * Converts the string v into base-r integer where r is equal to 2^bitwidth of integral data type.
    *
    * @param v The input string
    */
    void AssignVal(const std::string& v);

    /**
    * Sets the MSB to the correct value from the BigInteger.
    */
    void SetMSB();

	/**
    * Sets the MSB to the correct value from the BigInteger.
	* @param guessIdxChar is the hint of the MSB position.
    */
    void SetMSB(usint guessIdxChar);

	private:

		//array storing the native integers.
		// array size is the ceiling of BITLENGTH/(bits in the integral data type)
		uint_type m_value[(BITLENGTH+8*sizeof(uint_type)-1)/(8*sizeof(uint_type))];

		//variable that stores the MOST SIGNIFICANT BIT position in the number.
		usshort m_MSB;

		//variable to store the bit width of the integral data type.
		static const uschar m_uintBitLength;

		//variable to store the maximum value of the integral data type.
		static const uint_type m_uintMax;

		//variable to store the log(base 2) of the number of bits in the integral data type.
		static const uschar m_logUintBitLength;

		//variable to store the size of the data array.
		static const usint m_nSize;

		//The maximum number of digits in bigbinaryinteger. It is used by the cout(ostream) function for printing the bigbinarynumber.
		static const usint m_numDigitInPrintval;

		/**
		* function to return the ceiling of the number divided by the number of bits in the integral data type.
		* @param Number is the number to be divided.
		* @return the ceiling of Number/(bits in the integral data type)
		*/
		static uint_type ceilIntByUInt(const uint_type Number);

		//currently unused array
		static const BigInteger *m_modChain;
		
		/**
		* function to return the MSB of number.
		* @param x is the number.
		* @return the MSB position in the number x.
		*/
		
		static usint GetMSBUint_type(uint_type x);
		
		//Duint_type is the data type that has twice as many bits in the integral data type.
		typedef typename DoubleDataType<uint_type>::T Duint_type;

		/**
		* function to return the MSB of number that is of type Duint_type.
		* @param x is the number.
		* @return the MSB position in the number x.
		*/
		static usint GetMSBDUint_type(Duint_type x);
		
		/**
		* function that returns the BigInteger after multiplication by b.
		* @param b is the number to be multiplied.
		* @return the BigInteger after the multiplication.
		*/
        BigInteger MulIntegerByChar(uint_type b) const;

		/**
		* function that returns the BigInteger after multiplication by b.
		* the pointer argument is used to minimize the number of BigInteger instantiations
		* @param b is the number to be multiplied.
		* @param ans - where result is stored ("in-place")
		*/
		void MulIntegerByCharInPlace(uint_type b, BigInteger *ans) const;
		
		/**
		* function that returns the decimal value from the binary array a.
		* @param a is a pointer to the binary array.
		* @return the decimal value.
		*/
		static uint_type UintInBinaryToDecimal(uschar *a);

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

}//namespace ends

#endif
