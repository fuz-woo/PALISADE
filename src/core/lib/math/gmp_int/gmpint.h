/**
 * @file gmpint.h  This file contains the C++ code for implementing the main class for
 * big integers: gmpint which replaces BBI and uses NTL
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

#ifndef LBCRYPTO_MATH_GMPINT_GMPINT_H
#define LBCRYPTO_MATH_GMPINT_GMPINT_H



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
#include <exception>
#include "../../utils/exception.h"
#include "../../utils/inttypes.h"
#include "../../utils/memory.h"

#include "../../utils/debug.h"

#include <NTL/ZZ.h>
#include <NTL/ZZ_limbs.h>

/**
 *@namespace NTL
 * The namespace of this code
 */
namespace NTL{

// note that this backend does NOT use BARRETT_LEVELS or BARRETT
// all BARRETT functions use standard MOD arithmetic calls.
const usint BARRETT_LEVELS = 8;

//log2 constants
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

class myZZ : public NTL::ZZ, public lbcrypto::BigIntegerInterface<myZZ> {

public:

	myZZ();
	myZZ(uint64_t a);
	myZZ(const std::string &s);
	myZZ(const NTL::ZZ &a);

	//movecopy allocators (very important for efficiency)
	myZZ(NTL::ZZ &&a);

	//todo: figure out how to do && for wrapper
	//myZZ(NTL::myZZ_p &&a);

	myZZ(const NativeInteger& n) : myZZ(n.ConvertToInt()) {}

	const myZZ& operator=(const myZZ &rhs);

	const myZZ& operator=(uint64_t val){
		*this = myZZ(val);
		return *this;
	}

	inline const myZZ& operator=(std::string valstr){
		*this = myZZ(valstr);
		return *this;
	}

	/**
	 * A zero allocator that is called by the Matrix class. It is used to initialize a Matrix of myZZ objects.
	 */
	static unique_ptr<myZZ> Allocator();

	//adapter kit that wraps ZZ with BACKEND 2 functionality

	usint GetMSB() const ;
	static const myZZ& zero();

	//palisade conversion methods
	uint64_t ConvertToInt() const;
	uint64_t ConvertToUint64() const;
	double ConvertToDouble() const;

	//comparison method inline for speed
	int Compare(const myZZ& a) const { return compare(*this,a); };

	//set this int to 1
	void SetIdentity(){*this=1;}

	//palisade arithmetic methods
	myZZ Plus(const myZZ& b) const {
		return *static_cast<const ZZ*>(this) + static_cast<const ZZ&>(b);
	}

	const myZZ& PlusEq(const myZZ& b) {
		*static_cast<ZZ*>(this) += static_cast<const ZZ&>(b);
		return *this;
	}

	//note that in Sub we return 0, if a<b
	myZZ Minus(const myZZ& b) const {
		return (*this<b) ? ZZ(0): (*static_cast<const ZZ*>(this) - static_cast<const ZZ&>(b));
	}

	const myZZ& MinusEq(const myZZ& b) {
		if (*this<b)
			*this = ZZ(0);
		else
			*static_cast<ZZ*>(this) -= static_cast<const ZZ&>(b);
		return *this;
	}

	myZZ Times(const myZZ& b) const { return *static_cast<const ZZ*>(this) * static_cast<const ZZ&>(b); }
	const myZZ& TimesEq(const myZZ& b) {
		*static_cast<ZZ*>(this) *= static_cast<const ZZ&>(b);
		return *this;
	}

	myZZ DividedBy(const myZZ& b) const {return *static_cast<const ZZ*>(this) / static_cast<const ZZ&>(b); }
	const myZZ& DividedByEq(const myZZ& b) {
		*static_cast<ZZ*>(this) /= static_cast<const ZZ&>(b);
		return *this;
	}

	myZZ Exp(const usint p) const {return power(*this,p);}

	//palisade modular arithmetic methods

	myZZ Mod(const myZZ& modulus) const {return *static_cast<const ZZ*>(this) % static_cast<const ZZ&>(modulus);}
	const myZZ& ModEq(const myZZ& modulus) {
		*static_cast<ZZ*>(this) %= static_cast<const ZZ&>(modulus);
		return *this;
	}

	myZZ ModBarrett(const myZZ& modulus, const myZZ& mu) const {return *static_cast<const ZZ*>(this) % static_cast<const ZZ&>(modulus);}
	void ModBarrettInPlace(const myZZ& modulus, const myZZ& mu) { *static_cast<ZZ*>(this) %= static_cast<const ZZ&>(modulus);}

	myZZ ModBarrett(const myZZ& modulus, const myZZ mu_arr[BARRETT_LEVELS+1]) const  {return *static_cast<const ZZ*>(this) % static_cast<const ZZ&>(modulus);}

	myZZ ModInverse(const myZZ& modulus) const {
		bool dbg_flag = false;
		DEBUGEXP(modulus);

		//Error if modulus is 0
		if(modulus == myZZ(0)){
			PALISADE_THROW(lbcrypto::math_error, "zero has no inverse");
		}
		myZZ tmp(0);
		try {
			tmp = InvMod(*this%modulus, modulus);
		} catch (InvModErrorObject &e) { //note this code requires NTL Excptions coto be turned on. TODO: provide alternative when that is off.

			std::stringstream errmsg;
			errmsg <<"ModInverse exception "
					<<" this: "<< *this<<	" modulus: "<< modulus
					<< "GCD("<<e.get_a()<< ","<< e.get_n()<<"!=1"<<std::endl;
			PALISADE_THROW (lbcrypto::math_error, errmsg.str());
		}
		return tmp;
	}

	myZZ ModAdd(const myZZ& b, const myZZ& modulus) const {
		return AddMod(this->Mod(modulus), b.Mod(modulus), modulus);
	}

	const myZZ& ModAddEq(const myZZ& b, const myZZ& modulus) {
		AddMod(*this, this->Mod(modulus), b.Mod(modulus), modulus);
		return *this;
	}

	//Fast version does not check for modulus bounds.
	myZZ ModAddFast(const myZZ& b, const myZZ& modulus) const {return AddMod(*this, b, modulus);}


	myZZ ModBarrettAdd(const myZZ& b, const myZZ& modulus,const myZZ& mu) const {
		return this->ModAdd(b%modulus, modulus);
	}

	//NOTE ModSub needs to return signed modulus (i.e. -1/2..q/2) in order
	//to be consistent with BE 2
	myZZ ModSub(const myZZ& b, const myZZ& modulus) const
	{
		bool dbg_flag = false;
		myZZ newthis(*this%modulus);
		myZZ newb(b%modulus);

		if (newthis>=newb) {
			myZZ tmp(SubMod(newthis, newb, modulus));  //normal mod sub

			DEBUG("in modsub submod tmp "<<tmp);
			return tmp;

		} else {
			myZZ tmp(newthis+modulus -newb) ;  //signed mod

			DEBUG("in modsub alt tmp "<<tmp);
			return tmp;
		}
	}

	const myZZ& ModSubEq(const myZZ& b, const myZZ& modulus)
	{
		bool dbg_flag = false;
		this->ModEq(modulus);
		myZZ newb(b%modulus);

		if (*this>=newb) {
			SubMod(*this, *this, newb, modulus);  //normal mod sub

			DEBUG("in modsub submod tmp "<< *this);
			return *this;

		} else {
			this->PlusEq(modulus);
			this->MinusEq(newb);  //signed mod

			DEBUG("in modsub alt tmp "<< *this);
			return *this;
		}
	}

	//Fast version does not check for modulus bounds.
	myZZ ModSubFast(const myZZ& b, const myZZ& modulus) const
	{
		if (*this>=b) {
			return SubMod(*this, b, modulus);  //normal mod sub
		} else {
			return (*this+modulus -b) ;  //signed mod
		}

	}

	myZZ ModBarrettSub(const myZZ& b, const myZZ& modulus,const myZZ& mu) const {
		return this->ModSub(b, modulus);
	}

	myZZ ModMul(const myZZ& b, const myZZ& modulus) const {
		return MulMod(this->Mod(modulus), b.Mod(modulus), modulus);
	}

	const myZZ& ModMulEq(const myZZ& b, const myZZ& modulus) {
		MulMod(*this, this->Mod(modulus), b.Mod(modulus), modulus);
		return *this;
	}

	//Fast version does not check for modulus bounds.
	inline myZZ ModMulFast(const myZZ& b, const myZZ& modulus) const {return MulMod(*this, b, modulus);};

	//    inline myZZ ModBarrettMul(const myZZ& b, const myZZ& modulus,const myZZ& mu) const {return MulMod(*this%modulus, b%modulus, modulus);};
	inline myZZ ModBarrettMul(const myZZ& b, const myZZ& modulus,const myZZ& mu) const {return MulMod(*this, b, modulus);};
	inline void ModBarrettMulInPlace(const myZZ& b, const myZZ& modulus,const myZZ& mu)  { *this = MulMod(*this, b, modulus);};

	//    inline myZZ ModBarrettMul(const myZZ& b, const myZZ& modulus,const myZZ mu_arr[BARRETT_LEVELS]) const  {return MulMod(*this%modulus, b%modulus, modulus);};
	inline myZZ ModBarrettMul(const myZZ& b, const myZZ& modulus,const myZZ mu_arr[BARRETT_LEVELS]) const  {return MulMod(*this, b, modulus);};

	inline myZZ ModExp(const myZZ& b, const myZZ& modulus) const {
		bool dbg_flag = false;
		//      myZZ res(*this);
		myZZ res;
		DEBUG("ModExp this :"<< *this);
		DEBUG("ModExp b:"<< b);
		DEBUG("ModExp modulus:"<< modulus);

		// PowerMod (res, res%modulus, b%modulus, modulus);
		PowerMod( res, *this, b, modulus);
		DEBUG("ModExp res:"<< res);
		return res;
	}; //(this^b)%modulus

	myZZ MultiplyAndRound(const myZZ &p, const myZZ &q) const;
	myZZ DivideAndRound(const myZZ &q) const;

	/**
	 * << operation
	 *
	 * @param shift # of bits
	 * @return result of the shift operation.
	 */
	myZZ LShift(usshort shift) const { return *static_cast<const ZZ*>(this) << shift; }

	/**
	 * <<= operation
	 *
	 * @param shift # of bits
	 * @return result of the shift operation.
	 */
	const myZZ& LShiftEq(usshort shift) {
		*static_cast<ZZ*>(this) <<= shift;
		return *this;
	}

	/**
	 * >> operation
	 *
	 * @param shift # of bits
	 * @return result of the shift operation.
	 */
	myZZ RShift(usshort shift) const { return *static_cast<const ZZ*>(this) >> shift; }

	/**
	 * >>= operation
	 *
	 * @param shift # of bits
	 * @return result of the shift operation.
	 */
	const myZZ& RShiftEq(usshort shift) {
		*static_cast<ZZ*>(this) >>= shift;
		return *this;
	}

	//big integer stream output
	friend std::ostream& operator<<(std::ostream& os, const myZZ&ptr_obj);

	//palisade string conversion
	const std::string ToString() const;

	/**
	 * Basic set method for setting the value of a myZZ
	 *
	 * @param str is the string representation of the ubint to be copied.
	 */
	void SetValue(const std::string& str);

	/**
	 * Basic set method for setting the value of a myZZ
	 *
	 * @param a is the unsigned big int representation to be assigned.
	 */
	void SetValue(const myZZ& a);

	//helper functions
	/**
	 * Convert a string representation of a binary number to a myZZ.
	 * Note: needs renaming to a generic form since the variable type name is
	 * embedded in the function name. Suggest FromBinaryString()
	 * @param bitString the binary num in string.
	 * @return the  number represented as a ubint.
	 */
	static myZZ FromBinaryString(const std::string& bitString);
	static myZZ BitStringToBigInteger(const std::string& bitString);

	/**
	 * Get the number of digits using a specific base - support for
	 * arbitrary base may be needed.
	 *
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetLengthForBase(usint base) const {return GetMSB();};

	/**
	 * Get the integer value of the of a subfield of bits.
	 * power-of-2 bases are currently supported.
	 *
	 * @param index is the bit location (lsb)
	 * @param base is the bitwidth of the subfield
	 * @return the integer value of the subfield
	 */
	usint GetDigitAtIndexForBase(usint index, usint base) const;

	//variable to store the log(base 2) of the number of bits in the
	//limb data type.
	static const usint m_log2LimbBitLength;

	//Serialization functions

	// note that for efficiency, we use [De]Serialize[To|From]String when serializing
	// BigVectors, and [De]Serialize otherwise (to work the same as all
	// other serialized objects.

	const std::string SerializeToString(const myZZ& mod = 0) const;
	const char * DeserializeFromString(const char * str, const myZZ& mod = 0);

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


	static const std::string IntegerTypeName() { return "NTL"; }


	/**
	 * Gets the bit at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return resulting bit.
	 */
	uschar GetBitAtIndex(usint index) const;

	/**
	 * Gets 6 bits at the specified index. Right fill with 0
	 *
	 * @param index is the index of the bit to get.
	 * @return resulting bits.
	 */
	uschar Get6BitsAtIndex(usint index) const;

	/**
	 * Gets a copy of the  internal limb storage
	 * Used primarily for debugging
	 */
	vector <ZZ_limb_t> GetInternalRepresentation(void) const {
		vector<ZZ_limb_t> ret;
		const ZZ_limb_t *zlp = ZZ_limbs_get(*this);

		for (size_t i = 0; i < (size_t)this->size(); i ++){
			ret.push_back(zlp[i]);
		}
		return ret;
	}

private:
	//adapter kits
	void SetMSB();

	/**
	 * function to return the ceiling of the input number divided by
	 * the number of bits in the limb data type.  DBC this is to
	 * determine how many limbs are needed for an input bitsize.
	 * @param Number is the number to be divided.
	 * @return the ceiling of Number/(bits in the limb data type)
	 */
	//todo: rename to MSB2NLimbs()
	static usint ceilIntByUInt(const ZZ_limb_t Number);

	mutable size_t m_MSB;
	usint GetMSBLimb_t( ZZ_limb_t x) const;
}; //class ends

NTL_DECLARE_RELOCATABLE((myZZ*))
}//namespace ends

#endif //LBCRYPTO_MATH_GMPINT_GMPINT_H


