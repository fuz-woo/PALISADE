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

  //todo: note that this backend does NOT use BARRET_LEVELS or BARRET
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

  class myZZ : public NTL::ZZ {

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

    //TODO: this mimics backend 2 should this be uint_64_t val?

    inline const myZZ& operator=(usint val){
      *this = myZZ(val);
      return *this;
    }

    inline const myZZ& operator=(std::string valstr){
      *this = myZZ(valstr);
      return *this;
    }

    static const myZZ ZERO;
    static const myZZ ONE;
    static const myZZ TWO;
    static const myZZ THREE;
    static const myZZ FOUR; 
    static const myZZ FIVE;

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

    //associated comparison operators
    inline long operator==(const myZZ& b) const {return this->Compare(b)==0;};
    inline long operator==(const usint& b) const {return this->Compare(b)==0;};
    inline long operator!=(const myZZ& b) const {return this->Compare(b)!= 0;};
    inline long operator!=(const usint& b) const {return this->Compare(b)!= 0;};
  
    //set this int to 1
    inline void SetIdentity(){*this=myZZ::ONE;};

    //palisade arithmetic methods all inline for speed
    //note OLD code uses Plus, new code uses Add etc. 
    inline myZZ Add(const myZZ& b) const {return *this+b;};
    inline myZZ Plus(const myZZ& b) const {return *this+b;}; //to be deprecated

    //note that in Sub we return 0, if a<b
    inline myZZ Sub(const myZZ& b) const {return((*this<b)? ZZ(0):( *this-b));};  
    inline myZZ Minus(const myZZ& b) const {return((*this<b)? ZZ(0):( *this-b));}; //to be deprecated

    inline myZZ operator+(const myZZ &b) const {
      myZZ tmp;
      add(tmp, *this, b);
      return tmp ;
    };

    //inline myZZ operator+(const ZZ &b) const {
    //  myZZ tmp;
    //  add(tmp, *this, b);
    //  return tmp ;
    //};

    // there are not equivalent versions of uint64_t in BE 2
    // but we need them because otherwise NTL tries to use a default operation
    inline myZZ operator+(const uint64_t& b) const {
      myZZ tmp;
      myZZ bzz(b);
      add(tmp, *this, bzz);
      return tmp ;
    }

    inline myZZ& operator +=(const myZZ &a) {
      *this = *this+a;
      return *this;
    };

    inline myZZ& operator +=(const uint64_t a) {
      *this = *this+a;
      return *this;
    };

    inline myZZ operator-(const myZZ &b) const {
      if (*this < b) { // should return 0
	return myZZ(0);
      }
      myZZ tmp;
      sub(tmp, *this, b);
      return tmp ;
    };

    inline myZZ operator-(const uint64_t &b) const {
      myZZ bzz(b);
      if (*this < bzz) { // should return 0
    	return myZZ(0);
      }
      myZZ tmp;
      sub(tmp, *this, bzz);
      return tmp ;
    };

    inline myZZ& operator -=(const myZZ &a) {
      if (*this<a) { // note b>a should return 0
	*this = myZZ(0);
	return *this;
      }
      *this = *this-a;
      return *this;
    };// note this<a should return 0


    inline myZZ& operator -=(const uint64_t a) {
      myZZ azz(a);      
      if (*this<azz) { // note b>a should return 0
	*this = myZZ(0);
	return *this;
      }
      *this = *this-azz;
      return *this;
    };// note this<a should return 0


    // Unary minus on a lattice
    myZZ operator-() const {
      return myZZ(0).Minus(*this);
    }

    myZZ& operator*=(const myZZ &a);

    myZZ& operator*=(const uint64_t &a);

    inline myZZ operator*(const myZZ& b) const {
      myZZ tmp;
      mul(tmp, *this, b);
      return tmp ;
    }

    inline myZZ operator*(const uint64_t b) const {
      myZZ tmp;
      myZZ bzz(b);
      mul(tmp, *this, bzz);
      return tmp ;
    }

    inline myZZ Mul(const myZZ& b) const {return *this*b;};
    //inline myZZ Times(const myZZ& b) const {return *this*b;}; //to be deprecated
    void Times(const myZZ& b, myZZ *ans) const {*ans=(*this*b); return;}; 
    inline myZZ Div(const myZZ& b) const {return *this/b;};
    inline myZZ DividedBy(const myZZ& b) const {return *this/b;};
    inline myZZ Exp(const usint p) const {return power(*this,p);};

    //palisade modular arithmetic methods all inline for speed

    inline myZZ Mod(const myZZ& modulus) const {return *this%modulus;};

    inline myZZ operator%(const myZZ &modulus) { 
#if 1 //dbc version not as efficient due to copies. 
      ZZ tmp = *this;
      ZZ tmod = modulus;
      myZZ ret = tmp%modulus; 
      return(ret);
#else //Tom P version has compile error
      //return( myZZ((ZZ)(*this)) % (ZZ)modulus) );
      return( myZZ(NTL::ZZ::operator%(*this,modulus)));
#endif
    }

    inline myZZ operator%(int modulus) { //apparently this was required by compiler
      ZZ tmp = *this;
      ZZ tmod(modulus);
      myZZ ret = tmp%modulus; 
      return(ret);

    }
    inline myZZ& operator%=(const myZZ &modulus) {*this = *this%modulus; return *this;};  
    inline myZZ& operator%=(const int &modulus) {*this = *this%modulus; return *this;};  

    inline myZZ ModBarrett(const myZZ& modulus, const myZZ& mu) const {return *this%modulus;};
    void ModBarrettInPlace(const myZZ& modulus, const myZZ& mu) { *this%=modulus;};

    inline    myZZ ModBarrett(const myZZ& modulus, const myZZ mu_arr[BARRETT_LEVELS+1]) const  {return *this%modulus;};
    inline myZZ ModInverse(const myZZ& modulus) const {
      bool dbg_flag = false;
      DEBUGEXP(modulus);

      //Error if modulus is ZERO
      if(modulus==ZERO){
	PALISADE_THROW(lbcrypto::math_error, "zero has no inverse");
      }
      myZZ tmp(myZZ::ZERO);
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
    };
    inline myZZ ModAdd(const myZZ& b, const myZZ& modulus) const {return myZZ(AddMod(*this%modulus, b%modulus, modulus));};
    //Fast version does not check for modulus bounds.
    inline myZZ ModAddFast(const myZZ& b, const myZZ& modulus) const {return AddMod(*this, b, modulus);};


    inline myZZ ModBarrettAdd(const myZZ& b, const myZZ& modulus,const myZZ& mu) const {
      return this->ModAdd(b%modulus, modulus);
    };


    //NOTE ModSub needs to return signed modulus (i.e. -1/2..q/2) in order
    //to be consistent with BE 2
    inline myZZ ModSub(const myZZ& b, const myZZ& modulus) const
    {
      bool dbg_flag = false;
      ZZ newthis(*this%modulus);
      ZZ newb(b%modulus);

      if (newthis>=newb) {
	ZZ tmp(SubMod(newthis, newb, modulus));  //normal mod sub    
	
	DEBUG("in modsub submod tmp "<<tmp);
	return tmp;

      } else {
	ZZ tmp(newthis+modulus -newb) ;  //signed mod
	
	DEBUG("in modsub alt tmp "<<tmp);
	return tmp;
      }
    };

    //Fast version does not check for modulus bounds.
    inline myZZ ModSubFast(const myZZ& b, const myZZ& modulus) const
    {
      if (*this>=b) {
	return SubMod(*this, b, modulus);  //normal mod sub    
      } else {
	return (*this+modulus -b) ;  //signed mod
      }

    };


    inline myZZ ModBarrettSub(const myZZ& b, const myZZ& modulus,const myZZ& mu) const {
      return this->ModSub(b, modulus);
    };

    inline myZZ ModMul(const myZZ& b, const myZZ& modulus) const {return myZZ(MulMod(*this%modulus, b%modulus, modulus));};
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


    //left and right shift operators
    inline myZZ operator>>(long n) const {return RightShift(*this, n);};
    inline myZZ operator<<(long n) const {return LeftShift(*this, n);};
    inline const myZZ& operator>>=(long n) {return *this=RightShift(*this, n);};
    inline const myZZ& operator<<=(long n) {return *this=LeftShift(*this, n);};

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
    //void SetValue(const char *s);

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

    const std::string SerializeToString(const myZZ& mod = myZZ::ZERO) const;
    const char * DeserializeFromString(const char * str, const myZZ& mod = myZZ::ZERO);

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


