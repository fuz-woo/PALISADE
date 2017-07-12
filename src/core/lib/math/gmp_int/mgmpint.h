/**
 * @file mgmpint.h This file contains the main class for unsigned big integers: ubint. Big
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
 /*
 *
 * This file contains the main class for unsigned big integers: ubint. Big
 * integers are represented as arrays of machine native unsigned integers. The
 * native integer type is supplied as a template parameter.  Currently
 * implementation based on uint32_t and uint64_t is
 * supported. a native double the base integer size is also needed.
 */

#ifndef LBCRYPTO_MATH_MGMPINT_MGMPINT_H
#define LBCRYPTO_MATH_MGMPINT_MGMPINT_H

#define WARN_BAD_MODULUS  //define to cause code to report when a bad modulus is trapped.
//#define PAUSE_BAD_MODULUS  //define to cause code to pause when a bad modulus is trapped.

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

#include "time.h"
#include <chrono>
#include "../../utils/debug.h"

#include <NTL/ZZ_p.h>
#include <NTL/ZZ_limbs.h>

/**
 *@namespace NTL
 * The namespace of this code
 */
namespace NTL{

  //class myZZ_p : public NTL::ZZ_p, NTL::ZZ { //ambiguous all over the place
  class myZZ_p : public NTL::ZZ_p {

  public:

    myZZ_p();
    // constructors without moduli
    explicit myZZ_p(int a);
    explicit myZZ_p(long a);
    explicit myZZ_p(unsigned long a);
    explicit myZZ_p(const unsigned int a);
    // explicit myZZ_p(const unsigned int &a);
    //explicit myZZ_p(unsigned int &a);
    explicit myZZ_p(std::string s);
    explicit myZZ_p(const char * s);
    //copy
    myZZ_p(NTL::ZZ &a);
    myZZ_p(const NTL::ZZ &a);
    myZZ_p(NTL::ZZ_p &a);
    myZZ_p(const NTL::ZZ_p &a);

    ///movecopy
    myZZ_p(NTL::ZZ &&a);
    myZZ_p(NTL::ZZ_p &&a);

    //constructors with moduli
    //myZZ moduli
    myZZ_p(int a, myZZ &q);
    myZZ_p(long a, myZZ &q);
    myZZ_p(unsigned long a, myZZ &q);
    myZZ_p(const unsigned int &a, myZZ &q);
    myZZ_p(unsigned int &a, myZZ &q);
    myZZ_p(std::string s, myZZ &q);
    myZZ_p(const char * s, myZZ &q);
    //copy with myZZ moduli
    myZZ_p(NTL::ZZ &a, myZZ &q);
    myZZ_p(const NTL::ZZ &a, myZZ &q);
    myZZ_p(NTL::ZZ_p &a, myZZ &q);
    myZZ_p(const NTL::ZZ_p &a, myZZ &q);

    //char * moduli
    myZZ_p(int a, const char *sq);
    myZZ_p(long a, const char *sq);
    myZZ_p(unsigned long a, const char *sq);
    myZZ_p(const unsigned int &a, const char *sq);
    myZZ_p(unsigned int &a, const char *sq);
    myZZ_p(std::string s, const char *sq);
    myZZ_p(const char * s, const char *sq);

    //copy with char * moduli
    myZZ_p(NTL::ZZ &a, const char *sq);
    myZZ_p(const NTL::ZZ &a, const char *sq);
    myZZ_p(NTL::ZZ_p &a, const char *sq);
    myZZ_p(const NTL::ZZ_p &a, const char *sq);

   //copy with unsigned int moduli
    myZZ_p(NTL::ZZ &a, unsigned int q);
    myZZ_p(const NTL::ZZ &a, unsigned int q);
    myZZ_p(NTL::ZZ_p &a, unsigned int q);
    myZZ_p(const NTL::ZZ_p &a, unsigned int q);

    //inline myZZ_p& operator=(const unsigned int a) {return myZZ_p((unsigned int)a);}

    // operator=
    inline myZZ_p& operator=(const char * s) {this->_ZZ_p__rep=conv<ZZ>(s); return *this;}
    inline myZZ_p& operator=(int a) {this->_ZZ_p__rep=conv<ZZ>(a); return *this;}

    //myZZ_p( ZZ_p && zzin) : ZZ_p(zzin), m_MSB(5){};
#if 0
    static const myZZ_p ZERO;
    static const myZZ_p ONE;
    static const myZZ_p TWO;
    static const myZZ_p THREE;
    static const myZZ_p FOUR;
    static const myZZ_p FIVE;
#endif

    //  void InitMyZZ_p(ZZ_p &&zzin) const {this->m_MSB = 1; return;}
    //adapter kit
    usint GetMSB() const;
    static const myZZ_p& zero();

    //palisade conversion methods 
    //usint ConvertToUsint() const;
    uint64_t ConvertToInt() const;
    //uint32_t ConvertToUint32() const;
    uint64_t ConvertToUint64() const;
    //float ConvertToFloat() const;
    double ConvertToDouble() const;
    //long double ConvertToLongDouble() const;

    //it has problems finding which clear to use

    //read  http://www.prenhall.com/divisions/esm/app/kafura/secure/chapter7/html/7.5_inheritance.htm
    //and see if we can figure out what happened.

    //inline void clear(myZZ_p& a) { clear(*this);}; //why can't I inherit this?
    //inline void clear(myZZ_p& a) { clear(a);}; //this compiled but calls ZZ_p:clear in perpetual loop. 
  
    //comparison method inline for speed
    inline sint Compare(const myZZ_p& a) const {
      bool dbg_flag = false;
      sint result = compare(this->_ZZ_p__rep,a._ZZ_p__rep); 
      DEBUG("in unmixed Compare this "<< *this <<" a "<< a<<" result "<< result);      
      //return compare(this->_ZZ_p__rep,a._ZZ_p__rep); 
      return result;
    };
    inline sint Compare(const myZZ& a) const {
      bool dbg_flag = false;
      sint result = compare(this->_ZZ_p__rep,a);
      DEBUG("in mixed Compare this "<< *this <<" a "<< a<<" result "<< result);      
      //return compare(this->_ZZ_p__rep,a); 
      return result;
    };
    inline sint Compare(const long int& a) const {return compare(this->_ZZ_p__rep,a); };


    inline sint Compare(const myZZ& a, const myZZ_p &b) const {return compare(a, this->_ZZ_p__rep); };
    inline sint Compare(const long int& a, const myZZ_p &b) const {return compare(a,this->_ZZ_p__rep); };

    inline sint Compare(const myZZ_p& a , const myZZ& b) const {return compare(a._ZZ_p__rep,b); };
    //comparisons against myZZ_p and myZZ_p
    inline long operator==(const myZZ_p& b) const
    { return this->Compare(b) == 0; }
    inline long operator!=( const myZZ_p& b) const
    { return this->Compare(b) != 0; }
    inline long operator<( const myZZ_p& b) const
    { return this->Compare(b) < 0; }
    inline long operator>( const myZZ_p& b) const
    { return this->Compare(b) > 0; }
    inline long operator<=( const myZZ_p& b) const
    { return this->Compare(b) <= 0; }
    inline long operator>=( const myZZ_p& b) const
    { return this->Compare(b) >= 0; }


    //comparisons against myZZ_p and myZZ
    inline long operator==(const myZZ& b) const
    { return this->Compare(b) == 0; }
    inline long operator!=( const myZZ& b) const
    { return this->Compare(b) != 0; }
    inline long operator<( const myZZ& b) const
    { return this->Compare(b) < 0; }
    inline long operator>( const myZZ& b) const
    { return this->Compare(b) > 0; }
    inline long operator<=( const myZZ& b) const
    { return this->Compare(b) <= 0; }
    inline long operator>=( const myZZ& b) const
    { return this->Compare(b) >= 0; }

    //comparisons with myZZ_p as the second term are defined at the end of the file outside of the object (to allow for two operands

    //palisade arithmetic methods all inline for speed
    inline myZZ_p operator+(const myZZ_p &b) const {
      myZZ_p tmp;
      add(tmp, *this, b);
      return tmp ;
    };

    inline myZZ_p& operator+=(const myZZ_p &a) {
      add(*this, *this, a);
      return *this;
    };

    inline myZZ_p Add(const myZZ_p& b) const {return *this+b;};
    inline myZZ_p Plus(const myZZ_p& b) const {return *this+b;}; //to be deprecated

    //NOTE ModSub needs to return signed modulus (i.e. -1/2..q/2) in order
    //to be consistent with BE 2 

    inline myZZ_p Sub(const myZZ_p& b) const  {return(*this-b);};  
    inline myZZ_p Minus(const myZZ_p& b) const  {return(*this-b);}; //to be deprecated
    inline myZZ_p operator-(const myZZ_p &b) const {
      if (*this>=b) {
	return this->ModSub(b);
      } else { 
	myZZ tmp;
	myZZ mod = this->GetModulus();
	tmp = this->_ZZ_p__rep + mod - b._ZZ_p__rep;
	myZZ_p ret(tmp, mod);

	return ret;

      }
    };

    inline myZZ_p& operator-=(const myZZ_p &a) {
      //sub(*this, *this, a);
      *this = *this-a;
      return *this;
    };

    ///new

    inline myZZ_p operator*(const myZZ_p &b) const {
      myZZ_p tmp;
      mul(tmp, *this, b);
      return tmp ;
    };
    inline myZZ_p& operator*=(const myZZ_p &a) {
      mul(*this, *this, a);
      return *this;
    };




    ///new


  
    inline myZZ_p Mul(const myZZ_p& b) const {return *this*b;};
    inline myZZ_p Times(const myZZ_p& b) const {return *this*b;}; //to be deprecated
    inline myZZ_p Div(const myZZ_p& b) const {return *this/b;};
    inline myZZ_p DividedBy(const myZZ_p& b) const {return *this/b;};
    inline myZZ_p Exp(const usint p) const {return power(*this,p);};

    /**
     * Multiply and Rounding operation on a big integer x. Returns [x*p/q] where [] is the rounding operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return the result of multiply and round.
     */
    myZZ_p MultiplyAndRound(const myZZ &p, const myZZ &q) const;
    
    /**
     * Divide and Rounding operation on a big integer x. Returns [x/q] where [] is the rounding operation.
     *
     * @param q is the denominator to be divided.
     * @return the result of divide and round.
     */
    myZZ_p DivideAndRound(const myZZ &q) const;

    //palisade modular arithmetic methods all inline for speed
    //note b can't be ZZ_p cause it can't hold it's modulus value.
    inline myZZ_p operator%(const myZZ &b) const
    {
      myZZ_p res;
      res = (this->_ZZ_p__rep)%b;
      return(res);
    };

    //note b can't be ZZ_p cause it can't hold it's modulus value.
    inline myZZ_p operator%(const unsigned int &b) const
    {
      myZZ_p res;
      res = (this->_ZZ_p__rep)%b;
      return(res);
    };

    inline myZZ_p& operator %=(const myZZ &a) {
      bool dbg_flag = false;
      DEBUG("mgmpint %= this before mod "<<*this);
      *this = *this%a;
      DEBUG("mgmpint %= this after mod "<<*this);
      return *this;
    };
    inline myZZ_p& operator %=(const unsigned int &a) {
      *this = *this%a;
      return *this;
    };
  
    //note Mod() == ModBarrett() of all forms. 
    inline myZZ_p Mod(const myZZ& modulus) const {return (this->_ZZ_p__rep)%modulus;};
    inline myZZ_p ModBarrett(const myZZ& modulus, const myZZ& mu) const {return (this->_ZZ_p__rep)%modulus;};
    inline    myZZ_p ModBarrett(const myZZ& modulus, const myZZ mu_arr[BARRETT_LEVELS+1]) const  {return (this->_ZZ_p__rep)%modulus;};

    inline myZZ_p ModInverse(const myZZ& modulus) const { return InvMod(this->_ZZ_p__rep,modulus);}; 


    inline myZZ_p ModAdd(const myZZ_p& b) const {return *this+b;};

    inline myZZ_p ModAdd(const myZZ& b, const myZZ& modulus) const {
      return myZZ_p(AddMod(this->_ZZ_p__rep%modulus, b%modulus, modulus));
    }; //to comply with BBI
    //Fast version does not check for modulus bounds.

    inline myZZ_p ModAddFast(const myZZ& b, const myZZ& modulus) const {
      return myZZ_p(AddMod(this->_ZZ_p__rep, b, modulus));
    };

    inline myZZ_p ModSub(const myZZ_p& b) const
    {
      bool dbg_flag = false;
      ZZ newthis(this->_ZZ_p__rep);
      ZZ newb(b._ZZ_p__rep);
      DEBUG("in myZZ_p::ModSub()this getOTM "<<this->m_getOTM());
      DEBUG("in myZZ_p::ModSub()this GetModulus "<<this->GetModulus());

      DEBUG("in myZZ_p::ModSub() b getOTM "<<b.m_getOTM());
      DEBUG("in myZZ_p::ModSub() b GetModulus "<<b.GetModulus());

      ZZ mod(this->GetModulus());
      if (newthis>=newb) {
	return myZZ_p(SubMod(newthis, newb, mod));  //normal mod sub    
      } else {
	return myZZ_p(newthis+mod -newb) ;  //signed mod
      }
    };

    inline myZZ_p ModSub(const myZZ& b, const myZZ&modulus) const //to comply with BBI
    {
      ZZ newthis(this->_ZZ_p__rep%modulus);
      ZZ newb(b%modulus);
      if (newthis>=newb) {
	return myZZ_p(SubMod(newthis, newb, modulus));  //normal mod sub    
      } else {
	return myZZ_p(newthis+modulus -b) ;  //signed mod
      }

    };

    //Fast version does not check for modulus bounds.
    inline myZZ_p ModSubFast(const myZZ& b, const myZZ& modulus) const
    {
      ZZ newthis(this->_ZZ_p__rep);
      if (newthis>=b) {
	return myZZ_p(SubMod(newthis, b, modulus));  //normal mod sub    
      } else {
	return myZZ_p(newthis+modulus -b) ;  //signed mod
      }
    };


    inline myZZ_p ModMul(const myZZ_p& b) const {return *this*b;};

    // some library code calls things this way as well because of
    //mixing of gmpint and mgmpint.

    inline myZZ_p ModMul(const myZZ& b, const myZZ& q) const {
      myZZ newthis(*this);
      newthis.ModMulFast(b, q);
      myZZ_p ans(newthis);
      return(ans);
    };

    inline myZZ_p ModBarrettMul(const myZZ_p& b, const myZZ& modulus,const myZZ_p& mu) const {return MulMod(this->_ZZ_p__rep, b._ZZ_p__rep, modulus);};

    inline myZZ_p ModBarrettMul(const myZZ_p& b, const myZZ& modulus,const myZZ mu_arr[BARRETT_LEVELS]) const  {return MulMod(this->_ZZ_p__rep, b._ZZ_p__rep, modulus);};

    inline myZZ_p ModExp(const myZZ_p& b, const myZZ& modulus) const {
      //return PowerMod(this->_ZZ_p__rep, b._ZZ_p__rep, modulus);};
      
      bool dbg_flag = false;
      myZZ res(*this); 
      DEBUG("ModExp this :"<< *this);
      DEBUG("ModExp b:"<< b);
      DEBUG("ModExp modulus:"<< modulus);
      PowerMod (res, res%modulus, b._ZZ_p__rep%modulus, modulus); 
      DEBUG("ModExp res:"<< res);
      return myZZ_p(res);
    }; //(this^b)%modulus
    

    friend std::ostream& operator<<(std::ostream& os, const myZZ_p&ptr_obj);

    //palisade string conversion
    const std::string ToString() const;	

    //public modulus accessors

    inline bool isModulusSet(void) const{
      return(this->m_OTM_state == INITIALIZED);
    };
    
 
    inline void SetModulus(const usint& value){
      m_setOTM(myZZ(value));
    };
  
    inline void SetModulus(const myZZ& value){
      m_setOTM(value);
    };

    //the following confuses the compiler?
      inline void SetModulus(const myZZ_p& value){
      m_setOTM(myZZ(value.myZZ_p::GetModulus()));
    };

    inline void SetModulus(const std::string& value){
      m_setOTM(myZZ(value));
    };
  
    inline const myZZ& GetModulus() const{
      return (m_getOTM());
    };

    //TODO: is there a real need for these in higher level crypto operations?

    usint ceilIntByUInt( const ZZ_limb_t Number) const;

    //Serialization functions

    const std::string Serialize(const myZZ& modulus = myZZ::ZERO) const;
    const char * Deserialize(const char *cp, const myZZ& modulus = myZZ::ZERO);

  private:
    //adapter kits
    void SetMSB();
    
    size_t m_MSB;
    
    usint GetMSBLimb_t( ZZ_limb_t x) const;
    void m_setOTM(const myZZ &q);
    bool m_checkOTM(const myZZ &q) const;
    myZZ& m_getOTM(void) const;
    
    static myZZ m_OTM;
    
    enum OTMState {
      GARBAGE,INITIALIZED //note different order, Garbage is the default state
    };
    //enum to store the state of the
    static OTMState m_OTM_state;
    
  }; //class ends

  //negation operator NOTE this mimics binvect.h



  inline myZZ_p operator-(const myZZ_p &a) { return myZZ_p(0) - a; }


 //comparison operators with two operands defined outside the class
  inline long operator==(const myZZ &a, const myZZ_p& b) 
  { return b.Compare(a) == 0; }    
  inline long operator!=(const myZZ &a, const myZZ_p& b) 
  { return b.Compare(a) != 0; }    
  //note inversion of comparison because of swap of operands
  //inline long operator<(const myZZ &a, const myZZ_p& b) 
  //{ return b.Compare(a) > 0; }
  //  inline long operator>(const myZZ &a, const myZZ_p& b) 
  //{ return b.Compare(a) < 0; }
  //inline long operator<=(const myZZ &a, const myZZ_p& b)
  //{ return b.Compare(a) >= 0; }
  //inline long operator>=(const myZZ &a, const myZZ_p& b)
  //{ return b.Compare(a) <= 0; }

#if 1 //these may not be needed!
 //comparison operators with two operands defined outside the class
  inline long operator==(const usint &a, const myZZ_p& b) 
  { return b.Compare(a) == 0; }    
  inline long operator!=(const usint &a, const myZZ_p& b) 
  { return b.Compare(a) != 0; }    
  //note inversion of comparison because of swap of operands
  inline long operator<(const usint &a, const myZZ_p& b) 
  { return b.Compare(a) > 0; }
  inline long operator>(const usint &a, const myZZ_p& b) 
  { return b.Compare(a) < 0; }
  inline long operator<=(const usint &a, const myZZ_p& b)
  { return b.Compare(a) >= 0; }
  inline long operator>=(const usint &a, const myZZ_p& b)
  { return b.Compare(a) <= 0; }

 //comparison operators with two operands defined outside the class
  inline long operator==(const sint &a, const myZZ_p& b) 
  { return b.Compare(a) == 0; }    
  inline long operator!=(const sint &a, const myZZ_p& b) 
  { return b.Compare(a) != 0; }    
  //note inversion of comparison because of swap of operands
  inline long operator<(const sint &a, const myZZ_p& b) 
  { return b.Compare(a) > 0; }
  inline long operator>(const sint &a, const myZZ_p& b) 
  { return b.Compare(a) < 0; }
  inline long operator<=(const sint &a, const myZZ_p& b)
  { return b.Compare(a) >= 0; }
  inline long operator>=(const sint &a, const myZZ_p& b)
  { return b.Compare(a) <= 0; }
#endif

}//namespace ends



#endif //LBCRYPTO_MATH_MGMPINT_MGMPINT_H

