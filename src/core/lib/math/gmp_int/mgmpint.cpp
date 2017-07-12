/**
 * @file mgmpint.cpp This file contains the main class for unsigned big integers: ubint. Big
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
 * This file contains the C++ code for implementing the main class for
 * big integers: ubint. Big integers are represented as arrays of
 * native usigned integers. The native integer type is supplied as a
 * template parameter.  Currently implementation based on uint32_t is
 * supported. One needs a native integer 2x the size of the chosen type for
 * certain math operations.
 */


#define _SECURE_SCL 0 // to speed up VS


#include <iostream>
#include <fstream>
#include <sstream>

#include "../backend.h"

#if defined(__linux__) && MATHBACKEND == 6

#include "gmpint.h"
#include "mgmpint.h"


//#include <NTL/ZZ.h>
//#include <NTL/ZZ_limbs.h>


namespace NTL {

  //define the static vriables
  myZZ myZZ_p::m_OTM = 0;
  myZZ_p::OTMState myZZ_p::m_OTM_state = GARBAGE;

  // may have difficulty with not inintializing modulo first.
  // const myZZ_p myZZ_p::ZERO=myZZ_p(0L);
  // const myZZ_p myZZ_p::ONE=myZZ_p(1);
  // const myZZ_p myZZ_p::TWO=myZZ_p(2);
  // const myZZ_p myZZ_p::THREE=myZZ_p(3);
  // const myZZ_p myZZ_p::FOUR=myZZ_p(4);
  // const
  // myZZ_p myZZ_p::FIVE=myZZ_p(5);

  //constructors without moduli
  myZZ_p::myZZ_p():ZZ_p() {}
  myZZ_p::myZZ_p(int a): ZZ_p(a) {}
  myZZ_p::myZZ_p(long a): ZZ_p(a) {}
  myZZ_p::myZZ_p(unsigned long a): ZZ_p(a) {}
  myZZ_p::myZZ_p(const unsigned int a): ZZ_p(a) {}
  //myZZ_p::myZZ_p(const unsigned int &a): ZZ_p(a) {}
  //myZZ_p::myZZ_p(unsigned int &a): ZZ_p(a) {} 
  myZZ_p::myZZ_p(std::string s): ZZ_p() {this->_ZZ_p__rep=conv<ZZ>(s.c_str());}
  myZZ_p::myZZ_p(const char *s): ZZ_p() {this->_ZZ_p__rep=conv<ZZ>(s);}
  //constructors with explicit myZZ moduli
  myZZ_p::myZZ_p(int a, myZZ&q): ZZ_p(a) {m_setOTM(q);}
  myZZ_p::myZZ_p(long a, myZZ&q): ZZ_p(a) {m_setOTM(q);}
  myZZ_p::myZZ_p(unsigned long a, myZZ&q): ZZ_p(a) {m_setOTM(q);}
  myZZ_p::myZZ_p(const unsigned int &a, myZZ&q): ZZ_p(a) {m_setOTM(q);}
  myZZ_p::myZZ_p(unsigned int &a, myZZ&q): ZZ_p(a) {m_setOTM(q);} 
  myZZ_p::myZZ_p(std::string s, myZZ&q): ZZ_p() {this->_ZZ_p__rep=conv<ZZ>(s.c_str()); m_setOTM(q);}
  myZZ_p::myZZ_p(const char *s, myZZ&q): ZZ_p() {this->_ZZ_p__rep=conv<ZZ>(s); m_setOTM(q);}

  //constructors with explicit string moduli
  myZZ_p::myZZ_p(int a, const char *sq): ZZ_p(a) {m_setOTM(sq);}
  myZZ_p::myZZ_p(long a, const char *sq): ZZ_p(a) {m_setOTM(sq);}
  myZZ_p::myZZ_p(unsigned long a, const char *sq): ZZ_p(a) {m_setOTM(sq);}
  myZZ_p::myZZ_p(const unsigned int &a, const char *sq): ZZ_p(a) {m_setOTM(sq);}
  myZZ_p::myZZ_p(unsigned int &a, const char *sq): ZZ_p(a) {m_setOTM(sq);} 
  myZZ_p::myZZ_p(std::string s, const char *sq): ZZ_p() {this->_ZZ_p__rep=conv<ZZ>(s.c_str());m_setOTM(sq);}
  myZZ_p::myZZ_p(const char *s, const char *sq): ZZ_p() {this->_ZZ_p__rep=conv<ZZ>(s); m_setOTM(sq);}

  //copy constructors
  myZZ_p::myZZ_p(NTL::ZZ &a): ZZ_p() {this->_ZZ_p__rep=a;}
  myZZ_p::myZZ_p(const NTL::ZZ &a): ZZ_p() {this->_ZZ_p__rep=a;}
  myZZ_p::myZZ_p(NTL::ZZ_p &a): ZZ_p(a) {}
  myZZ_p::myZZ_p(const NTL::ZZ_p &a): ZZ_p(a) {}
  // copy constructors with myZZ moduli
  myZZ_p::myZZ_p(NTL::ZZ &a, myZZ&q): ZZ_p() {this->_ZZ_p__rep=a; m_setOTM(q);}
  myZZ_p::myZZ_p(const NTL::ZZ &a, myZZ&q): ZZ_p() {this->_ZZ_p__rep=a; m_setOTM(q);}
  myZZ_p::myZZ_p(NTL::ZZ_p &a, myZZ&q): ZZ_p(a) { m_setOTM(q);}
  myZZ_p::myZZ_p(const NTL::ZZ_p &a, myZZ&q): ZZ_p(a) { m_setOTM(q);}
  // copy constructors with string constant moduli
  myZZ_p::myZZ_p(NTL::ZZ &a, const char *sq): ZZ_p() {this->_ZZ_p__rep=a; m_setOTM(sq);}
  myZZ_p::myZZ_p(const NTL::ZZ &a, const char *sq): ZZ_p() {this->_ZZ_p__rep=a; m_setOTM(sq);}
  myZZ_p::myZZ_p(NTL::ZZ_p &a, const char *sq): ZZ_p(a) { m_setOTM(sq);}
  myZZ_p::myZZ_p(const NTL::ZZ_p &a, const char *sq): ZZ_p(a) { m_setOTM(sq);}
  // copy constructors with unsigned int moduli
  myZZ_p::myZZ_p(NTL::ZZ &a, unsigned int q): ZZ_p() {this->_ZZ_p__rep=a; m_setOTM(q);}
  myZZ_p::myZZ_p(const NTL::ZZ &a, unsigned int q): ZZ_p() {this->_ZZ_p__rep=a; m_setOTM(q);}
  myZZ_p::myZZ_p(NTL::ZZ_p &a, unsigned int q): ZZ_p(a) { m_setOTM(q);}
  myZZ_p::myZZ_p(const NTL::ZZ_p &a, unsigned int q): ZZ_p(a) { m_setOTM(q);}


  //move copy constructors
  myZZ_p::myZZ_p(NTL::ZZ &&a) : ZZ_p() {this->_ZZ_p__rep.swap(a);}
  myZZ_p::myZZ_p(NTL::ZZ_p &&a) : ZZ_p() {this->swap(a);}
    

  myZZ_p  myZZ_p::MultiplyAndRound(const myZZ &p, const myZZ &q) const
  {
    myZZ ans(this->_ZZ_p__rep);
    ans *= p;
    ans = ans.DivideAndRound(q);
    return myZZ_p(ans);
  }

  myZZ_p myZZ_p::DivideAndRound(const myZZ &q) const
  {
    myZZ ans(this->_ZZ_p__rep);
     ans = ans.DivideAndRound(q);
    return myZZ_p(ans);
  }


  usint myZZ_p::GetMSB() const {
    //note: originally I did not worry about this, and just set the 
    //MSB whenever this was called, but then that violated constness in the 
    // various libraries that used this heavily
    //this->SetMSB(); //note no one needs to SetMSB()
    //return m_MSB;

    //SO INSTEAD I am just regenerating the MSB each time
    size_t sz = this->_ZZ_p__rep.size();
    usint MSB;
    //std::cout<<"size "<<sz <<" ";
    if (sz==0) { //special case for empty data
      MSB = 0;
      return(MSB);
    }
    MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    const ZZ_limb_t *zlp = ZZ_limbs_get(this->_ZZ_p__rep);
    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.
    MSB+=tmp;
    return(MSB);
  }

  void myZZ_p::SetMSB()
  {
    size_t sz = this->_ZZ_p__rep.size();
    //std::cout<<"size "<<sz <<" ";
    if (sz==0) { //special case for empty data
      m_MSB = 0;
      return;
    }

    m_MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    //std::cout<<"msb starts with "<<m_MSB<< " ";
    //could also try
    //m_MSB = NumBytes(*this)*8;
    const ZZ_limb_t *zlp = ZZ_limbs_get(this->_ZZ_p__rep);
    //for (usint i = 0; i < sz; i++){
    //std::cout<< "limb["<<i<<"] = "<<zlp[i]<<std::endl;
    //}

    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.
    //std::cout<< "tmp = "<<tmp<<std::endl;
    m_MSB+=tmp;
    //std::cout<<"msb ends with "<<m_MSB<< " " <<std::endl;
  }

 // inline static usint GetMSBLimb_t(ZZ_limb_t x){
  usint myZZ_p::GetMSBLimb_t( ZZ_limb_t x) const{
    const usint bval[] =
    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    uint64_t r = 0;
    if (x & 0xFFFFFFFF00000000) { r += 32/1; x >>= 32/1; }
    if (x & 0x00000000FFFF0000) { r += 32/2; x >>= 32/2; }
    if (x & 0x000000000000FF00) { r += 32/4; x >>= 32/4; }
    if (x & 0x00000000000000F0) { r += 32/8; x >>= 32/8; }
    return r + bval[x];
  }

  void myZZ_p::m_setOTM(const myZZ &q) 
  {
    //should test first but for now just set
    ZZ_p::init(q);
    m_OTM = q;
    m_OTM_state = INITIALIZED;
  }

  bool myZZ_p::m_checkOTM(const myZZ &q) const 
  {
#ifdef WARN_BAD_MODULUS
    if (m_OTM_state == GARBAGE){
      //throw std::logic_error("myZZ_p::m_checkOTM() called with uninitialized OTM");
      std::cout<<"myZZ_p::m_checkOTM() called with uninitialized OTM"<<std::endl;
#ifdef PAUSE_BAD_MODULUS
      std::string foo;
      std::cin >> foo;
#endif

    }
#endif
    return (m_OTM == q);
  }

  myZZ& myZZ_p::m_getOTM(void) const 
  {
#ifdef WARN_BAD_MODULUS
    if (m_OTM_state == GARBAGE){
      //std::logic_error("myZZ_p::m_getOTM() called with uninitialized OTM");
      std::cout<<"myZZ_p::m_getOTM() called with uninitialized OTM"<<std::endl;
#ifdef PAUSE_BAD_MODULUS
      std::string foo;
      std::cin >> foo;
#endif
    }
#endif
    return m_OTM;
  }

  //adapter kit
  //static const myZZ_p& myZZ_p::zero() {return const myZZ_p(0);}

  // //palisade conversion methods
  // usint myZZ_p::ConvertToUsint() const{
  //   bool dbg_flag = false;

  //   DEBUG("in myZZ_p::ConvertToUsint() this "<<*this);

  //   return (conv<usint>(*this)); 
  // }
  uint64_t myZZ_p::ConvertToInt() const{ 
   bool dbg_flag = false;

    DEBUG("in myZZ_p::ConvertToInt() this "<<*this);

    uint64_t result = conv<uint64_t>(*this);
    if (this->GetMSB() >= 64) {
      std::cerr<<"Warning myZZ_p::ConvertToInt() Loss of precision. "<<std::endl;
      std::cerr<<"input  "<< *this<<std::endl;			
      std::cerr<<"result  "<< result<<std::endl;			
    }
    return result;
  }
  // uint32_t myZZ_p::ConvertToUint32() const { return (conv<uint32_t>(*this));}

 // warning on some platforms usint64_t is implemented as an unsigned
  // long long which is not included in the conv functions in tools.h
  // in which case the following does not compile. 

  uint64_t myZZ_p::ConvertToUint64() const{ 
    static_assert(sizeof(uint64_t) == sizeof(long), 
		  "sizeof(uint64_t) != sizeof(long), edit myZZ ConvertToUint64()");
    uint64_t result = conv<uint64_t>(*this);
    if (this->GetMSB() >= 64) {
      std::cerr<<"Warning myZZ_p::ConvertToInt() Loss of precision. "<<std::endl;
      std::cerr<<"input  "<< *this<<std::endl;			
      std::cerr<<"result  "<< result<<std::endl;			
    }
    return result;
  }
  //float myZZ_p::ConvertToFloat() const{ return (conv<float>(this->_ZZ_p__rep));}
  double myZZ_p::ConvertToDouble() const{ return (conv<double>(this->_ZZ_p__rep));}
  //long double myZZ_p::ConvertToLongDouble() const {
  //  std::cerr<<"can't convert to long double"<<std::endl; 
  //  return 0.0L;
  //}

  std::ostream& operator<<(std::ostream& os, const myZZ_p& ptr_obj){
    os << (ZZ_p)ptr_obj;
    return os;
  }
  
  const std::string myZZ_p::ToString() const
  {
    //todo Not sure if this string is safe, it may be ephemeral if not returned  by value.
    std::stringstream result("");
    result << *this;
    return result.str();
  }	


  //optimized ceiling function after division by number of bits in the limb data type.
  usint myZZ_p::ceilIntByUInt( const ZZ_limb_t Number) const{
    //mask to perform bitwise AND
    static ZZ_limb_t mask = NTL_ZZ_NBITS-1;

    if(!Number)
      return 1;
    if((Number&mask)!=0)
      return (Number>>myZZ::m_log2LimbBitLength)+1;
    else
      return Number>>myZZ::m_log2LimbBitLength;
  }
#if 0
  // friend or inherit this? it is the same as gmpint
 //the following code is new serialize/deserialize code from

  // the array and the next
  // two functions convert a ubint in and out of a string of
  // characters the encoding is Base64-like: the first 5 6-bit
  // groupings are Base64 encoded, and the last 2 bits are A-D
  
  // Note this is, sadly, hardcoded for 32 bit integers and needs Some
  // Work to handle arbitrary sizes

  // precomputed shift amounts for each 6 bit chunk
  static const usint b64_shifts[] = { 0, 6, 12, 18, 24, 30 };
  static const usint B64MASK = 0x3F;

  // this for encoding...
  static char to_base64_char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  // and this for decoding...
  static inline unsigned int base64_to_value(char b64) {
    if( isupper(b64) )
      return b64 - 'A';
    else if( islower(b64) )
      return b64 - 'a' + 26;
    else if( isdigit(b64) )
      return b64 - '0' + 52;
    else if( b64 == '+' )
      return 62;
    else
      return 63;
  }

#endif
  // serialization of myZZ_p, calls myZZ.Serialize, 
  const std::string myZZ_p::Serialize(const myZZ &modulus) const {
    bool dbg_flag = false;

    //note this does simple serialization, other libraries store small special values for 0 or  -1
    //we ignore this
    DEBUG("mgmp ser "<<*this);
    return (myZZ(this->_ZZ_p__rep)).Serialize();
  }

  // deserialization of myZZ_p, calls myZZ.Deserialize, 
  // sets modulus to input  modulus. 
  const char * myZZ_p::Deserialize(const char *cp, const myZZ &modulus){
    bool dbg_flag = false;
    const char *cpout;
    clear(*this);
    myZZ(repZZ); //new value store decode

    //DEBUG("cp before in mgminp "<<cp);
    cpout = repZZ.Deserialize(cp);    //cpout is rest of cp after decode
    //DEBUG("cp after in mgminp "<<cpout);
    //save
    *this=myZZ_p(repZZ);
    this->SetModulus(modulus);
    DEBUG("mgmp deser "<<*this);
    SetMSB();

    return cpout;
  }

  

} // namespace NTL ends

#endif
