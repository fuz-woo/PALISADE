/**
 * @file gmpint.cpp  This file contains the C++ code for implementing the main class for
 * big integers: gmpint which replaces BBI and uses NTL
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met: 1. Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.  2. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRI CT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * @section DESCRIPTION
 *
 *
 * This file contains the C++ code for implementing the main class for
 * big integers: gmpint which replaces BBI and uses NTLLL
 */



#define _SECURE_SCL 0 // to speed up VS

#include <iostream>
#include <fstream>
#include <sstream>
#include "../backend.h"

#include "gmpint.h"

namespace NTL {

  // constant log2 of limb bitlength
  const usint myZZ::m_log2LimbBitLength = Log2<NTL_ZZ_NBITS>::value;

  myZZ::myZZ():ZZ() {SetMSB();}

  myZZ::myZZ(uint64_t d): ZZ(0) {

    bool dbg_flag = false;
    static_assert(NTL_ZZ_NBITS != sizeof(uint64_t) , "can't compile gmpint on this architecture");
    
    DEBUGEXP(NTL_ZZ_NBITS);
    DEBUGEXP(sizeof(ZZ_limb_t));
    DEBUGEXP(NTL_BITS_PER_LONG);
    if (d==0)
      return;
    DEBUGEXP(sizeof(ZZ_limb_t));
    const ZZ_limb_t d1(d);
    ZZ_limbs_set(*this, &d1, 1);
    SetMSB();
  }
  myZZ::myZZ(const std::string &s): ZZ(conv<ZZ>(s.c_str())) {SetMSB();}
  myZZ::myZZ(const NTL::ZZ &a): ZZ(a) {SetMSB();}
  myZZ::myZZ(NTL::ZZ &&a) : ZZ() {this->swap(a);SetMSB();}
  void myZZ::SetValue(const std::string& str) 
  {
    *this = conv<ZZ>(str.c_str());
    SetMSB();
  }

  void myZZ::SetValue(const myZZ& a)
  {
    *this = a;
    SetMSB();
  }

  //this is the zero allocator for the palisade matrix class
  unique_ptr<myZZ> myZZ::Allocator() {
    return lbcrypto::make_unique<NTL::myZZ>();
  };

  usint myZZ::GetMSB() const {
    //note: originally I did not worry about this, and just set the 
    //MSB whenever this was called, but then that violated constness in the 
    // various libraries that used this heavily
    //this->SetMSB(); //note no one needs to SetMSB()
    //return m_MSB;

    //SO INSTEAD I am just regenerating the MSB each time
    size_t sz = this->size();
    usint MSB;
    if (sz==0) { //special case for empty data
      MSB = 0;
      return(MSB);
    }

    MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);
    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.

    MSB+=tmp;
    m_MSB = MSB;
    return(MSB);
  }

  void myZZ::SetMSB()
  {

    size_t sz = this->size();
    if (sz==0) { //special case for empty data
      m_MSB = 0;
    }
    else {
    m_MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    //could also try
    //m_MSB = NumBytes(*this)*8;
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);

    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.
    m_MSB+=tmp;
  }
    return;
  }

 // inline static usint GetMSBLimb_t(ZZ_limb_t x){
  usint myZZ::GetMSBLimb_t( ZZ_limb_t x) const {
    const usint bval[] =
    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    uint64_t r = 0;
    if (x & 0xFFFFFFFF00000000) { r += 32/1; x >>= 32/1; }
    if (x & 0x00000000FFFF0000) { r += 32/2; x >>= 32/2; }
    if (x & 0x000000000000FF00) { r += 32/4; x >>= 32/4; }
    if (x & 0x00000000000000F0) { r += 32/8; x >>= 32/8; }
    return r + bval[x];
  }

  //Splits the binary string to equi sized chunks and then populates the internal array values.
  myZZ myZZ::FromBinaryString(const std::string& vin){
    bool dbg_flag = false;		// if true then print dbg output
    DEBUG("FromBinaryString");

    std::string v = vin;
    // strip off leading spaces from the input string
    v.erase(0, v.find_first_not_of(' '));
    // strip off leading zeros from the input string
    v.erase(0, v.find_first_not_of('0'));

    if (v.size() == 0) {
      //caustic case of input string being all zeros
      v = "0"; //set to one zero
    }

    myZZ value;
    //value.clear(); //clear out all limbs
    clear(value); //clear out all limbs

    usint len = v.length();
    ///new code here

    const unsigned int bitsPerByte = 8;
    //parse out string 8 bits at a time into array of bytes
    vector<unsigned char> bytes;

    DEBUG("input string: "<<v);
    DEBUG("len/bitsperbyte = "<<len/bitsPerByte);
    //reverse the string to make code easier
    std::reverse(v.begin(), v.end());
    DEBUG("reversedinput string: "<<v);

    DEBUG("len = "<<len);
    for (usint i = 0; i < len; i+=bitsPerByte){
      std::string bits = v.substr(0, bitsPerByte);
      //reverse the bits
      std::reverse(bits.begin(), bits.end());
      DEBUG("i = "<<i<<" bits: "<<bits);
      int newlen = v.length()-bitsPerByte;
      size_t nbits;
      DEBUG("newlen = "<<newlen);      
      unsigned char byte = std::stoi(bits, &nbits, 2);
      DEBUG("byte = "<<(unsigned int)byte);
      bytes.push_back(byte);
      if (newlen<1)
	break;
      v = v.substr(bitsPerByte, newlen);
      DEBUG("input string now: "<<v);
   }
    DEBUG("bytes size now "<<bytes.size());
    for (auto it = bytes.begin(); it != bytes.end(); ++it){
	DEBUG("bytes ="<< (unsigned int)(*it));
    }
    ZZFromBytes(value, bytes.data(), bytes.size());
    DEBUG("value ="<<value);    
    return(value);


  }

  myZZ myZZ::BitStringToBigInteger(const std::string& vin){ 
    myZZ ans;
    return ans.FromBinaryString(vin);
  }

  usint myZZ::GetDigitAtIndexForBase(usint index, usint base) const{
    bool dbg_flag = false;		// if true then print dbg output
    DEBUG("myZZ::GetDigitAtIndexForBase:  index = " << index
	  << ", base = " << base);

	  usint DigitLen = ceil(log2(base));

	  usint digit = 0;
	  usint newIndex = 1 + (index - 1)*DigitLen;
	  for (usint i = 1; i < base; i = i * 2)
	  {
		  digit += GetBitAtIndex(newIndex)*i;
		  newIndex++;
	  }
    DEBUG("digit = " << digit);
	  return digit;
  }

  // returns the bit at the index into the binary format of the big integer, 
  // note that msb is 1 like all other indicies. 
  //TODO: this code could be massively simplified
  uschar myZZ::GetBitAtIndex(usint index) const{
    bool dbg_flag = false;		// if true then print dbg output
    DEBUG("myZZ::GetBitAtIndex(" << index << "), this=" << *this);
    GetMSB();

    if(index<=0){
      return 0;
    }
    else if (index > m_MSB) {
      return 0;
    }

    ZZ_limb_t result;
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this); //get access to limb array
    int idx =ceilIntByUInt(index)-1;//idx is the index of the limb array

    if (idx >= (this->size())){
      return (uschar)0;
    }

    ZZ_limb_t temp = zlp[idx]; // point to correct limb
    ZZ_limb_t bmask_counter = index%NTL_ZZ_NBITS==0? NTL_ZZ_NBITS:index%NTL_ZZ_NBITS;//bmask is the bit number in the limb
    ZZ_limb_t bmask = 1;
    for(usint i=1;i<bmask_counter;i++)
      bmask<<=1;//generate the bitmask number
    DEBUG("temp = " << temp << ", bmask_counter = " << bmask_counter
	  << ", bmask = " << bmask);
    result = temp&bmask;//finds the bit in  bit format
    DEBUG("result = " << result);
    result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
    DEBUG("result = " << result);
    return (uschar)result;
  }

  //optimized ceiling function after division by number of bits in the limb data type.
  usint myZZ::ceilIntByUInt( const ZZ_limb_t Number){
    //mask to perform bitwise AND
    static ZZ_limb_t mask = NTL_ZZ_NBITS-1;

    if(!Number)
      return 1;

    if((Number&mask)!=0)
      return (Number>>m_log2LimbBitLength)+1;
    else
      return Number>>m_log2LimbBitLength;
  }

  //adapter kit
  //const myZZ& myZZ::zero() {return myZZ(ZZ::zero());}

  //palisade conversion methods

  uint64_t myZZ::ConvertToInt() const{
    bool dbg_flag = false;

    DEBUG("in myZZ::ConvertToInt() this.size() "<<this->size());
    DEBUG("in myZZ::ConvertToInt() this "<<*this);

    std::stringstream s; //slower
    s <<*this;
    //uint64_t result = s.str().stoull();
    uint64_t result;
    s>>result;

    if ((this->GetMSB() >= (sizeof(uint64_t)*8)) ||
	(this->GetMSB() >= NTL_ZZ_NBITS)) {
      std::cerr<<"Warning myZZ::ConvertToInt() Loss of precision. "<<std::endl;
      std::cerr<<"input  "<< *this<<std::endl;			
      std::cerr<<"result  "<< result<<std::endl;			
    }
    return result; 
  }
    
  double myZZ::ConvertToDouble() const{ return (conv<double>(*this));}

  const myZZ& myZZ::operator=(const myZZ &rhs){

    if(this!=&rhs){
      _ntl_gcopy(rhs.rep, &(this->rep));
      this->m_MSB = rhs.m_MSB;
  }
    return *this;
  }

  std::ostream& operator<<(std::ostream& os, const myZZ& ptr_obj){
    bool dbg_flag = false;
    ZZ tmp = ptr_obj;
    DEBUG("in operator<< "<<tmp);

    os << tmp;
    return os;
  }
  
  const std::string myZZ::ToString() const
  {
    std::stringstream result("");
    result << *this;
    return result.str();
  }	

  myZZ myZZ::MultiplyAndRound(const myZZ &p, const myZZ &q) const
  {
    
    myZZ ans(*this);
    ans *= p;
    ans = ans.DivideAndRound(q);
    
    return ans;
    
  }
  myZZ myZZ::DivideAndRound(const myZZ &q) const 
  {
    bool dbg_flag = false;
    
    //check for garbage initialization and 0 condition
    //check for garbage initialization and 0 condition
    if(q==myZZ(0))
      throw std::logic_error("DivideAndRound() Divisor is zero");
    
    myZZ halfQ(q>>1);
    DEBUG("halfq "<<halfQ.ToString());
    
    if (*this < q) {
      if (*this <= halfQ)
	return myZZ(0);
      else
	return myZZ(1);
    }
    //=============
    myZZ ans(0);
    myZZ rv(0);
    
    
    DEBUG( "*this "<<this->ToString());
    DEBUG("q "<<q.ToString());
    
    
    DivRem(ans, rv, *this,q);
    
    //f = divqr_vect(ans, rv,  *this,  q);
    //if (f!= 0)
    ///throw std::logic_error("Divqr() error in DivideAndRound");
    
    //ans.NormalizeLimbs();
    //rv.NormalizeLimbs();
    
    ans.SetMSB();
    rv.SetMSB();
    DEBUG("ans "<<ans.ToString());
    DEBUG("rv "<<rv.ToString());
    DEBUG("ans "<<ans.ToString());
    DEBUG("rv "<<rv.ToString());
    //==============
    //Rounding operation from running remainder
    if (!(rv <= halfQ)) {
      ans += myZZ(1);
      DEBUG("added1 ans "<<ans.ToString());
    }
    return ans;
  }
  
  
  // helper functions convert a ubint in and out of a string of
  // characters the encoding is Base64-like: the first 11 6-bit
  // groupings are Base64 encoded

  // precomputed shift amounts for each 6 bit chunk
  static const usint b64_shifts[] = { 0, 6, 12, 18, 24, 30, 36, 42, 48, 54, 60};
  static const ZZ_limb_t B64MASK = 0x3F; //6 bit mask

  // this for encoding...mapping 0.. 2^6-1 to an ascii char
  static char to_base64_char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  // this for decoding...
  static inline ZZ_limb_t base64_to_value(char b64) {
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

  //Serialize myZZ by concatnating 6bits converted to an ascii character together, and terminating with '|'

  const std::string myZZ::SerializeToString(const myZZ& modulus) const {
    bool dbg_flag = false;

    std::string ans = "";
    //note limbs are stored little endian in myZZ
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);
    for (auto i = 0; i<this->size(); ++i){
      DEBUG(" ser "<<i<<" "<<zlp[i]);
      DEBUG(" ser "<<std::hex<<" "<<zlp[i]<<std::dec);      

      //shift and convert 6 bits at a time
      ans += to_base64_char[((zlp[i]) >> b64_shifts[0]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[1]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[2]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[3]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[4]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[5]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[6]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[7]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[8]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[9]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[10]) & B64MASK];

    }
    ans += "|"; //mark end of word. 
    return ans;
  }
  //Deserialize myZZ by building limbs 6 bits at a time 
  //returns input cp with stripped chars for decoded myZZ
  const char * myZZ::DeserializeFromString(const char *cp, const myZZ& modulus){
    bool dbg_flag = false;
    clear(*this);

    vector<ZZ_limb_t> cv;

    while( *cp != '\0' && *cp != '|' ) {//till end of string or myZZ

      ZZ_limb_t converted =  base64_to_value(*cp++) << b64_shifts[0];
      converted |= base64_to_value(*cp++) << b64_shifts[1];
      converted |= base64_to_value(*cp++) << b64_shifts[2];
      converted |= base64_to_value(*cp++) << b64_shifts[3];
      converted |= base64_to_value(*cp++) << b64_shifts[4];
      converted |= base64_to_value(*cp++) << b64_shifts[5];
      converted |= base64_to_value(*cp++) << b64_shifts[6];
      converted |= base64_to_value(*cp++) << b64_shifts[7];
      converted |= base64_to_value(*cp++) << b64_shifts[8];
      converted |= base64_to_value(*cp++) << b64_shifts[9];
      converted |= base64_to_value(*cp++) << b64_shifts[10];
      
      DEBUG(" deser "<<converted);      
      DEBUG(" deser "<<std::hex<<" "<<converted<<std::dec);      
      cv.push_back(converted);
    }

    ZZ_limbs_set(*this, cv.data(), cv.size()); //save value
    SetMSB();
    if (*cp == '|') {		// if end of myZZ strip of separator
      cp++;
    }
    return cp;
  }

  bool myZZ::Serialize(lbcrypto::Serialized* serObj) const{
    bool dbg_flag = false;
    if( !serObj->IsObject() )
      return false;
    
    lbcrypto::SerialItem bbiMap(rapidjson::kObjectType);

    DEBUGEXP(IntegerTypeName());
    DEBUGEXP(this->ToString());
    bbiMap.AddMember("IntegerType", IntegerTypeName(), serObj->GetAllocator());
    bbiMap.AddMember("Value", this->ToString(), serObj->GetAllocator());
    serObj->AddMember("BigIntegerImpl", bbiMap, serObj->GetAllocator());
    return true;
  }

  bool myZZ::Deserialize(const lbcrypto::Serialized& serObj){
    bool dbg_flag = false;
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

    DEBUGEXP(vIt->value.GetString());
    SetValue(vIt->value.GetString());
    return true;
  }
  
} // namespace NTL ends
