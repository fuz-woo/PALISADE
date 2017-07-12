/*
 * @file ubintvec.cpp  This file contains ubintvec, a <vector> of ubint, with associated
 * math operators.  
 * NOTE: this has been refactored so that implied modulo (ring)
 * aritmetic is in mbintvec
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

#include "../../utils/serializable.h"
#include "../backend.h"

namespace exp_int {

  //CTORS
  // basic constructor
  template<class ubint_el_t>
  ubintvec<ubint_el_t>::ubintvec(){
  }

  // Basic constructor for specifying the length of the vector.
  template<class ubint_el_t>
  ubintvec<ubint_el_t>::ubintvec(usint length){
    m_data.resize(length);

    for (usint i = 0; i < length; i++){
      m_data[i] = 0;
    }
  }

  // constructor specifying the ubintvec as a vector of strings
  template<class ubint_el_t>
  ubintvec<ubint_el_t>::ubintvec(std::vector<std::string> &s){
    m_data.resize(s.size());
    for (usint i = 0; i < s.size(); i++){
      m_data[i] = ubint_el_t(s[i]);
    }
  }

  //copy constructor
  template<class ubint_el_t>
  ubintvec<ubint_el_t>::ubintvec(const ubintvec &in_bintvec){
    //todo: redo
    usint length = in_bintvec.m_data.size();
    m_data.resize(length);
    for(usint i=0;i < length;i++){
      m_data[i]= in_bintvec.m_data[i];
    }
  }

  template<class ubint_el_t>
  ubintvec<ubint_el_t>::ubintvec(ubintvec &&in_bintvec){
    m_data = in_bintvec.m_data;
    in_bintvec.m_data.clear();
  }


  //ASSIGNMENT copy allocator const binvec to binvec


  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator=(const ubintvec &rhs){
    if(this!=&rhs){
      if(this->m_data.size()==rhs.m_data.size()){
        for (usint i = 0; i < this->m_data.size(); i++){
          this->m_data[i] = rhs.m_data[i];
        }
      }
      else{
        m_data.resize(rhs.m_data.size());
        for (usint i = 0; i < m_data.size(); i++){
          m_data[i] = rhs.m_data[i];
        }
      }
    }

    return *this;
  }

  //Assignment with initializer list of ubints
  // does not resize the vector
  // unless lhs size is too small
  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator=(std::initializer_list<ubint_el_t> rhs){
    usint len = rhs.size();
    if (this->m_data.size()< len){
      this->m_data.resize(len);
    }

    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	m_data[i] =  ubint_el_t(*(rhs.begin()+i));
      } else {
	m_data[i] = 0;
      }
    }

    return *this;
  }
  //Assignment with initializer list of usints
  // does not resize the vector
  // unless lhs size is too small
  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator=(std::initializer_list<usint> rhs){
    usint len = rhs.size();
    if (this->m_data.size()< len){
      this->m_data.resize(len);
    }
    //m_data.clear();
    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	m_data[i] = ubint_el_t(*(rhs.begin()+i));
      } else {
	m_data[i] = 0;
      }
    }
    return *this;
  }

  //Assignment with initializer list of strings
  // does not resize the vector
  // unless lhs size is too small

  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator=(std::initializer_list<std::string> rhs){
    usint len = rhs.size();
    if (this->m_data.size()< len){
      this->m_data.resize(len);
    }
    // m_data.clear();
    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	m_data[i] = ubint_el_t(*(rhs.begin()+i));
      } else {
	m_data[i] = 0;
      }
    }
    return *this;
  }


  // move copy allocator
  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator=(ubintvec &&rhs){

    if(this!=&rhs){
     this->m_data.swap(rhs.m_data); //swap the two vector contents,
     if (rhs.m_data.size()>0)
          rhs.m_data.clear();
    }

    return *this;

  }

  //desctructor
  template<class ubint_el_t>
  ubintvec<ubint_el_t>::~ubintvec(){
    //std::cout<<"destructor called for vector of size: "<<this->m_data.size()<<"  "<<std::endl;
    m_data.clear();
  }

  //ACCESSORS


  // Set value at index from ubint
  template<class ubint_el_t>
  void ubintvec<ubint_el_t>::SetValAtIndex(usint index, const ubint_el_t& value){

    if(!this->IndexCheck(index)){
      throw std::logic_error("ubintvec index out of range");
    }
    else{
      this->m_data.at(index) = value;
    }
  }

  // set value at index from string
  template<class ubint_el_t>
  void ubintvec<ubint_el_t>::SetValAtIndex(usint index, const std::string& str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("ubintvec index out of range");
    }
    else{
      this->m_data.at(index).SetValue(str);
    }
  }

  template<class ubint_el_t>
  const ubint_el_t& ubintvec<ubint_el_t>::GetValAtIndex(size_t index) const{
    if(!this->IndexCheck(index)){
      throw std::logic_error("ubintvec index out of range");
    }
    return this->m_data[index];
  }




  //todo: deprecate this.
  template<class ubint_el_t>
  size_t ubintvec<ubint_el_t>::GetLength() const{
    return this->m_data.size();
  }

  template<class ubint_el_t>
  size_t ubintvec<ubint_el_t>::size() const{
    return this->m_data.size();
  }

  //Math functions
  // Mod
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::Mod(const ubint_el_t& modulus) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].Mod(modulus);
    }
    return ans;
  }

    // %=
  // method to vector with scalar
  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator%=(const ubint_el_t& modulus) {

    *this = this->Mod(modulus);
    return *this;

  }



  // method to add scalar to vector
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::Add(const ubint_el_t &b) const{
	ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].Add(b);
    }
    return ans;
  }


  // +=  operator to add scalar to vector
  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator+=(const ubint_el_t& b) {

    *this = this->Add(b);
    return *this;

  }


  // method to subtract scalar from vector
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::Sub(const ubint_el_t &b) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].Sub(b);
    }
    return ans;
  }

  // -=  operator to subtract scalar from vector
  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator-=(const ubint_el_t& b) {

    *this = this->Sub(b);
    return *this;

  }

  // method to multiply vector by scalar
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::Mul(const ubint_el_t &b) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].Mul(b);
    }
    return ans;
  }

  // *=  operator to multiply  scalar from vector
  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator*=(const ubint_el_t& b) {

    *this = this->Mul(b);
    return *this;

  }
#if 0 //not used
template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::Exp(const ubint_el_t &b) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].Exp(b);
    }
    return ans;
  }
#endif
  // vector elementwise add
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::Add(const ubintvec &b) const{
    
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec adding vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
    	  ans.m_data[i] = ans.m_data[i].Add(b.m_data[i]);
      }
      return ans;
    }
  }

  // vector elementwise subtract
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::Sub(const ubintvec &b) const{
    
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec subtracting vectors of different lengths");
    } else {

      for(usint i=0;i<ans.m_data.size();i++){
    	  ans.m_data[i] = ans.m_data[i].Sub(b.m_data[i]);
      }
      return ans;
    }
  }

  // vector elementwise multiply
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::Mul(const ubintvec &b) const{
    
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec multiplying vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
        ans.m_data[i] = ans.m_data[i].Mul(b.m_data[i]);
      }
      return ans;
    }
  }

  // vector scalar modulo addition
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::ModAdd(const ubint_el_t &b, const ubint_el_t &modulus) const{
    ubintvec ans(*this);
    for(usint i=0;i<ans.m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModAdd(b, modulus);
    }
    
    return ans;
  }
  
  // vector scalar modulo subtraction
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::ModSub(const ubint_el_t &b, const ubint_el_t &modulus) const{
    ubintvec ans(*this);
    for(usint i=0;i<ans.m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModSub(b, modulus);
    }
    return ans;
  }

  // vector scalar modulo multiplication
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::ModMul(const ubint_el_t &b, const ubint_el_t &modulus) const{
    ubintvec ans(*this);
    for(usint i=0;i<ans.m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModMul(b, modulus);
    }
    return ans;
  }
  


  // vector vector modulo addition
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::ModAdd(const ubintvec<ubint_el_t> &b, const ubint_el_t &modulus) const{
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec ModAdd vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModAdd(b.m_data[i], modulus);
      }
      return ans;
    }
  }
  
  // vector vector modulo subtraction
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::ModSub(const ubintvec<ubint_el_t> &b, const ubint_el_t &modulus) const{
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec ModSub vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModSub(b.m_data[i], modulus);
      }
      return ans;
    }
  }

  // vector vector modulo multiplication
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::ModMul(const ubintvec<ubint_el_t> &b, const ubint_el_t &modulus) const{
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
        throw std::logic_error("ubintvec ModMul vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModMul(b.m_data[i], modulus);
      }
      return ans;
    }
  }

  // assignment operators

  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator+=(const ubintvec &b) {

    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec += vectors of different lengths");
    }

    for(usint i=0;i<this->m_data.size();i++){
      this->m_data[i] = this->m_data[i].Add(b.m_data[i]);
    }
    return *this;

  }

  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator-=(const ubintvec &b) {

    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec -= vectors of different lengths");
    }

    for(usint i=0;i<this->m_data.size();i++){
      this->m_data[i] = this->m_data[i].Sub(b.m_data[i]);
    }
    return *this;

  }


  template<class ubint_el_t>
  const ubintvec<ubint_el_t>& ubintvec<ubint_el_t>::operator*=(const ubintvec &b) {

    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec *= vectors of different lengths");
    }

    for(usint i=0;i<this->m_data.size();i++){
      this->m_data[i] = this->m_data[i].Mul(b.m_data[i]);
    }
    return *this;

  }

  //Gets the ind
  template<class ubint_el_t>
  ubintvec<ubint_el_t> ubintvec<ubint_el_t>::GetDigitAtIndexForBase(usint index, usint base) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ubint_el_t(ans.m_data[i].GetDigitAtIndexForBase(index,base));
    }

    return ans;
  }

  //new serialize and deserialise operations
  //todo: not tested
  //currently using the same map as bigVector, execpt without modulus. 
  //mubintvec.cpp will have attached modulus.

  // JSON FACILITY - Serialize Operation
  template<class bin_el_t>
  bool ubintvec<bin_el_t>::Serialize(lbcrypto::Serialized* serObj) const {

    if( !serObj->IsObject() )
      return false;

    lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);
    // ubintvec has no modulus, mubintvec does.
    // bbvMap.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator()); 

    size_t pkVectorLength = GetLength();
    if( pkVectorLength > 0 ) {
      std::string pkBufferString = GetValAtIndex(0).Serialize();
      for (size_t i = 1; i < pkVectorLength; i++) {
	pkBufferString += "|";
	pkBufferString += GetValAtIndex(i).Serialize();
      }
      bbvMap.AddMember("VectorValues", pkBufferString, serObj->GetAllocator());
    }

    serObj->AddMember("ubintvec", bbvMap, serObj->GetAllocator());

    return true;
  }

  // JSON FACILITY - Deserialize Operation
  template<class ubint_el_t>
  bool ubintvec<ubint_el_t>::Deserialize(const lbcrypto::Serialized& serObj) {

    lbcrypto::Serialized::ConstMemberIterator mIter = serObj.FindMember("ubintvec");
    if( mIter == serObj.MemberEnd() )
      return false;

    lbcrypto::SerialItem::ConstMemberIterator vIt;
    // ubintvec has no modulus, mubintvec does.
    //  if( (vIt = mIter->value.FindMember("Modulus")) == mIter->value.MemberEnd() )
    //  return false;
    //limb_t bbiModulus(vIt->value.GetString());

    if( (vIt = mIter->value.FindMember("VectorValues")) == mIter->value.MemberEnd() )
      return false;

    // this->SetModulus(bbiModulus);

    this->m_data.clear();

    ubint_el_t vectorElem;
    //usint ePos = 0;
    const char *vp = vIt->value.GetString();
    while( *vp != '\0' ) {
      vp = vectorElem.Deserialize(vp);
      //this->SetValAtIndex(ePos++, vectorElem);
      this->m_data.push_back(vectorElem);
      if( *vp == '|' )
	vp++;
    }

    return true;
  }



  //Private functions
  template<class ubint_el_t>
  bool ubintvec<ubint_el_t>::IndexCheck(usint length) const{
    if(length>this->m_data.size())
      return false;
    return true;
  }

} // namespace lbcrypto ends

#ifdef UBINT_32
template class exp_int::ubintvec<exp_int::ubint<uint32_t>>; 
#endif
#ifdef UBINT_64
template class exp_int::ubintvec<exp_int::ubint<uint64_t>>; 
#endif
