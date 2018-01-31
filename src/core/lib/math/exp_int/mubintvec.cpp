/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 * 
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
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
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This file contains the cpp implementation of  mubintvec, a <vector> of ubint, with associated math operators.
 *
 */


#include "../../utils/serializable.h"
#include "../backend.h"

#include "time.h"
#include <chrono>

#include "../../utils/debug.h"

namespace exp_int {

  //CTORS
  // basic constructor
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(){
    bool dbg_flag = false;
    this->m_modulus = 0;
    m_modulus_state = GARBAGE;
    DEBUG("mubintvec ctor()");
  }

  // Basic constructor for specifying the length of the vector.
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length){
    bool dbg_flag = false;
    this->m_data.resize(length);

    //this->m_data = new ubint_el_t*[m_length];
    for (usint i = 0; i < length; i++){
      this->m_data[i] = 0;
    }
    m_modulus = 0;
    m_modulus_state = GARBAGE;
    DEBUG("mubintvec ctor(usint length)"<<length);
  }

  // Basic constructor for specifying the length of the vector and modulus.
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length, const usint &modulus){
    bool dbg_flag = false;
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = 0;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    *this=this->Mod(ubint_el_t(modulus));
    DEBUG("mubintvec CTOR( length "<<length<< " modulus usint) "<<modulus);
  }

  
  // Basic constructor for specifying the length of the vector and modulus.
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length, const ubint_el_t &modulus){
    bool dbg_flag = false;
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = 0;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    *this = this->Mod(modulus);

    DEBUG("mubintvec CTOR( length "<<length<< " modulus ubint_el_t) "<<modulus);
  }

  
  // Basic constructor for specifying the length of the vector and modulus with initializer list of usint

  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length, const ubint_el_t &modulus, std::initializer_list<usint>rhs){
    bool dbg_flag = false;
    this->m_data.resize(length);
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    
    usint len = rhs.size();
    for (usint i=0;i<length;i++){ // this loops over each entry
      if(i<len) {
	this->m_data[i] =  ubint_el_t(*(rhs.begin()+i))%m_modulus;  
      } else {
	this->m_data[i] = ubint_el_t(0);
      }
    }
    DEBUG("mubintvec CTOR (length "<<length<< " modulus ubint) "<<modulus.ToString());
  }

  // Basic constructor for specifying the length of the vector and modulus with initializer list of strings

  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length, const ubint_el_t &modulus, std::initializer_list<std::string>rhs){
    bool dbg_flag = false;
    this->m_data.resize(length);
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    
    usint len = rhs.size();
    for (usint i=0;i<length;i++){ // this loops over each entry
      if(i<len) {
	this->m_data[i] =  ubint_el_t(*(rhs.begin()+i))%m_modulus;
      } else {
	this->m_data[i] = ubint_el_t(0);
      }
    }
    DEBUG("mubintvec CTOR (length "<<length<< " modulus ubint) "<<modulus.ToString());
  }

  // Baspic constructor for specifying the length of the vector and modulus.
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length, const std::string &modulus){
    bool dbg_flag = false;
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = 0;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    DEBUG("mubintvec CTOR (length "<<length<< " modulus string) "<<modulus);
  }


  //
  // constructor specifying the mubintvec as a vector of strings and modulus
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string> &s, const ubint_el_t &modulus) {
    bool dbg_flag = false;
    this->m_data.resize(s.size());
    m_modulus = ubint_el_t(modulus);
    m_modulus_state = INITIALIZED;
    for (usint i = 0; i < s.size(); i++){
      this->m_data[i] = ubint_el_t(s[i])%m_modulus;
    }
    DEBUG("mubintvec CTOR (strvec length "<<s.size()<< " modulus ubint) "<<modulus.ToString());
  }

 //constructor specifying the mubintvec as a vector of strings with string modulus
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string> &s, const std::string &modulus) {
    bool dbg_flag = false;
    this->m_data.resize(s.size());
    m_modulus = ubint_el_t(modulus);
    m_modulus_state = INITIALIZED;

    for (usint i = 0; i < s.size(); i++){
      this->m_data[i] = ubint_el_t(s[i])%m_modulus;
    }

    DEBUG("mubintvec CTOR (strvec length "<<s.size()<< " modulus string) "<<modulus);
  }

  //copy constructor
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const mubintvec &in_bintvec){
    bool dbg_flag = false;

    size_t length = in_bintvec.m_data.size();
    this->m_data.resize(length);
    for(size_t i=0; i < length; i++){
      this->m_data[i]= in_bintvec.m_data[i];
    }
    m_modulus = in_bintvec.m_modulus;
    m_modulus_state = INITIALIZED;

    DEBUG("mubintvec copy CTOR length "<<length<< " modulus "<<m_modulus);
  }

  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(mubintvec &&in_bintvec){
    bool dbg_flag = false;
    this->m_data = std::move(in_bintvec.m_data);
    this->m_modulus = std::move(in_bintvec.m_modulus);
    this->m_modulus_state = std::move(in_bintvec.m_modulus_state);

    DEBUG("mubintvec move CTOR length "<<this->m_data.size()<< " modulus "<< m_modulus);

  }

  //ASSIGNMENT copy allocator const mubinvec to mubinvec
  //if two vectors are different sized, then it will resize target vector
  //will overwrite target modulus
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(const mubintvec &rhs){
    bool dbg_flag = false;
    if(this!=&rhs){
      if(this->m_data.size()==rhs.m_data.size()){
        for (usint i = 0; i < this->m_data.size(); i++){
          this->m_data[i] = rhs.m_data[i];
        }
      }
      else{
       this->m_data.resize(rhs.m_data.size());
        for (usint i = 0; i < this->m_data.size(); i++){
          this->m_data[i] = rhs.m_data[i];
        }
      }
      this->m_modulus = rhs.m_modulus;
      this->m_modulus_state = rhs.m_modulus_state;
    }

    return *this;
    DEBUG("mubintvec assignment copy CTOR length "<<this->m_data.size()<< " modulus "<<m_modulus.ToString());


  }

  //Assignment with initializer list of usints
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<uint64_t> rhs){
    bool dbg_flag = false;
    size_t len = rhs.size();
    if (this->m_data.size()< len){
      this->m_data.resize(len);
    }
    for(usint i=0;i<this->m_data.size();i++){ // this loops over each entry
      if(i<len) {
	this->m_data[i] =  ubint_el_t(*(rhs.begin()+i));
      } else {
	this->m_data[i] = 0;
      }
    }
    if (this->m_modulus_state == INITIALIZED) {
      *this = this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR usint init list length "<<this->m_data.size());
  }

  //Assignment with initializer list of strings
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<std::string> rhs){
    bool dbg_flag = true;
    size_t len = rhs.size();
    if (this->m_data.size()< len){
      this->m_data.resize(len);
    }
    for(usint i=0;i< this->m_data.size();i++){ // this loops over each entry
      if(i<len) {
	this->m_data[i] =  ubint_el_t(*(rhs.begin()+i));
      } else {
	this->m_data[i] = 0;
      }
    }
    if (this->m_modulus_state == INITIALIZED) {
      *this = this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR string init list length "<<this->m_data.size());
  }

  // move copy allocator
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(mubintvec &&rhs){
    bool dbg_flag = false;

    if(this!=&rhs){
      this->m_data.swap(rhs.m_data); //swap the two vector contents,
      if (rhs.m_data.size()>0)
	rhs.m_data.clear();
      this->m_modulus = rhs.m_modulus;
      this->m_modulus_state = rhs.m_modulus_state;
    }

    return *this;
    DEBUG("mubintvec move copy CTOR length "<<this->m_data.size()<< " modulus "<<m_modulus.ToString());
  }

  //desctructor
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::~mubintvec(){
    this->m_data.clear();
  }

  //ACCESSORS

  //modulus accessors
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SetModulus(const usint& value){
    m_modulus= ubint_el_t(value);
    m_modulus_state = INITIALIZED;
  }
  
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SetModulus(const ubint_el_t& value){
    m_modulus= value;
    m_modulus_state = INITIALIZED;
  }
  
  
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SetModulus(const std::string& value){
    m_modulus= ubint_el_t(value);
    m_modulus_state = INITIALIZED;
  }

  
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SetModulus(const mubintvec& value){
    m_modulus= ubint_el_t(value.GetModulus());
    m_modulus_state = INITIALIZED;
  }
  
  
  template<class ubint_el_t>
  const ubint_el_t& mubintvec<ubint_el_t>::GetModulus() const{
    if (m_modulus_state != INITIALIZED)
      throw std::logic_error("GetModulus() on uninitialized mubintvec");

    return(m_modulus);
  }


  /**Switches the integers in the vector to values corresponding to the new modulus
   *  Algorithm: Integer i, Old Modulus om, New Modulus nm, delta = abs(om-nm):
   *  Case 1: om < nm
   *  if i > i > om/2
   *  i' = i + delta
   *  Case 2: om > nm
   *  i > om/2
   *  i' = i-delta
   */	
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SwitchModulus(const ubint_el_t& newModulus) {
	
    ubint_el_t oldModulus(this->m_modulus);
    ubint_el_t n;
    ubint_el_t oldModulusByTwo(oldModulus>>1);
    ubint_el_t diff ((oldModulus > newModulus) ? (oldModulus-newModulus) : (newModulus - oldModulus));
    for(usint i=0; i< this->GetLength(); i++) {
      n = this->at(i);
      if(oldModulus < newModulus) {
	if(n > oldModulusByTwo) {
	  this->at(i)= n.ModAdd(diff, newModulus);
	} else {
	  this->at(i)= n.Mod(newModulus);
	}
      } else {
	if(n > oldModulusByTwo) {
	  this->at(i)= n.ModSub(diff, newModulus);
	} else {
	  this->at(i)= n.Mod(newModulus);
	}
      }
    }
    this->SetModulus(newModulus);
  }

  //////////////////////////////////////////////////
  // Set value at index with Mod 
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::atMod(size_t index, const ubint_el_t& value){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    else{
      // must be set modulo
      if (isModulusSet())
	this->at(index) = value%m_modulus;
      else //must be set directly
	this->at(index) = value;
    }
  }

  // set value at index from string with Mod
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::atMod(size_t index, const std::string& str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    else{
      // must be set modulo
      if (isModulusSet())
	this->at(index) = ubint_el_t(str)%m_modulus;
      else //must be set directly
	this->at(index) = ubint_el_t(str);
    }
  }

  
  //Math functions
  // Mod
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Mod(const ubint_el_t& modulus) const{

		mubintvec ans(*this);
		ans.ModEq(modulus);
		return std::move(ans);
  }

  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModEq(const ubint_el_t& modulus) {

	if (modulus == 2)
		return this->ModByTwoEq();
	else
	{
		ubint_el_t halfQ(this->GetModulus() >> 1);
		for (usint i = 0; i<this->m_data.size(); i++) {
			if ((*this)[i] > halfQ) {
				this->m_data[i].ModSubEq(this->GetModulus(), modulus);
			}
			else {
				this->m_data[i].ModEq(modulus);
			}
		}
		return *this;
	}
  }


  //method to mod by two
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModByTwo() const {

	  mubintvec ans(*this);
	  ans.ModByTwoEq();
	  return std::move(ans);
  }

  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModByTwoEq() {

	  ubint_el_t halfQ(this->GetModulus() >> 1);
	  for (usint i = 0; i<this->GetLength(); i++) {
		  if (this->operator[](i)>halfQ) {
			  if (this->operator[](i).Mod(2) == 1)
				  this->operator[](i) = ubint_el_t(0);
			  else
				  this->operator[](i) = ubint_el_t(1);
		  }
		  else {
			  if (this->operator[](i).Mod(2) == 1)
				  this->operator[](i) = ubint_el_t(1);
			  else
				  this->operator[](i)= ubint_el_t(0);
		  }

	  }
	  return *this;
  }

  // method to add scalar to vector element at index i

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAddAtIndex(usint i, const ubint_el_t &b) const{
    if(i > this->GetLength()-1) {
      std::string errMsg = "mubintvec::ModAddAtIndex. Index is out of range. i = " + std::to_string(i);
      throw std::runtime_error(errMsg);
    }
    mubintvec ans(*this);
    ans.m_data[i].ModAddEq(b, this->m_modulus);
    return std::move(ans);
  }

  // method to add scalar to vector
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAdd(const ubint_el_t &b) const{
	  mubintvec ans(*this);
	  for(usint i=0;i<this->m_data.size();i++){
		  ans.m_data[i].ModAddEq(b, ans.m_modulus);
	  }
	  return std::move(ans);
  }
    
  // method to add scalar to vector
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModAddEq(const ubint_el_t &b) {
	  for(usint i=0;i<this->m_data.size();i++){
		  this->m_data[i].ModAddEq(b, this->m_modulus);
	  }
	  return *this;
  }

  // needs to match BE 2 using signed modulus for result
  // method to subtract scalar from vector
    template<class ubint_el_t>
    mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModSub(const ubint_el_t &b) const{
      mubintvec ans(*this);
      for(usint i=0;i<this->m_data.size();i++){
        ans.m_data[i].ModSubEq(b, ans.m_modulus);
      }
      return std::move(ans);
    }

    template<class ubint_el_t>
    const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModSubEq(const ubint_el_t &b) {
      for(usint i=0;i<this->m_data.size();i++){
        this->m_data[i].ModSubEq(b, this->m_modulus);
      }
      return *this;
    }

  // method to multiply vector by scalar
    template<class ubint_el_t>
    mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModMul(const ubint_el_t &b) const{
  #ifdef NO_BARRETT //non barrett way
      mubintvec ans(*this);
      for(usint i=0;i<this->m_data.size();i++){
        ans.m_data[i].ModMulEq(b, ans.m_modulus);
      }
      return std::move(ans);
  #else

      mubintvec ans(*this);

      //Precompute the Barrett mu parameter
      ubint_el_t temp(ubint_el_t::ONE);

      temp<<=2*this->GetModulus().GetMSB()+3;

      ubint_el_t mu = temp.DividedBy(m_modulus);

      //Precompute the Barrett mu values
      /*ubint temp;
        uschar gamma;
        uschar modulusLength = this->GetModulus().GetMSB() ;
        ubint mu_arr[BARRETT_LEVELS+1];
        for(usint i=0;i<BARRETT_LEVELS+1;i++) {
        temp = ubint::ONE;
        gamma = modulusLength*i/BARRETT_LEVELS;
        temp<<=modulusLength+gamma+3;
        mu_arr[i] = temp.DividedBy(this->GetModulus());
        }*/

      for(usint i=0;i<this->m_data.size();i++){
        ans.m_data[i] = ans.m_data[i].ModBarrettMul(b,this->m_modulus,mu);
      }

      return ans;


  #endif
    }

    template<class ubint_el_t>
    const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModMulEq(const ubint_el_t &b) {
      for(usint i=0;i<this->m_data.size();i++){
        this->m_data[i].ModMulEq(b, this->m_modulus);
      }
      return *this;
    }

template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModExp(const ubint_el_t &b) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModExp(b, ans.m_modulus);
    }
    return std::move(ans);
  }


  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModInverse() const{

    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModInverse(this->m_modulus);
    }
    return std::move(ans);

}

    
 // method to exponentiate vector by scalar 
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Exp(const ubint_el_t &b) const{ //overload of ModExp()
    mubintvec ans(*this);
    ans = ans.ModExp(b);
    return std::move(ans);
  }

  // vector elementwise add
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAdd(const mubintvec &b) const{

	  mubintvec ans(*this);
	  if(this->m_modulus!=b.m_modulus){
		  throw std::logic_error("mubintvec adding vectors of different moduli");
	  } else if(this->m_data.size()!=b.m_data.size()){
		  throw std::logic_error("mubintvec adding vectors of different lengths");
	  } else {
		  for(usint i=0;i<ans.m_data.size();i++){
			  ans.m_data[i] = ans.m_data[i].ModAdd(b.m_data[i], ans.m_modulus);
		  }
		  return std::move(ans);
	  }
  }

  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModAddEq(const mubintvec &b) {
	  if(this->m_modulus!=b.m_modulus){
		  throw std::logic_error("mubintvec adding vectors of different moduli");
	  } else if(this->m_data.size()!=b.m_data.size()){
		  throw std::logic_error("mubintvec adding vectors of different lengths");
	  } else {
		  for(usint i=0;i<this->m_data.size();i++){
			  this->m_data[i].ModAddEq(b.m_data[i], this->m_modulus);
		  }
		  return *this;
	  }
  }

  // vector elementwise subtract
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModSub(const mubintvec &b) const{

	  mubintvec ans(*this);
	  if(this->m_modulus!=b.m_modulus){
		  throw std::logic_error("mubintvec subtracting vectors of different moduli");
	  } else if(this->m_data.size()!=b.m_data.size()){
		  throw std::logic_error("mubintvec subtracting vectors of different lengths");
	  } else {

		  for(usint i=0;i<ans.m_data.size();i++){
			  ans.m_data[i] = ans.m_data[i].ModSub(b.m_data[i],ans.m_modulus);
		  }
		  return std::move(ans);
	  }
  }

  // vector elementwise subtract
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModSubEq(const mubintvec &b) {

	  if(this->m_modulus!=b.m_modulus){
		  throw std::logic_error("mubintvec subtracting vectors of different moduli");
	  } else if(this->m_data.size()!=b.m_data.size()){
		  throw std::logic_error("mubintvec subtracting vectors of different lengths");
	  } else {

		  for(usint i=0;i<this->m_data.size();i++){
			  this->m_data[i].ModSubEq(b.m_data[i],this->m_modulus);
		  }
		  return *this;
	  }
  }

  // vector elementwise multiply
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModMul(const mubintvec &b) const{
#ifdef NO_BARRETT
    mubintvec ans(*this);
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec multiplying vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec multiplying vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
        ans.m_data[i].ModMulEq(b.m_data[i],ans.m_modulus);
      }
      return std::move(ans);
    }

#else // bartett way

    if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
      throw std::logic_error("ModMul called on mubintvecs with different parameters.");
    }
    
    mubintvec ans(*this);
    
    //Precompute the Barrett mu parameter
    ubint_el_t temp(ubint_el_t::ONE);
    temp<<=2*this->GetModulus().GetMSB()+3;
    ubint_el_t mu = temp.Div(this->GetModulus());
    
    //Precompute the Barrett mu values
    /*BigInteger temp;
      uschar gamma;
      uschar modulusLength = this->GetModulus().GetMSB() ;
      BigInteger mu_arr[BARRETT_LEVELS+1];
      for(usint i=0;i<BARRETT_LEVELS+1;i++) {
      temp = BigInteger::ONE;
      gamma = modulusLength*i/BARRETT_LEVELS;
      temp<<=modulusLength+gamma+3;
      mu_arr[i] = temp.DividedBy(this->GetModulus());
      }*/
    
    for(usint i=0;i<ans.m_data.size();i++){
      //ans.m_data[i] = ans.m_data[i].ModMul(b.m_data[i],this->m_modulus);
      ans.m_data[i] = ans.m_data[i].ModBarrettMul(b.m_data[i],this->m_modulus,mu);
    }
    return ans;

#endif
  }
  
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModMulEq(const mubintvec &b) {
	  if(this->m_modulus!=b.m_modulus){
		  throw std::logic_error("mubintvec multiplying vectors of different moduli");
	  }else if(this->m_data.size()!=b.m_data.size()){
		  throw std::logic_error("mubintvec multiplying vectors of different lengths");
	  } else {
		  for(usint i=0;i<this->m_data.size();i++){
			  this->m_data[i].ModMulEq(b.m_data[i],this->m_modulus);
		  }
		  return *this;
	  }
  }

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::MultiplyAndRound(const ubint_el_t &p, const ubint_el_t &q) const {

	  mubintvec ans(*this);
	  ubint_el_t halfQ(this->m_modulus >> 1);
	  for (usint i = 0; i<this->m_data.size(); i++) {
		  if (ans.m_data[i] > halfQ) {
			  ubint_el_t temp = this->m_modulus - ans.m_data[i];
			  ans.m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
		  }
		  else
			  ans.m_data[i] = ans.m_data[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
	  }
	    return std::move(ans);
  }

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::DivideAndRound(const ubint_el_t &q) const {
	  mubintvec ans(*this);
	  for (usint i = 0; i<this->m_data.size(); i++) {
		  ans.m_data[i] = ans.m_data[i].DivideAndRound(q);
	  }
	    return std::move(ans);
  }

  //Gets the ind
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::GetDigitAtIndexForBase(usint index, usint base) const{
    mubintvec ans(*this);
    for(usint i=0; i < this->m_data.size(); i++){
      ans.m_data[i] = ubint_el_t(ans.m_data[i].GetDigitAtIndexForBase(index,base));
    }

    return std::move(ans);
  }


  //new serialize and deserialise operations
  //currently using the same map as bigVector, with modulus. 
 // serialize and deserialise operations
  template<class ubint_el_t>
  bool mubintvec<ubint_el_t>::Serialize(lbcrypto::Serialized* serObj) const {

    bool dbg_flag = false;
    if( !serObj->IsObject() ){
      std::cerr<<"myVecP::Serialize failed bad object"<<std::endl;
      return false;
    }
    //serialize the modulus or mark as unknown
    std::string modstring ="";
    DEBUG("in vector Serialize");
    if (this->isModulusSet()){
      modstring = this->GetModulus().ToString();
    }else{
      modstring = "undefined";
    }
    DEBUG("modstring "<<modstring);

    //build the map for the serialization
    lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);
    //add modulus
    bbvMap.AddMember("Modulus", modstring, serObj->GetAllocator()); 
    //add Integer type
    DEBUG("IntegerType "<<ubint_el_t::IntegerTypeName());
    bbvMap.AddMember("IntegerType", ubint_el_t::IntegerTypeName(), 
		     serObj->GetAllocator());

    //determine vector length 
    size_t pkVectorLength = m_data.size();
    DEBUG ("size "<<pkVectorLength);
    bbvMap.AddMember("Length", std::to_string(pkVectorLength), 
		     serObj->GetAllocator());

    //build a string containing all vector elements concatenated
    if( pkVectorLength > 0 ) {
      std::string pkBufferString = "";
      for (size_t i = 0; i < pkVectorLength; i++) {
	DEBUG("element "<<i<<" "<<this->m_data[i]);
	std::string tmp = this->m_data[i].SerializeToString(this->GetModulus());
	pkBufferString += tmp;
      }
      DEBUG("add VectorValues");
      bbvMap.AddMember("VectorValues", pkBufferString, serObj->GetAllocator());
    }
    //store the map.
    DEBUG("add BigVectorImpl");
    serObj->AddMember("BigVectorImpl", bbvMap, serObj->GetAllocator());

    DEBUG("serialize done");
    return true;
  }

  // Deserialize
  template<class ubint_el_t>
  bool mubintvec<ubint_el_t>::Deserialize(const lbcrypto::Serialized& serObj) {
    bool dbg_flag = false;
    DEBUG("in deserialize");

    //decode in reverse order from Serialize above
    lbcrypto::Serialized::ConstMemberIterator mIter = serObj.FindMember("BigVectorImpl");
    if( mIter == serObj.MemberEnd() ){
      std::cerr<<"myVecP::Deserialize() failed"
	       <<" BigVectorImpl not found"<<std::endl;
      return false;
    }    

    lbcrypto::SerialItem::ConstMemberIterator vIt; //iterator over serial items
    //look for IntegerType
    if( (vIt = mIter->value.FindMember("IntegerType")) 
	== mIter->value.MemberEnd() ){
      std::cerr<<"myVecP::Deserialize() failed IntegerType not found"
	       <<std::endl;
      return false;
    }
    if( ubint_el_t::IntegerTypeName() != vIt->value.GetString() ){
      std::cerr<<"myVecP::Deserialize() failed IntegerType transltion"
	       <<std::endl;
      return false;
    }
    //look for Modulus
    if( (vIt = mIter->value.FindMember("Modulus"))
	== mIter->value.MemberEnd() ){
      std::cerr<<"myVecP::Deserialize() failed Modulus not found"<<std::endl;
      return false;
    }
    //decode modulus
    std::string strval(vIt->value.GetString());
    DEBUG("getting modulus string "<<strval);
    ubint_el_t bbiModulus;
    if (strval !="undefined"){
      bbiModulus =  ubint_el_t(strval);
    }
    DEBUG("bbiModulus "<<bbiModulus);
    
    //find length of vector
    if( (vIt = mIter->value.FindMember("Length")) 
	== mIter->value.MemberEnd() ){
      std::cerr<<"myVecP::Deserialize() failed Length not found"<<std::endl;
      return false;
    }
    usint vectorLength = std::stoi(vIt->value.GetString());
    DEBUG("vectorLength "<<vectorLength);
    
    if( (vIt = mIter->value.FindMember("VectorValues")) == 
	mIter->value.MemberEnd() ){
      std::cerr<<"myVecP::Deserialize() failed VectorValues not found"
	       <<std::endl;
      return false;
    }    
    
    mubintvec<ubint_el_t> newVec(vectorLength, bbiModulus); //build new vector
    ubint_el_t vectorElem; //element to store decode
    
    const char *vp = vIt->value.GetString(); //concatenated str of coded values
    DEBUG("vp is size "<<strlen(vp));

    for( usint ePos = 0; ePos < vectorLength; ePos++ ) {
      if( *vp == '\0' ) {
	std::cerr<<"myVecP::Deserialize() premature end of vector"<<std::endl;
	std::cerr<<"at position "<<ePos<<std::endl;
	return false; // premature end of vector
      }
      DEBUG("loop "<<ePos<<" vp before is size "<<strlen(vp));
      vp = vectorElem.DeserializeFromString(vp, bbiModulus); //decode element
      DEBUG("vp after is size "<<strlen(vp));
      newVec[ePos] = vectorElem;//store it
    }
    *this = std::move(newVec);//save the overall vector
    return true;
  }

} // namespace lbcrypto ends
 
#ifdef UBINT_32
template class exp_int::mubintvec<exp_int::ubint<uint32_t>>; 
#endif
#ifdef UBINT_64
template class exp_int::mubintvec<exp_int::ubint<uint64_t>>; 
#endif
