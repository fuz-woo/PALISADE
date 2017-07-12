/*
 * @file gmpintvec.cpp This file contains ubintvec, a <vector> of ubint, with associated
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
#if defined(__linux__) && MATHBACKEND == 6

#include "gmpintvec.h"

#include "../../utils/debug.h"


namespace NTL {

 template<class myT>
  myVec<myT>::myVec(const myVec<myT> &&a) : Vec<myT>(INIT_SIZE, a.length()) 
  {
    //consider using Victor's move(a);
    for (auto i=0; i< a.length(); i++) {
      (*this)[i]=a[i];
    }
  }

  // constructor specifying the myvec as a vector of strings
  template<class myT>
  myVec<myT>::myVec(std::vector<std::string> &s){
    usint len = s.size();
    this->SetLength(len);
    for (usint i = 0; i < len; i++){
      (*this)[i] = myT(s[i]);
    }
  }

  //Assignment with initializer list of myZZ
  // does not resize the vector
  // unless lhs size is too small
  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(std::initializer_list<myT> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <myT>");
    size_t len = rhs.size();
    if (this->size()< len){
      this->SetLength(len);
    };

    for(usint i=0;i<this->size();i++){ // this loops over each entry
      if (i<len) {
	(*this)[i] =  myT(*(rhs.begin()+i));
      }else{
	(*this)[i] =  myT::ZERO;
      }
    }
    return *this;
  }

  //Assignment with initializer list of usints
  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(std::initializer_list<usint> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <myT>");
    size_t len = rhs.size();
    if (this->size()< len){
      this->SetLength(len);
    };
    for(usint i=0;i<this->size();i++){ // this loops over each entry
      if (i<len) {
	(*this)[i] =  myT(*(rhs.begin()+i));
      }else{
	(*this)[i] =  myT::ZERO;
      }
    }
    return *this;
  }
  
  //Assignment with initializer list of strings
  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(std::initializer_list<std::string> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <string>");
    size_t len = rhs.size();
    if (this->size()< len){
      this->SetLength(len);
    };
    for(usint i=0;i<this->size();i++){ // this loops over each entry
      if (i<len) {
	(*this)[i] =  myT(*(rhs.begin()+i));
      }else{
	(*this)[i] =  myT::ZERO;
      }
    }
    return *this;
  }

  //Assignment with initializer list of const char *
  //not sure why this isn't taken care of by string above

  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(std::initializer_list<const char *> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist const char*");
    size_t len = rhs.size();
    if (this->size()< len){
      this->SetLength(len);
    };
    for(usint i=0;i<this->size();i++){ // this loops over each entry
      if (i<len) {
	(*this)[i] =  myT(*(rhs.begin()+i));
      }else{
	(*this)[i] =  myT::ZERO;
      }
    }
    return *this;
  }

  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(const myVec<myT> &rhs){
    bool dbg_flag = false;
    DEBUG("in op=const myVec<myT>&");
    usint len = rhs.length(); //TODO: define size()
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  rhs[i];
    }
    return *this;
  }

  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(const myT &rhs){
    bool dbg_flag = false;
    DEBUG("in op=myT&");
    this->SetLength(1);
    (*this)[0] =rhs;
    return *this;
  }

  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(unsigned int &rhs){
    bool dbg_flag = false;
    DEBUG("in op=usint&");
    this->SetLength(1);
    (*this)[0] =rhs;
    return *this;
  }

  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(unsigned int rhs){
    bool dbg_flag = false;
    DEBUG("in op=usint");
    this->SetLength(1);
    (*this)[0] =rhs;
    return *this;
  }

  template<class myT>
  void myVec<myT>::clear(myVec<myT>& x){
    //sets all elements to zero, but does not change length
    bool dbg_flag = false;
    DEBUG("in clear myVec");
    //using NTL_NAMESPACE::clear;
    long n = x.length();
    long i;
    for (i = 0; i < n; i++){
      NTL_NAMESPACE::clear(x[i]);  
    }
  }
  /// ARITHMETIC FUNCTIONS

  //arithmetic operations
  //modulus

  template<class myT>
  myVec<myT> myVec<myT>::operator%( const myT& b) const
  {
    unsigned int n = this->length();
    myVec<myT> res(n);
    for (unsigned int i = 0; i < n; i++){
      res[i] = (*this)[i]%b;
    }
    return(res);
  }

  //addition of scalar
  template<class myT>
  myVec<myT> myVec<myT>::operator+( const myT& b) const
  {
    unsigned int n = this->length();
    myVec<myT> res(n);
    long i;
    for (i = 0; i < n; i++)
      res[i] = (*this)[i]+b;
    return(res);
  }

  //addition of vector
  //why can't I inheret this?
  template<class myT>
  myVec<myT> myVec<myT>::operator+( const myVec<myT>& b) const
  {
    myVec<myT> res;
    myVec<myT>::add(res, *this, b);
    //NTL_OPT_RETURN(myVec<myT>, res);
    return(res);
  }

  //procedural addition why can't I inheret this?
  template<class myT>
  void  myVec<myT>::add(myVec<myT>& x, const myVec<myT>& a, const myVec<myT>& b) const
  {
    unsigned int n = a.length();
    if (b.length() != n) LogicError("vector add: dimension mismatch");

    x.SetLength(n);
    unsigned int i;
    for (i = 0; i < n; i++)
      x[i]=a[i]+b[i];
  }
  
  //subtraction of scalar
  template<class myT>
  myVec<myT> myVec<myT>::operator-( const myT& b) const
  {
    unsigned int n = this->length();
    myVec<myT> res(n);
    long i;
    for (i = 0; i < n; i++)
      res[i] = (*this)[i]-b;
    return(res);
  }

  //subtraction of vector
  template<class myT>
  myVec<myT> myVec<myT>::operator-( const myVec<myT>& b) const
  {
    myVec<myT> res;
    myVec<myT>::sub(res, *this, b);
    //NTL_OPT_RETURN(myVec<myT>, res);
    return(res);
  }

  //procedural subtraction why can't I inheret this?
  template<class myT>
  void  myVec<myT>::sub(myVec<myT>& x, const myVec<myT>& a, const myVec<myT>& b) const
  {
    unsigned int n = a.length();
    if (b.length() != n) LogicError("vector add: dimension mismatch");

    x.SetLength(n);
    unsigned int i;
    for (i = 0; i < n; i++)
      x[i]=a[i]-b[i];
  }

  //multiplication of scalar
  template<class myT>
  myVec<myT> myVec<myT>::operator*( const myT& b) const
  {
    unsigned int n = this->length();
    myVec<myT> res(n);
    long i;
    for (i = 0; i < n; i++)
      res[i] = (*this)[i]*b;
    return(res);
  }

  //multiplication of vector
  template<class myT>
  myVec<myT> myVec<myT>::operator*( const myVec<myT>& b) const
  {
    myVec<myT> res;
    myVec<myT>::mul(res, *this, b);
    //NTL_OPT_RETURN(myVec<myT>, res);
    return(res);
  }

  //procedural multiplication why can't I inheret this?
  template<class myT>
  void  myVec<myT>::mul(myVec<myT>& x, const myVec<myT>& a, const myVec<myT>& b) const
  {
    unsigned int n = a.length();
    if (b.length() != n) LogicError("vector add: dimension mismatch");

    x.SetLength(n);
    unsigned int i;
    for (i = 0; i < n; i++)
      x[i]=a[i]*b[i];
  }

  //////////////////////////////////////////////////
  // Set value at index from ubint
  template<class myT>
  void myVec<myT>::SetValAtIndex(usint index, const myT& value){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVec index out of range");
    }
    else{
      this->at(index) = myZZ(value);
    }
  }


  // set value at index from string
  template<class myT>
  void myVec<myT>::SetValAtIndex(usint index, const std::string& str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVec index out of range");
    }
    else{
      this->at(index) = myZZ(str);
    }
  }
  // set value at index from const char*
  template<class myT>
  void myVec<myT>::SetValAtIndex(usint index, const char * str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVec index out of range");
    }
    else{
      this->at(index) = myZZ(str);
    }
  }

  template<class myT>
  const myT& myVec<myT>::GetValAtIndex(size_t index) const{
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVec index out of range");
    }
    return this->at(index);
  }

  //Private functions
  template<class myT>
  bool myVec<myT>::IndexCheck(usint length) const{
    if(length>this->length())
      return false;
    return true;
  }



} // namespace NTL ends

template class NTL::myVec<NTL::myZZ>; //instantiate template here

#endif
