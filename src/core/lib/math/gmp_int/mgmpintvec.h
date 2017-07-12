/**
 * @file mgmpintvec.h This file contains ubintvec, a <vector> of ubint, with associated
 * math operators
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
 * This file contains ubintvec, a <vector> of ubint, with associated
 * math operators.  
 * NOTE: this has been refactored so that implied modulo (ring)
 * aritmetic is in mbintvec
 *
 */

#ifndef LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H
#define LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H

#include <iostream>
#include <vector>

#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include <initializer_list>
#include "gmpintvec.h"
#include "mgmpint.h"

#if 1
#include <NTL/vector.h>
#include <NTL/vec_ZZ.h>
#include <NTL/SmartPtr.h>
#include <NTL/vec_ZZ_p.h>
#endif

//defining this forces modulo when you write to the vector (except with SetValAtIndexWithoutMod)
#define FORCE_NORMALIZATION 

/**
 * @namespace NTL
 * The namespace of this code
 */
namespace NTL {
  /**
   * @brief The class for representing vectors of ubint with associated modulo math
   */
  //note this inherits from gmpintvec

  //JSON FACILITY

  template<class myT>
    class myVecP : public NTL::Vec<myT> {
    //    class myVecP : public lbcrypto::Serializable


  public:
    //note gmpint.h puts constructor bodies here, 
    //mubint.h moves them to .cpp, so we may do that too. 


  myVecP(): Vec<myT>() {};
    //constructors without moduli
    explicit myVecP(const usint n): Vec<myT>(INIT_SIZE, n) {m_modulus_state = GARBAGE;}; 
   myVecP(const INIT_SIZE_TYPE, const long n): Vec<myT>(INIT_SIZE, n) {m_modulus_state = GARBAGE;}; 
   myVecP(const INIT_SIZE_TYPE, const long n,  myT const& a): Vec<myT>(INIT_SIZE, n, a)  {m_modulus_state = GARBAGE;}; 


    //copy
    // copy ctors with vector inputs
    explicit myVecP(const myVecP<myT> &a);
    explicit myVecP(const myVec<myZZ> &a);
    
    //movecopy
    myVecP(myVecP<myT> &&a);
    myVecP(myVec<myZZ> &&a);
    
    //constructors with moduli
    //ctor myZZ moduli
    myVecP(const long n, const myZZ &q);
    myVecP(const INIT_SIZE_TYPE, const long n, const myZZ &q);
    myVecP(const INIT_SIZE_TYPE, const long n, const myT& a, const myZZ &q);

    //constructors with moduli and initializer lists
    myVecP(const long n, const myZZ &q, std::initializer_list<usint> rhs);
    myVecP(const long n, const myZZ &q, std::initializer_list<std::string> rhs);
    
    //copy with myZZ moduli
    myVecP(const myVecP<myT> &a, const myZZ &q);
    myVecP(const myVec<myZZ> &a, const myZZ &q);
    
    //ctor with char * moduli
    myVecP(usint n, const char *sq);
    myVecP(INIT_SIZE_TYPE, long n, const char *sq);
    myVecP(INIT_SIZE_TYPE, long n, const myT& a, const char *sq);
    
     //copy with char * moduli
     myVecP(const myVecP<myT> &a, const char *sq);
    myVecP(const myVec<myZZ> &a, const char *sq);

    //ctor with usint moduli
    myVecP(usint n, usint q);
    myVecP(INIT_SIZE_TYPE, long n, usint q);
    myVecP(INIT_SIZE_TYPE, long n, const myT& a, usint q);

    //copy with unsigned int moduli
    myVecP(const myVecP<myT> &a, const usint q);
    myVecP(const myVec<myZZ> &a, const usint q);
    
    //destructor
    ~myVecP();
    
    //adapters
    myVecP(std::vector<std::string>& s); //without modulus
    
    myVecP(std::vector<std::string>& s, const myZZ &q); // with modulus
    myVecP(std::vector<std::string>& s, const char *sq); // with modulus
    myVecP(std::vector<std::string>& s, const usint q); // with modulusu

    const myVecP& operator=(const myVecP &a);


    const myVecP& operator=(std::initializer_list<myT> rhs);
    const myVecP& operator=(std::initializer_list<int> rhs);
    const myVecP& operator=(std::initializer_list<usint> rhs);
    const myVecP& operator=(std::initializer_list<std::string> rhs);
    const myVecP& operator=(std::initializer_list<const char *> rhs);
    const myVecP& operator=(myT &rhs);
    const myVecP& operator=(const myT &rhs);
    const myVecP& operator=(unsigned int &rhs);
    const myVecP& operator=(unsigned int rhs);

    void clear(myVecP& x); //why isn't this inhereted?


    // Note, SetValAtIndex should be deprecated by .at() and []
    void SetValAtIndex(usint index, const myT&value);
    void SetValAtIndex(usint index, const myZZ&value);
    void SetValAtIndex(usint index, const char *s);
    void SetValAtIndex(usint index, const std::string& str);

    void SetValAtIndexWithoutMod(usint index, const myZZ&value);

    //DBC could not get & return to work!!!
    const myZZ GetValAtIndex(size_t index) const;

    /**
     * Returns a vector of digit at a specific index for all entries
     * for a given number base.
     * TODO: rename this better... what is a digit?
     * TODO: does this fail for some values of base?
     * @param index is the index to return the digit from in all entries.
     * @param base is the base to use for the operation.
     * @return is the resulting vector.
     */
    myVecP  GetDigitAtIndexForBase(usint index, usint base) const;
  
    inline void push_back(const myT& a) { this->append(a);};

    static inline myVecP Single(const myZZ& val, const myZZ &modulus) {
      bool dbg_flag = false;
      DEBUG("single in");
      myVecP vec(1);
      DEBUG("a");
      vec.SetModulus(modulus);
      DEBUG("b");
      vec[0]=val;
      DEBUG("single out");
      return vec;
    };

    //comparison. 
    
    //arithmetic
    //scalar modulus
    
    myVecP operator%(const myZZ& b) const; 
    
    myVecP Mod(const myZZ& b) const; //defined in cpp
    
    myVecP ModByTwo() const; //defined in cpp
    
    void SwitchModulus(const myZZ& newModulus);
    
    //scalar modulo assignment
    inline myVecP& operator%=(const myZZ& a)
    { 
      for (size_t i = 0; i < this->size(); i++){
	(*this)[i]%=a;
      }
      return *this;
    };
    
    //vector addition assignment
    inline myVecP& operator+=(const myVecP& a) {
      this->ArgCheckVector(a, "myVecP::op +=");
      add(*this, *this, a);
      return *this;
    };
    
    //scalar addition assignment
    inline myVecP& operator+=(const myZZ& a)
    { 
      ModulusCheck("Warning: myVecP::op+=");
      for (unsigned int i = 0; i < this->size(); i++){
#ifdef FORCE_NORMALIZATION	
	//(*this)[i]=(*this)[i]+a%m_modulus; //+= not defined yet
	AddMod((*this)[i]._ZZ_p__rep,(*this)[i]._ZZ_p__rep, a, m_modulus); 
#else
	AddMod((*this)[i]._ZZ_p__rep,(*this)[i]._ZZ_p__rep, a, m_modulus); 
#endif
      }
      return *this;
    };
    
    myVecP operator+(const myVecP& b) const;
    myVecP operator+(const myZZ& b) const;
    
    inline myVecP Add(const myZZ& b) const {ModulusCheck("Warning: myVecP::Add"); return (*this)+b%m_modulus; };
    inline myVecP ModAdd(const myZZ& b) const {ModulusCheck("Warning: myVecP::ModAdd"); return (*this)+b%m_modulus; };
    void add(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural
    
    myVecP ModAddAtIndex(usint i, const myZZ &b) const;
    
    //vector add
    inline myVecP Add(const myVecP& b) const { ArgCheckVector(b, "myVecP Add()"); return (*this)+b;};
    inline myVecP ModAdd(const myVecP& b) const { return (this->Add(b));};
    
    //Subtraction
    //vector subtraction assignment
    inline myVecP& operator-=(const myVecP& a) {
      ArgCheckVector(a, "myVecP -="); 
      sub(*this, *this, a);
      return *this;
    };
    
    //scalar subtraction assignment
    inline myVecP& operator-=(const myZZ& a)
    { 
      ModulusCheck("Warning: myVecP::op-=");
      for (size_t i = 0; i < this->size(); i++){
	SubMod((*this)[i]._ZZ_p__rep,(*this)[i]._ZZ_p__rep, a, m_modulus); 	
	//(*this)[i]-=a%m_modulus;
      }
      return *this;
    };
    
    myVecP operator-(myVecP const& b) const;
    myVecP operator-(myZZ const& b) const;

    myVecP operator-(void); //negation


    //scalar
    inline myVecP Sub(const myZZ& b) const {ModulusCheck("Warning: myVecP::Sub"); return (*this)-b%m_modulus;};
    inline myVecP ModSub(const myZZ& b) const {ModulusCheck("Warning: myVecP::ModSub"); return (*this)-b%m_modulus;};
    
    //vector
    inline myVecP Sub(const myVecP& b) const {
      bool dbg_flag = false;
      DEBUG("in myVecP::Sub");
      DEBUG(*this);
      DEBUG(this->GetModulus());
      DEBUG(b);
      DEBUG(b.GetModulus());
      ArgCheckVector(b, "myVecP Sub()");  
      return (*this)-b;
    };
    inline myVecP ModSub(const myVecP& b) const {ArgCheckVector(b, "myVecP ModSub()"); return (this->Sub(b));};
    
    //deprecated vector
    inline myVecP Minus(const myVecP& b) const {ArgCheckVector(b, "myVecP Minus()"); return (this->Sub(b));};
    
    void sub(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural
    
    //Multiplication
    //vector multiplication assignments
    inline myVecP& operator*=(const myVecP& a)
    { 
      ArgCheckVector(a, "myVecP *="); 
      mul(*this, *this, a);
      return *this;
    };
    
    //scalar multiplication assignments
    inline myVecP& operator*=(const myZZ& a)
    { 
      ModulusCheck("Warning: myVecP::op-=");
      for (size_t i = 0; i < this->size(); i++){
	MulMod((*this)[i]._ZZ_p__rep,(*this)[i]._ZZ_p__rep, a, m_modulus); 
	//
      }
      return *this;
    };
    
    myVecP operator*(myVecP const& b) const;
    myVecP operator*(myZZ const& a) const;
    
    //scalar
    inline myVecP Mul(const myZZ& b) const {ModulusCheck("Warning: myVecP::Mul"); return (*this)*b%m_modulus;};
    inline myVecP ModMul(const myZZ& b) const {ModulusCheck("Warning: myVecP::ModMul"); return (*this)*b%m_modulus;};
    
    //vector
    inline myVecP Mul(const myVecP& b) const {ArgCheckVector(b, "myVecP Mul()"); return (*this)*b;};
    inline myVecP ModMul(const myVecP& b) const {ArgCheckVector(b, "myVecP Mul()");return (this->Mul(b));};
    
    void mul(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural
    
    
    /**
     * Scalar exponentiation.
     *
     * @param &b is the scalar to modulo exponentiate at all locations.
     * @return is the result of the exponentiation operation.
     */
    myVecP Exp(const myZZ &b) const;
    myVecP ModExp(const myZZ &b) const;
    
    myVecP MultiplyAndRound(const myT &p, const myT &q) const;
    myVecP DivideAndRound(const myT &q) const;
    
    
    /**
     * Modulus inverse.
     *
     * @return a new vector which is the result of the modulus inverse operation.
     */
    myVecP ModInverse(void) const;
    
    //public modulus accessors
    inline bool isModulusSet(void) const{
      return(this->m_modulus_state == INITIALIZED);
    };
    
    //return true if both myVecP have same modulus
    inline bool SameModulus(const myVecP &a) const{
      return((this->m_modulus_state == a.m_modulus_state)&&
	     (this->m_modulus == a.m_modulus));
    };
    
    //sets modulus and the NTL init function usint argument
    inline void SetModulus(const usint& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const usint& "<<value<<")");
      if (value == 0) {
	throw std::logic_error("SetModulus(usint) cannot be zero");
      }
      this->m_modulus= myZZ(value);
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };
    
    //sets modulus and the NTL init function myZZ argument
    inline void SetModulus(const myZZ& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const myZZ& "<<value<<")");
      if (value == myZZ::ZERO) {
	throw std::logic_error("SetModulus(myZZ) cannot be zero");
      }
      this->m_modulus= value;
      DEBUG("this->modulus = "<<this->m_modulus);
      this->m_modulus_state = INITIALIZED;
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };
    
    //sets modulus and the NTL init function using myZZ_p.modulus argument
    //note this is not the same as setting the modulus to value!
    inline void SetModulus(const myZZ_p& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const myZZ_p& "<<value<<")");
      if (value.GetModulus() == myZZ::ZERO) {
	throw std::logic_error("SetModulus(myZZ_p) cannot be zero");
      }
      this->m_modulus= value.GetModulus();
      DEBUG("this->modulus = "<<this->m_modulus);
      this->m_modulus_state = INITIALIZED;
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };
    
    //sets modulus and the NTL init function string argument
    inline void SetModulus(const std::string& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const string& "<<value<<")");
      this->m_modulus = myZZ(value);
      if (this->m_modulus == myZZ::ZERO) {
	throw std::logic_error("SetModulus(string) cannot be zero");
      }
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };
    //sets modulus and the NTL init function uses same modulus
    inline void SetModulus(const myVecP& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const myVecP& "<<value<<")");
      this->m_modulus = value.GetModulus();
      if (this->m_modulus == myZZ::ZERO) {
	throw std::logic_error("SetModulus(myVecP) cannot be zero");
      }
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };

    inline const myZZ& GetModulus() const{
      bool dbg_flag = false;
      if (this->isModulusSet()){
	DEBUG("GetModulus returns "<<this->m_modulus);
	return (this->m_modulus);
      }else{
	std::cout<<"myZZ GetModulus() on uninitialized modulus"<<std::endl;
	return myZZ::ZERO;
      }
    };
    
    inline int CopyModulus(const myVecP& rhs){
      bool dbg_flag = false;
      DEBUG("CopyModulus(const myVecP& modulus is "<<rhs.m_modulus);
      DEBUG("CopyModulus(const myVecP& modulus_state is "<<rhs.m_modulus_state);
      this->m_modulus = rhs.m_modulus;
      this->m_modulus_state = rhs.m_modulus_state;
      if (isModulusSet()){
	ZZ_p::init(this->m_modulus);
	return (0);
      } else{
	//std::cout<<"Warning: myVec_p::CopyModulus() from uninitialized modulus"<<std::endl; //happens many many times
	this->m_modulus_state = GARBAGE;
	return (-1);
      }
    };

    inline size_t GetLength(void) const{ //deprecated by size()
      return this->length();
    };

    inline size_t size(void) const{
      return this->length();
    };


    //need to add comparison operators == and !=
    //note these should fail if the modulii are different!
    // inline sint Compare(const myVecP& a) const {return compare(this->_ZZ_p__rep,a._ZZ_p__rep); };
    // myvecP and myvecP
    inline bool operator==(const myVecP& b) const
    { 
      if ((this->SameModulus(b)) && 
	  (this->size()==b.size())) { 
	//loop over each entry and fail if !=
	for (size_t i = 0; i < this->size(); ++i) {
	  if ((*this)[i]!=b[i]){
	    return false;
	  }
	}
	return true;// all entries ==
	
      }else{ //fails check of size and modulus
	return false;
      }
    };
    
    inline bool operator!=( const myVecP& b) const
    { return !(this->operator==(b)); };
    
    // myvecP and myvec<myZZ>
    inline bool operator==(const myVec<myZZ>& b) const
    { 
      if ((this->size()==b.size())) { //TODO: define size() for b
	//loop over each entry and fail if !=
	for (size_t i = 0; i < this->size(); ++i) {
	  if ((*this)[i]!=b[i]){
	    return false;
	  }
	}
	return true;// all entries ==
	
      }else{ //fails check of size
	return false;
      }
    };
    
    inline bool operator!=( const myVec<myZZ>& b) const
    { return !(this->operator==(b)); };
    
    
    // inline long operator<( const myZZ_p& b) const
    // { return this->Compare(b) < 0; }
    // inline long operator>( const myZZ_p& b) const
    // { return this->Compare(b) > 0; }
    // inline long operator<=( const myZZ_p& b) const
    // { return this->Compare(b) <= 0; }
    // inline long operator>=( const myZZ_p& b) const
    // { return this->Compare(b) >= 0; }


    /* operators to get a value at an index.
       * @param idx is the index to get a value at.
       * @return is the value at the index. return NULL if invalid index.
       */
#if 0 //this has problems 
    inline myZZ_p& operator[](std::size_t idx) {
      //myZZ_p tmp((*this)[idx]._ZZ_p__rep);
      //tmp.SetModulus(this->GetModulus());
      myZZ_p tmp = this->NTL::operator[](idx);
      

      if(! tmp.isModulusSet()){
	std::cout<<"op[] mod not set"<<std::endl;
	tmp.SetModulus(this->GetModulus());
      }
      return tmp;

      //here we have the problem we return the element, but it never had it's modulus value set. 
      //we need to somehow beable to set that modulus. 
    }

    inline const myZZ_p& operator[](std::size_t idx) const {
      if(! (*this)[idx].isModulusSet()){
	std::cout<<"const op[] mod not set"<<std::endl;
	//(*this)[idx].SetModulus(this->GetModulus());
      }
	//how do we get this to work for the const???
      return (*this)[idx];
    }
#endif
 

#if 0
    // ostream 
    friend std::ostream& operator<<(std::ostream& os, const myVecP &ptr_obj);
#endif


    //Todo: get rid of printvalues everywhere
    void PrintValues() const { std::cout << *this; }
    

    //JSON FACILITY
    /**
     * Serialize the object into a Serialized 
     *
     * @param serObj is used to store the serialized result. It MUST
     * be a rapidjson Object (SetObject());
     *
     * @param fileFlag is an object-specific parameter for the
     * serialization 
     *
     * @return true if successfully serialized
     */
    bool Serialize(lbcrypto::Serialized* serObj) const;

    /**
     * Populate the object from the deserialization of the Setialized
     * @param serObj contains the serialized object
     * @return true on success
     */
    bool Deserialize(const lbcrypto::Serialized& serObj);

  private:
    //utility function to warn if modulus is no good
    //use when argument to function is myZZ
    inline void ModulusCheck(std::string msg) const {
      if (!isModulusSet()){
	std::cout<<msg<<" uninitialized this->modulus"<<std::endl;
      } else {
	ZZ_p::init(this->m_modulus); //set global modulus to this 
      }
    };

    //utility function to check argument consistency for vector scalar fns
    //use when argument to function is myZZ_p (myT)
    inline void ArgCheckScalar(const myT &b, std::string fname) const {
      if(this->m_modulus!=b.GetModulus()) {
	throw std::logic_error(fname+" modulus vector modulus scalar op of different moduli");
      } else if (!isModulusSet()) {
	throw std::logic_error(fname+" modulus vector modulus scalar op GARBAGE  moduli");
      }
      ZZ_p::init(this->m_modulus); //set global modulus to this 
    };
    
    //utility function to check argument consistency for vector vector fns
    //use when argument to function is myVecP
    inline void ArgCheckVector(const myVecP &b, std::string fname) const {
      if(this->m_modulus!=b.m_modulus) {
	throw std::logic_error(fname+" modulus vector modulus vector op of different moduli");
      }else if (!isModulusSet()) {
	throw std::logic_error(fname+" modulus vector modulus vector op GARBAGE  moduli");
      }else if(this->size()!=b.size()){
	throw std::logic_error(fname +" vectors of different lengths");
      }
      
      ZZ_p::init(this->m_modulus); //set global modulus to this 
    };
    
    //used to make sure all entries in this are <=current modulus
    inline void Renormalize(void) {
      bool dbg_flag = false;
      DEBUG("mgmpintvec Renormalize modulus"<<m_modulus);     
      DEBUG("mgmpintvec size"<< this->size());     
      //loop over each entry and fail if !=
      for (auto i = 0; i < this->size(); ++i) {
	(*this)[i] %=m_modulus;
	DEBUG("this ["<<i<<"] now "<< (*this)[i]);     
      }
    };
    
    
    myZZ m_modulus;
    enum ModulusState {
      GARBAGE,INITIALIZED //note different order, Garbage is the default state
    };
    //enum to store the state of the
    ModulusState m_modulus_state;
    
  protected:
    bool IndexCheck(usint) const;
  }; //template class ends
  
  
  
  //comparison operators with two operands must be defined outside the class
  //myVec<myZZ> and myVecP
  inline long operator==(const myVec<myZZ> &a, const myVecP<myZZ_p> &b) 
  {
    if ((a.size()==b.size())) { 
      //loop over each entry and fail if !=
      for (size_t i = 0; i < a.size(); ++i) {
	if (a[i]!=b[i]){
	  return false;
	}
      }
      return true;// all entries ==
    }else{ //fails check of size
      return false;
    }
  };
  
  inline long operator!=(const myVec<myZZ> &a, const myVecP<myZZ_p> &b) 
  { return !(operator==(a,b)); };
  
  
  
} // namespace NTL ends

#endif // LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H
