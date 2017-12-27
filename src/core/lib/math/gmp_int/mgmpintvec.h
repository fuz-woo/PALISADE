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
#include "../../utils/exception.h"
#include <initializer_list>
#include "gmpint.h"

#include <NTL/vector.h>
#include <NTL/vec_ZZ.h>
#include <NTL/SmartPtr.h>

//defining this forces modulo when you write to the vector (except with at())
//this is becuase NTL required inputs to modmath to be < modulus but BU does not
// play with this and you will see different tests in pke pass and fail.
//I think this will go away soon
//#define FORCE_NORMALIZATION 


//defining this enables a run time warning when a vector with uninitialized modulus is used in math operations (A very bad thing) 
//#define WARN_BAD_MODULUS

/**
 * @namespace NTL
 * The namespace of this code
 */
namespace NTL {
  /**
   * @brief The class for representing vectors of ubint with associated modulo math
   */

  template<class myT>
    class myVecP : public NTL::Vec<myT> {
    //    class myVecP : public lbcrypto::Serializable


  public:


  myVecP(): Vec<myT>() {};
    //constructors without moduli
    explicit myVecP(const size_t length): Vec<myT>(INIT_SIZE, length) {m_modulus_state = GARBAGE;}; 
   myVecP(INIT_SIZE_TYPE, const long length): Vec<myT>(INIT_SIZE, length) {m_modulus_state = GARBAGE;};


    //copy
    // copy ctors with vector inputs
    explicit myVecP(const myVecP<myT> &a);
    
    //movecopy
    myVecP(myVecP<myT> &&a);
    
    //constructors with moduli
    //ctor myZZ moduli
    myVecP(const long n, const myZZ &q);

    //constructors with moduli and initializer lists
    myVecP(const long n, const myZZ &q, std::initializer_list<uint64_t> rhs);
    myVecP(const long n, const myZZ &q, std::initializer_list<std::string> rhs);
    
    //copy with myZZ moduli
    myVecP(const myVecP<myT> &a, const myZZ &q);
    
    //ctor with char * moduli
    myVecP(size_t n, const std::string &sq);
    
     //copy with char * moduli
    myVecP(const myVecP<myT> &a, const std::string &sq);

    //ctor with uint64_t moduli
    myVecP(size_t n, uint64_t q);

    //copy with uint64_t moduli
    myVecP(const myVecP<myT> &a, const uint64_t q);
    
    //destructor
    ~myVecP();
    
    //adapters
    myVecP(std::vector<std::string>& s); //without modulus
    
    myVecP(std::vector<std::string>& s, const myZZ &q); // with modulus
    myVecP(std::vector<std::string>& s, const char *sq); // with modulus
    myVecP(std::vector<std::string>& s, const uint64_t q); // with modulusu

    const myVecP& operator=(const myVecP &a);
    const myVecP& operator=(myVecP &&a);


    const myVecP& operator=(std::initializer_list<uint64_t> rhs);
    const myVecP& operator=(std::initializer_list<int32_t> rhs);
    const myVecP& operator=(std::initializer_list<std::string> rhs);
    const myVecP& operator=(uint64_t rhs);

    void clear(myVecP& x); //why isn't this inhereted?

    // the following are like writing to this->at(i) but with modulus implied.
    void atMod(size_t index, const myT&value);
    void atMod(size_t index, const std::string& str);

    const myZZ& at(size_t index) const;
    myZZ& at(size_t index);

    /**
     * Returns a vector of digit at a specific index for all entries
     * for a given number base.
     * TODO: rename this better... what is a digit?
     * TODO: does this fail for some values of base?
     * @param index is the index to return the digit from in all entries.
     * @param base is the base to use for the operation.
     * @return is the resulting vector.
     */
    myVecP  GetDigitAtIndexForBase(size_t index, usint base) const;
  
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
      modadd_p(*this, *this, a);
      return *this;
    };
    
    //scalar addition assignment
    inline myVecP& operator+=(const myZZ& a)
    { 
      ModulusCheck("Warning: myVecP::op+=");
      for (unsigned int i = 0; i < this->size(); i++){
	AddMod((*this)[i],(*this)[i], a, m_modulus); 
      }
      return *this;
    };
    
    myVecP operator+(const myVecP& b) const; //becomes modulo addition
    myVecP operator+(const myZZ& b) const; //becomes modulo addition
    
    inline myVecP Add(const myZZ& b) const {ModulusCheck("Warning: myVecP::Add"); return (*this)+b%m_modulus; };
    inline myVecP ModAdd(const myZZ& b) const {ModulusCheck("Warning: myVecP::ModAdd"); return this->Add(b); };

    void modadd_p(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural version
    
    myVecP ModAddAtIndex(size_t i, const myZZ &b) const;
    
    //vector add
    inline myVecP Add(const myVecP& b) const { 
      ArgCheckVector(b, "myVecP Add()"); 
      return (*this)+b;
    };
    inline myVecP ModAdd(const myVecP& b) const { 
      return (this->Add(b));
    };
    
    //Subtraction
    //vector subtraction assignment note uses DIFFERNT modsub than standard math
    //this is a SIGNED mod sub
    inline myVecP& operator-=(const myVecP& a) {
      ArgCheckVector(a, "myVecP -="); 
      modsub_p(*this, *this, a);
      return *this;
    };
    
    //scalar subtraction assignment
    inline myVecP& operator-=(const myZZ& a)
    { 
      ModulusCheck("Warning: myVecP::op-=");
      *this = *this-a;
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

    //procecural
    void modsub_p(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural
    
    //Multiplication
    //vector multiplication assignments
    inline myVecP& operator*=(const myVecP& a)
    { 
      ArgCheckVector(a, "myVecP *="); 
      modmul_p(*this, *this, a);
      return *this;
    };
    
    //scalar multiplication assignments
    inline myVecP& operator*=(const myZZ& a)
    { 
      ModulusCheck("Warning: myVecP::op-=");
      for (size_t i = 0; i < this->size(); i++){
	MulMod((*this)[i],(*this)[i], a%m_modulus, m_modulus); 
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
    
    void modmul_p(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural
    
    
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
    
    //sets modulus and the NTL init function uint64_t argument
    inline void SetModulus(const uint64_t& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const uint64_t& "<<value<<")");
      if (value == 0) {
	PALISADE_THROW(lbcrypto::palisade_error, "SetModulus(uint64_t) cannot be zero");
      }
      this->m_modulus= myZZ(value);
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      // ZZ_p::init(this->m_modulus);
      //this->Renormalize();
    };
    
    //sets modulus and the NTL init function myZZ argument
    inline void SetModulus(const myZZ& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const myZZ& "<<value<<")");
      if (value == myZZ::ZERO) {
	PALISADE_THROW( lbcrypto::palisade_error, "SetModulus(myZZ) cannot be zero");
      }
      this->m_modulus= value;
      DEBUG("this->modulus = "<<this->m_modulus);
      this->m_modulus_state = INITIALIZED;
      //ZZ_p::init(this->m_modulus);
      //this->Renormalize();
    };
    
    //sets modulus and the NTL init function string argument
    inline void SetModulus(const std::string& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const string& "<<value<<")");
      this->m_modulus = myZZ(value);
      if (this->m_modulus == myZZ::ZERO) {
	PALISADE_THROW( lbcrypto::palisade_error, "SetModulus(string) cannot be zero");
      }
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      //ZZ_p::init(this->m_modulus);
      //this->Renormalize();
    };
    //sets modulus and the NTL init function uses same modulus
    inline void SetModulus(const myVecP& value){
      bool dbg_flag = false;
      DEBUG("SetModulus(const myVecP& "<<value<<")");
      this->m_modulus = value.GetModulus();
      if (this->m_modulus == myZZ::ZERO) {
	PALISADE_THROW( lbcrypto::palisade_error, "SetModulus(myVecP) cannot be zero");
      }
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      //ZZ_p::init(this->m_modulus);
      //this->Renormalize();
    };

    inline const myZZ& GetModulus() const{
      bool dbg_flag = false;
      if (this->isModulusSet()){
	DEBUG("GetModulus returns "<<this->m_modulus);
	return (this->m_modulus);
      }else{
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
	//ZZ_p::init(this->m_modulus);
	return (0);
      } else{
	this->m_modulus_state = GARBAGE;
	return (-1);
      }
    };

    inline size_t GetLength(void) const{ //deprecated by size()
      // size() is STL::Vector standard call for this functionality.
      //note it returns size_type, but we will use size_t
      return this->size();
    };

    inline size_t size(void) const{
      //note length() returns a long in NTL, which triggers issues with
      // comparison against  
      return this->length();
    };

    inline void resize(size_t n) {
      //resize is the STL::vector standard call for this functionality
      this->SetLength(n); //SetLength() is an NTL call
    }

    //need to add comparison operators == and !=
    //note these should fail if the modulii are different!
    // inline int32_t Compare(const myVecP& a) const {return compare(this->_ZZ_p__rep,a._ZZ_p__rep); };
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
	//ZZ_p::init(this->m_modulus); //set global modulus to this 
      }
    };


    //utility function to check argument consistency for vector vector fns
    //use when argument to function is myVecP
    inline void ArgCheckVector(const myVecP &b, std::string fname) const {
      if(this->m_modulus!=b.m_modulus) {
	PALISADE_THROW( lbcrypto::palisade_error, fname+" modulus vector modulus vector op of different moduli");
      }else if (!isModulusSet()) {
	PALISADE_THROW( lbcrypto::palisade_error, fname+" modulus vector modulus vector op GARBAGE  moduli");
      }else if(this->size()!=b.size()){
	PALISADE_THROW( lbcrypto::palisade_error,  fname+" vectors of different lengths");
      }
      
      //ZZ_p::init(this->m_modulus); //set global modulus to this 
    };
    
    //used to make sure all entries in this are <=current modulus
    inline void Renormalize(void) {
      bool dbg_flag = false;
      DEBUG("mgmpintvec Renormalize modulus"<<m_modulus);     
      DEBUG("mgmpintvec size"<< this->size());     
      //loop over each entry and fail if !=
      for (size_t i = 0; i < this->size(); ++i) {
	(*this)[i] %=m_modulus;
	DEBUG("this ["<<i<<"] now "<< (*this)[i]);     
      }
    };
    
    
    myZZ m_modulus;
    //TODO: BE 2 has gotten rid of this, we may too.
    enum ModulusState {
      GARBAGE,INITIALIZED //note different order, Garbage is the default state
    };
    //enum to store the state of the
    ModulusState m_modulus_state;
    
  protected:
    bool IndexCheck(size_t index) const;
  }; //template class ends
  
  
  
} // namespace NTL ends

#endif // LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H

