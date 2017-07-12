/**
 * @file gmpintvec.h This file contains ubintvec, a <vector> of ubint, with associated
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
 /*
 *
 * This file contains ubintvec, a <vector> of ubint, with associated
 * math operators.  
 * NOTE: this has been refactored so that implied modulo (ring)
 * aritmetic is in mbintvec
 *
 */

#ifndef LBCRYPTO_MATH_GMPINT_GMPINTVEC_H
#define LBCRYPTO_MATH_GMPINT_GMPINTVEC_H


#include <iostream>
#include <vector>

//#include "binmat.h"
#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include <initializer_list>
#include "gmpint.h"
#include <NTL/vector.h>
#include <NTL/vec_ZZ.h>



/**
 * @namespace NTL
 * The namespace of this code
 */
namespace NTL {
  /**
   * @brief The class for representing vectors of ubint with associated math
   */
  //JSON FACILITY

  template<class myT>
    class myVec : public NTL::Vec<myT> {
    
  public:
    //ctors with no or int inputs
  myVec() : Vec<myT>() {};
  myVec(usint n) : Vec<myT>(INIT_SIZE, n) {}; // adapter kit
  myVec(INIT_SIZE_TYPE, long n) : Vec<myT>(INIT_SIZE, n) {};
  myVec(INIT_SIZE_TYPE, long n, const myT& a) : Vec<myT>(INIT_SIZE, n, a) {};  
    
    //copy Ctors with vector inputs    
  myVec(const myVec<myT> &a) : Vec<myT>(a) {};
    //move copy
    myVec(const myVec<myT> &&a);
    
    myVec(std::vector<std::string>& s);
    
    
    //adapters

    const myVec& operator=(std::initializer_list<myT> rhs);
    const myVec& operator=(std::initializer_list<usint> rhs);
    const myVec& operator=(std::initializer_list<std::string> rhs);
    const myVec& operator=(std::initializer_list<const char *> rhs);
    const myVec& operator=(const myVec &rhs);
    const myVec& operator=(const myT &rhs);
    const myVec& operator=(unsigned int &rhs);
    const myVec& operator=(unsigned int rhs);

    void clear(myVec& x); //why isn't this inhereted?

    inline size_t size(void) const {return this->length();};

    void SetValAtIndex(usint index, const myT&value);
    void SetValAtIndex(usint index, const char *s);
    void SetValAtIndex(usint index, const std::string& str);
    const myT& GetValAtIndex(size_t index) const;

    inline void push_back(const myT& a) { this->append(a);};

    static inline myVec Single(const myZZ val) { 
      myVec vec(1);
      vec[0]=val;
      return vec;
    }

    //arithmetic
    //scalar modulus

    myVec operator%(const myT& b) const; 

    inline myVec Mod(const myZZ& b) const { return (*this)%b;};

    //scalar modulo assignment
    inline myVec& operator%=(const myT& a)
    { 
      unsigned int n = this->length();
      for (unsigned int i = 0; i < n; i++){
	(*this)[i]%=a;
      }
      return *this;
    };

    inline myVec& operator+=(const myVec& a) {
      add(*this, *this, a);
      return *this;
    };

    //scalar addition assignment
    inline myVec& operator+=(const myT& a)
    { 
      unsigned int n = this->length();
      for (unsigned int i = 0; i < n; i++){
	(*this)[i]+=a;
      }
      return *this;
    };

    myVec operator+(const myVec& b) const;
    myVec operator+(const myT& b) const;

    inline myVec Add(const myT& b) const { return (*this)+b;};

    void add(myVec& x, const myVec& a, const myVec& b) const; //define procedural

    //vector add
    inline myVec Add(const myVec& b) const { return (*this)+b;};

    //Subtraction
    inline myVec& operator-=(const myVec& a)
    { 
      sub(*this, *this, a);
      return *this;
    };

    inline myVec& operator-=(const myT& a)
    { 
      unsigned int n = this->length();
      for (unsigned int i = 0; i < n; i++){
	(*this)[i]-=a;
      }
      return *this;
    };

  
    myVec operator-(const myVec& b) const;
    myVec operator-(const myT& a) const;

    //scalar
    inline myVec Sub(const myT& b) const { return (*this)-b;};
    //vector
    inline myVec Sub(const myVec& b) const { return (*this)-b;};

    //deprecated vector
    inline myVec Minus(const myVec& b) const { return (*this)-b;};

    void sub(myVec& x, const myVec& a, const myVec& b) const; //define procedural

    //Multiplication
    inline myVec& operator*=(const myVec& a)
    { 
      mul(*this, *this, a);
      return *this;
    };

    inline myVec& operator*=(const myT& a)
    { 
      unsigned int n = this->length();
      for (unsigned int i = 0; i < n; i++){
	(*this)[i]*=a;
      }
      return *this;
    };

  
    myVec operator*(const myVec& b) const;
    myVec operator*(const myT& a) const;
    //scalar
    inline myVec Mul(const myT& b) const { return (*this)*b;};
    //vector
    inline myVec Mul(const myVec& b) const { return (*this)*b;};
    void mul(myVec& x, const myVec& a, const myVec& b) const; //define procedural

    //not tested yet

    //scalar then vector
    //note a more efficient means exists for these
    inline myVec ModAdd(const myT& b, const myZZ& modulus) const {return ((*this)+b)%modulus;};
    inline myVec ModAdd(const myVec& b, const myZZ& modulus) const {return ((*this)+b)%modulus;};

    //Need to mimic Palisade use of signed modulus for modsub.
    inline myVec ModSub(const myT& b, const myZZ& modulus) const 
    {
      unsigned int n = this->length();
      myVec<myT> res(n);
      for (unsigned int i = 0; i < n; i++){
	res[i] = (*this)[i].ModSub(b, modulus);
      }
      return(res);
    };

    inline myVec ModSub(const myVec& b, const myZZ& modulus) const 
    {
      unsigned int n = this->length();
      myVec<myT> res(n);
      for (unsigned int i = 0; i < n; i++){
	res[i] = (*this)[i].ModSub(b[i],modulus);
      }
      return(res);
    };

    inline myVec ModMul(const myT& b, const myZZ& modulus) const {return ((*this)*b)%modulus;};
    inline myVec ModMul(const myVec& b, const myZZ& modulus) const {return ((*this)*b)%modulus;};

  protected:
    bool IndexCheck(usint) const;

  }; //template class ends

} // namespace NTL ends

#endif // LBCRYPTO_MATH_GMPINT_GMPINTVEC_H
