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
 * This file contains mubintvec, a <vector> of ubint, with associated
 * modulus and modulo math operators.  
 *
 */

#ifndef LBCRYPTO_MATH_EXPINT_MUBINTVEC_H
#define LBCRYPTO_MATH_EXPINT_MUBINTVEC_H

#include <iostream>
#include <vector>

//#include "binmat.h"
#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include <initializer_list>
#include "ubintvec.h"
 #include "../cpu_int/binvect.h"


/**
 * @namespace exp_int
 * The namespace of exp_int
 */
namespace exp_int {
/**
 * @brief The class for representing vectors of ubint with associated modulo math
 */

template<class ubint_el_t>
class mubintvec: public ubintvec<ubint_el_t>
	// note inherits Serializable from ubintvec
{
public:
  /**
   * Basic constructor.
   */
  explicit mubintvec();

  static inline mubintvec Single(const ubint_el_t& val, const ubint_el_t&modulus) {
    mubintvec vec(1);
    vec.m_data[0]=val;
    vec.SetModulus(modulus);
    return vec;
  }

  /**
   * Basic constructor for specifying the length of the vector.
   *
   * @param length initial size in terms of the number of entries.
   */
  explicit mubintvec(usint length);

  /**
   * Basic constructor for specifying the length and modulus of the vector.
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus usint associated with entries in the vector.
   */
  explicit mubintvec(const usint length, const usint &modulus);

  /**
   * Basic constructor for specifying the length of the vector with modulus
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus ubint associated with entries in the vector.
   */
  explicit mubintvec(const usint length, const ubint_el_t & modulus);

  /**
   * Basic constructor for specifying the length and modulus of the vector.
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus string associated with entries in the vector.
   */
  explicit mubintvec(const usint length, const std::string& modulus);


  /**
   * Basic constructor for specifying the length of the vector with
   * modulus with initializer lists
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus ubint associated with entries in the vector.
   * @param rhs initialier list of usints
   */
  explicit mubintvec(const usint length, const ubint_el_t & modulus, std::initializer_list<usint> rhs);


  /**
   * Basic constructor for specifying the length of the vector with
   * modulus with initializer lists
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus ubint associated with entries in the vector.
   * @param rhs initialier list of strings
   */
  explicit mubintvec(const usint length, const ubint_el_t & modulus, std::initializer_list<std::string> rhs);


  // constructor specifying the mubintvec as a vector of strings and modulus
  explicit mubintvec(const std::vector<std::string> &s, const ubint_el_t &modulus);

  // constructor specifying the mubintvec as a vector of strings and modulus
  explicit mubintvec(const std::vector<std::string> &s, const std::string &modulus);

  // constructor specifying the mubintvec as an ubintvec and undefined modulus
 explicit mubintvec(const ubintvec<ubint_el_t> &b);

#if 1


  // constructor specifying the mubintvec as an ubintvec and usint modulus
 explicit mubintvec(const ubintvec<ubint_el_t> &b, const usint &modulus);

  // constructor specifying the mubintvec as an ubintvec and string modulus
 explicit mubintvec(const ubintvec<ubint_el_t> &b, const std::string &modulus);
  
  // constructor specifying the mubintvec as an ubintvec and modulus
 explicit mubintvec(const ubintvec<ubint_el_t> &s, const ubint_el_t &modulus);
#endif

  /**
   * Basic constructor for copying a vector
   *
   * @param rhs is the mubintvec to be copied.
   */
  explicit mubintvec(const mubintvec& rhs);

  /**
   * Basic move constructor for moving a vector
   *
   * @param &&rhs is the mubintvec to be moved.
   */
  mubintvec(mubintvec &&rhs);      //move copy constructor

  /**
   * Assignment operator
   *
   * @param &rhs is the mubintvec to be assigned from.
   * @return assigned mubintvec ref.
   */
  const mubintvec& operator=(const mubintvec &rhs);

  /**
       * move assignment  contructor
   *
   * @param &rhs is the mubintvec to move
   * @return the return value.
   */
  const mubintvec& operator=(mubintvec &&rhs);

  /**
   * Initializer list for mubintvec.
   *
   * @param &&rhs is the list of ubints to be assigned to the mubintvec.
   * @return mubintvec object 
   * note if  modulus is set then mod(input) is stored
   * note modulus remains unchanged.
   */

  const mubintvec& operator=(std::initializer_list<ubint_el_t> rhs);

  /**
   * Initializer list for mubintvec.
   *
   * @param &&rhs is the list of usints to be assigned to the mubintvec.
   * @return mubintvec object 
   * note if  modulus is set then mod(input) is stored
   * note modulus remains unchanged.
   */

  const mubintvec& operator=(std::initializer_list<usint> rhs);

  /**
   * Initializer list for mubintvec.
   *
   * @param &&rhs is the list of sints to be assigned to the mubintvec.
   * @return mubintvec object 
   * note if  modulus is set then mod(input) is stored
   * note modulus remains unchanged.
   */

  const mubintvec& operator=(std::initializer_list<sint> rhs);

  /**
   * Initializer list for mubintvec.
   *
   * @param &&rhs is the list of strings to be assigned to the mubintvec.
   * @return mubintvec object 
   * note if  modulus is set then mod(input) is stored
   * note modulus remains unchanged.
   */

  const mubintvec& operator=(std::initializer_list<std::string> rhs);

  /**
   * Equality test == for mubintvec.
   *
   * @param &b is the mubintvec to test equality with 
   * @return true if == false otherwise
   * note moduli must also be ==
   */
  
  inline bool operator==(const mubintvec &b) const {
    if (this->ubintvec<ubint_el_t>::GetLength() != b.GetLength()) {
      return false;
    }      //todo replace with vector equality check.
    if (this->m_modulus != b.m_modulus)
      return false;
    for (size_t i = 0; i < this->GetLength(); ++i) {
      if (this->GetValAtIndex(i) != b.GetValAtIndex(i)) {
        return false;
      }
    }
    return true;
  }
  /**
   * NotEquals operator checks if to ubintvec objs are Notequal
   *
   * @param &&rhs is the ubintvec to compare  with.
   * @return true if not equal, false otherwise.
   */
  
  
  
  inline bool operator!=(const mubintvec &b) const {
    return !(*this == b);
  }
  

//&&&
 
  /**
   * Equality test == for mubintvec and ubintvec
   *
   * @param &b is the ubintvec to test equality with 
   * @return true if == false otherwise
   */
  
  inline bool operator==(const ubintvec<ubint_el_t> &b) const {
    if (this->ubintvec<ubint_el_t>::GetLength() != b.GetLength()) {
      return false;
    }      //todo replace with vector equality check.
    for (size_t i = 0; i < this->GetLength(); ++i) {
      if (this->GetValAtIndex(i) != b.GetValAtIndex(i)) {
        return false;
      }
    }
    return true;
  }
      /**
       * NotEquals operator checks if mubintvec ubintvec objs are Notequal
       *
       * @param &&rhs is the ubintvec to compare  with.
       * @return true if not equal, false otherwise.
       */



  inline bool operator!=(const ubintvec<ubint_el_t> &b) const {
    return !(*this == b);
  }

  //&&&&

  //currently screwing around with these
  //assignment from usint Note this is not the standard mathematical approach
  /**
   * @param &&rhs is the usint value to assign to the zeroth entry
   * @return resulting ubintvec
   * note that modulus remains untouched.
   */

  //assignment from usint
  inline const mubintvec& operator=(usint val) {
    //todo this is the way kurt and yuri want it
    this->m_data[0] = val;
    for (size_t i = 1; i < this->ubintvec<ubint_el_t>::GetLength(); ++i) {
      this->m_data[i] = 0;
    }
    //m_modulus=0;
    //m_modulus_state = GARBAGE;
    //std::cout<<"inline operator=usint "<<val<<std::endl;
    return *this;
  }
  
  //assignment from sint
  inline const mubintvec& operator=(sint val) {
    //todo this is the way kurt and yuri want it
    if (val<0) 
      throw std::logic_error("mubintvec() = with  negative number");
    this->m_data[0] = val;
    for (size_t i = 1; i < this->ubintvec<ubint_el_t>::GetLength(); ++i) {
      this->m_data[i] = 0;
    }
    //m_modulus=0;
    //m_modulus_state = GARBAGE;
    //std::cout<<"inline operator=sint "<<val<<std::endl;
    return *this;
  }
  
  
  //assignment from usint Note this is not the standard mathematical approach
  /**
   * @param &&rhs is the ubint value to assign to the zeroth entry
   * @return resulting ubintvec
   */

  const mubintvec& operator=(const ubint_el_t &val) {
    //todo this is the way that yuri and kurt want it?
    this->m_data[0] = val;
    for (size_t i = 1; i < this->m_data.size(); ++i) {
      this->m_data[i] = 0;
    }
    //      m_modulus=0;
    // m_modulus_state = GARBAGE;

    //std::cout<<"inline operator=ubint "<<val.ToString()<<std::endl;
    return *this;
  }


  /**
   * Destructor.
   */
  virtual ~mubintvec();

  //ACCESSORS

    /**
       * ostream output << operator.
       *
       * @param os is the std ostream object.
       * @param ptr_obj is mubintvec to be printed.
       * @return is the ostream object.
       */
  friend std::ostream& operator<<(std::ostream& os,
				  const mubintvec &ptr_obj)
  {
    os<<std::endl;
    for(usint i=0;i<ptr_obj.m_data.size();i++){
      os<<ptr_obj.m_data[i] <<std::endl;
    }

    os<<"modulus: "<<ptr_obj.m_modulus;
    os <<std::endl;

    return os;
  }

  void PrintValues() const { std::cout << *this; }

  /**
   * checks the vector modulus state.
   * always returns true
   */
  bool isModulusSet(void) const { return true;};


  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const usint& value);

  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const ubint_el_t& value);

  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const std::string& value);

  /**
   * Sets the vector modulus to the same as another mubintvec
   *
   * @param value is the vector whose modulus to use.
   */
  void SetModulus(const mubintvec& value);

  
  /**
   * Sets the vector modulus and changes the values to match the new modulus.
   *
   * @param value is the value to set.
   */
  void SwitchModulus(const ubint_el_t& value);

  /**
   * Gets the vector modulus.
   *
   * @return the vector modulus.
   */
  const ubint_el_t& GetModulus() const;

  //METHODS

  /**
   * returns the vector modulus with respect to the input value.
   *
   * @param modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   * side effect it resets the vector modulus to modulus
   */
  mubintvec Mod(const ubint_el_t& modulus) const;

    /**
   * vector scalar %=
   *
   * @param &modulus is the new modulus value
   * @return is the result of the mod operation.
   */
  const mubintvec& operator%=(const ubint_el_t& modulus);

  /**
   * Perform a modulus by 2 operation.  Returns the least significant bit.
   *
   * @return a new vector which is the return value of the modulus by 2, also the least significant bit.
   */
  mubintvec ModByTwo() const;

  //scalar operations

  /**
   * Scalar modulus addition at a particular index.
   *
   * @param &b is the scalar to add.
   * @param i is the index of the entry to add.
   * @return is the result of the modulus addition operation.
   */
  mubintvec ModAddAtIndex(usint i, const ubint_el_t &b) const;

  /**
   * Scalar addition.
   *
   * @param &b is the scalar to modulo add at all locations.
   * @return is the result of the addition operation.
   */
  mubintvec Add(const ubint_el_t &b) const;  
  mubintvec ModAdd(const ubint_el_t &b) const;		//Add() is the same as ModAdd()


      /**
       * scalar +=
       *
       * @param &b is the ubint scalar  to add to lhs
       * @return is the result of the addition operation.
       */
      const mubintvec& operator+=(const ubint_el_t &b);

  /**
   * Scalar subtraction.
   *
   * @param &b is the scalar to modulo subtract from all locations.
   * @return is the result of the subtraction operation.
   */
  mubintvec Sub(const ubint_el_t &b) const;
  mubintvec ModSub(const ubint_el_t &b) const;  //Sub() is the same as ModSub()
      /**
       * scalar -=
       *
       * @param &b is the ubint scalar  to subtract from lhs
       * @return is the result of the subtraction operation.
       */
      const mubintvec& operator-=(const ubint_el_t &b);

  /**
   * Scalar multiplication.
   *
   * @param &b is the scalar to modulo multiply at all locations.
   * @return is the result of the multiplication operation.
   */
  mubintvec Mul(const ubint_el_t &b) const;
  mubintvec ModMul(const ubint_el_t &b) const;//Mul() is the same as ModMul()

      /**
       * scalar *=
       *
       * @param &b is the ubint scalar to multiply by lhs
       * @return is the result of the multiplication operation.
       */
      const mubintvec& operator*=(const ubint_el_t &b);


  /**
   * Scalar exponentiation.
   *
   * @param &b is the scalar to modulo exponentiate at all locations.
   * @return is the result of the exponentiation operation.
   */
  mubintvec Exp(const ubint_el_t &b) const;
  mubintvec ModExp(const ubint_el_t &b) const;


  /**
   * Modulus inverse.
   *
   * @return a new vector which is the result of the modulus inverse operation.
   */
  mubintvec ModInverse() const;
  

  //vector operations

  //component-wise addition
  /**
   * vector addition.
   *
   * @param &b is the vector to add at all locations.
   * @return is the result of the addition operation.
   */
  mubintvec Add(const mubintvec  &b) const;
  mubintvec ModAdd(const mubintvec &b) const;

  /**
   * vector +=
   *
   * @param &b is the vector to modadd to lhs
   * @return is the result of the addition operation.
   */
  const mubintvec& operator+=(const mubintvec &b);

  //component-wise subtraction

  /**
   * Vector subtraction.
   *
   * @param &b is the vector to subtract from lhs
   * @return is the result of the subtraction operation.
   */
  mubintvec Sub(const mubintvec &b) const;
  mubintvec ModSub(const mubintvec &b) const;

  /**
  * Multiply and Rounding operation on a big integer x. Returns [x*p/q] where [] is the rounding operation.
  *
  * @param p is the numerator to be multiplied.
  * @param q is the denominator to be divided.
  * @return the result of multiply and round.
  */
  mubintvec MultiplyAndRound(const ubint_el_t &p, const ubint_el_t &q) const;

  /**
  * Divide and Rounding operation on a big integer x. Returns [x/q] where [] is the rounding operation.
  *
  * @param q is the denominator to be divided.
  * @return the result of divide and round.
  */
  mubintvec DivideAndRound(const ubint_el_t &q) const;

  /**
   * vector -=
   *
   * @param &b is the vector to mod subtract from lhs
   * @return is the result of the addition operation.
   */
  const mubintvec& operator-=(const mubintvec &b);

  //component-wise multiplication

  /**
   * Vector multiplication.
   *
   * @param &b is the vector to multiply.
   * @return is the result of the multiplication operation.
   */
  mubintvec Mul(const mubintvec &b) const;
  mubintvec ModMul(const mubintvec &b) const;

  /**
   * vector *=
   *
   * @param &b is the vector to add to lhs
   * @return is the result of the multiplication operation.
   */
  const mubintvec& operator*=(const mubintvec &b);
  

  /**
   * Returns a vector of digit at a specific index for all entries
   * for a given number base.
   * TODO: rename this better... what is a digit?
   * TODO: does this fail for some values of base?
   * @param index is the index to return the digit from in all entries.
   * @param base is the base to use for the operation.
   * @return is the resulting vector.
   */
  
  mubintvec GetDigitAtIndexForBase(usint index, usint base) const;
  
  // auxiliary functions

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
  ubint_el_t m_modulus;
  enum State {
    INITIALIZED, GARBAGE
  };
  //enum to store the state of the
  State m_modulus_state;

};

template<typename ubint_el_t>
inline mubintvec<ubint_el_t> operator-(const mubintvec<ubint_el_t> &a) {
 return mubintvec<ubint_el_t>(0) - a; }

//BINARY OPERATORS
  /**
   *   scalar modulo
   *
   * @param &a is the input vector to modulo.
   * @param &modulus is the input bint modulus
   * @return is the result of the modulo operation.
   * as a side effect, sets the modulus of the mubintvec to modulo
   */
  template<class ubint_el_t>
  inline mubintvec<ubint_el_t> operator%(const mubintvec<ubint_el_t> &a,
      const ubint_el_t &modulo) {
    return a.Mod(modulo);
  }


/**
 *   scalar modulo addition.
 *
 * @param &a is the input vector to add.
 * @param &b is the input bint to add.
 * @return is the result of the modulo addition operation.
 */
template<class ubint_el_t>
inline mubintvec<ubint_el_t> operator+(const mubintvec<ubint_el_t> &a,
    const ubint_el_t &b) {
  return a.ModAdd(b);
}

/**
 *   scalar modulo subtraction
 *
 * @param &a is the input vector to subtract.
 * @param &b is the input bint to subtract.
 * @return is the result of the modulo subtraction operation.
  */
template<class ubint_el_t>
inline mubintvec<ubint_el_t> operator-(const mubintvec<ubint_el_t> &a,
    const ubint_el_t &b) {
  return a.ModSub(b);
}

/**
 *  scalar modulo multiplication.
 *
 * @param &a is the input vector to multiply.
 * @param &i is the input integer to multiply.
 * @return is the result of the modulo multiplication operation.
 */
template<class ubint_el_t>
inline mubintvec<ubint_el_t> operator*(const mubintvec<ubint_el_t> &a,
    const ubint_el_t &b) {
  return a.ModMul(b);
}

/**
 *  vector modulo addition.
 *
 * @param &a is the first input vector to add.
 * @param &b is the second input vector to add.
 * @return is the result of the modulo addition operation.
 
 */
template<class ubint_el_t>
inline mubintvec<ubint_el_t> operator+(const mubintvec<ubint_el_t> &a,
    const mubintvec<ubint_el_t> &b) {
  return a.ModAdd(b);
}

/**
 *  vector subtraction.
 *
 * @param &a is the first input vector to subtract.
 * @param &b is the second input vector to subtract.
 * @return is the result of the subtraction operation.
 */
template<class ubint_el_t>
inline mubintvec<ubint_el_t> operator-(const mubintvec<ubint_el_t> &a,
    const mubintvec<ubint_el_t> &b) {
  return a.ModSub(b);
}

/**
 *  vector multiplication.
 *
 * @param &a is the first input vector to multiply.
 * @param &b is the second input vector to multiply.
 * @return is the result of the multiplication operation.
 */
template<class ubint_el_t>
inline mubintvec<ubint_el_t> operator*(const mubintvec<ubint_el_t> &a,
    const mubintvec<ubint_el_t> &b) {
  return a.ModMul(b);
}

} // namespace lbcrypto ends

#endif // LBCRYPTO_MATH_EXPINT_MUBINTVEC_H
