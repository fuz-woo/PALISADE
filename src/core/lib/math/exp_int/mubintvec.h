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

#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include <initializer_list>
#include "mubintvec.h"
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
class mubintvec: public lbcrypto::BigVectorInterface<mubintvec<ubint_el_t>,ubint_el_t>, public lbcrypto::Serializable
{
public:
  /**
   * Basic constructor.
   */
  explicit mubintvec();

  static mubintvec Single(const ubint_el_t& val, const ubint_el_t&modulus) {
    mubintvec vec(1);
    vec.m_data[0] = val;
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
   * @param &&rhs is the list of usints to be assigned to the mubintvec.
   * @return mubintvec object 
   * note if  modulus is set then mod(input) is stored
   * note modulus remains unchanged.
   */

  const mubintvec& operator=(std::initializer_list<uint64_t> rhs);

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
   * @param &&rhs is the usint value to assign to the zeroth entry
   * @return resulting mubintvec
   * note that modulus remains untouched.
   */
  
  //assignment from uint64_t
  const mubintvec& operator=(uint64_t val) {
    this->m_data[0] = val;
    for (size_t i = 1; i < GetLength(); ++i) {
      this->m_data[i] = 0;
    }
    return *this;
  }
  
  
  //assignment from usint Note this is not the standard mathematical approach
  /**
   * @param &&rhs is the ubint value to assign to the zeroth entry
   * @return resulting mubintvec
   */

  const mubintvec& operator=(const ubint_el_t &val) {
    this->m_data[0] = val;
    for (size_t i = 1; i < this->m_data.size(); ++i) {
      this->m_data[i] = 0;
    }
    return *this;
  }


  /**
   * Destructor.
   */
  virtual ~mubintvec();

  size_t GetLength() const { return m_data.size(); }

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
   * write to index with bounds check and with MOD
   * @param index is the index to write to
   * @param value is value to write, using vector's mod
   * @return is the value at the index.
   */
  
  void atMod(size_t index, const ubint_el_t &value);
  void atMod(size_t index, const std::string &valstr);

  ubint_el_t& at(size_t i) {
	  if(!this->IndexCheck(i)) {
		  throw std::logic_error("index out of range");
	  }
	  return this->m_data[i];
  }

  const ubint_el_t& at(size_t i) const {
	  if(!this->IndexCheck(i)) {
		  throw std::logic_error("index out of range");
	  }
	  return this->m_data[i];
  }

  ubint_el_t& operator[](size_t i) {
	  return this->m_data[i];
  }
  
  const ubint_el_t& operator[](size_t i) const {
	  return this->m_data[i];
  }

  /**
   * returns the vector modulus with respect to the input value.
   *
   * @param modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   * side effect it resets the vector modulus to modulus
   */
  mubintvec Mod(const ubint_el_t& modulus) const;
  const mubintvec& ModEq(const ubint_el_t& modulus);

  /**
   * Perform a modulus by 2 operation.  Returns the least significant bit.
   *
   * @return a new vector which is the return value of the modulus by 2, also the least significant bit.
   */
  mubintvec ModByTwo() const;
  const mubintvec& ModByTwoEq();

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
  mubintvec ModAdd(const ubint_el_t &b) const;
  const mubintvec& ModAddEq(const ubint_el_t& b);

  /**
   * Scalar subtraction.
   *
   * @param &b is the scalar to modulo subtract from all locations.
   * @return is the result of the subtraction operation.
   */
  mubintvec ModSub(const ubint_el_t &b) const;
  const mubintvec& ModSubEq(const ubint_el_t &b);

  /**
   * Scalar multiplication.
   *
   * @param &b is the scalar to modulo multiply at all locations.
   * @return is the result of the multiplication operation.
   */
  mubintvec ModMul(const ubint_el_t &b) const;
  const mubintvec& ModMulEq(const ubint_el_t &b);

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
  mubintvec ModAdd(const mubintvec &b) const;
  const mubintvec& ModAddEq(const mubintvec &b);

  //component-wise subtraction

  /**
   * Vector subtraction.
   *
   * @param &b is the vector to subtract from lhs
   * @return is the result of the subtraction operation.
   */
  mubintvec ModSub(const mubintvec &b) const;
  const mubintvec& ModSubEq(const mubintvec &b);

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

  //component-wise multiplication

  /**
   * Vector multiplication.
   *
   * @param &b is the vector to multiply.
   * @return is the result of the multiplication operation.
   */
  mubintvec ModMul(const mubintvec &b) const;
  const mubintvec& ModMulEq(const mubintvec &b);

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

  std::vector<ubint_el_t> m_data;

	bool IndexCheck(size_t length) const {
		if(length > m_data.size())
			return false;
		return true;
	}

};

} // namespace lbcrypto ends

#endif // LBCRYPTO_MATH_EXPINT_MUBINTVEC_H
