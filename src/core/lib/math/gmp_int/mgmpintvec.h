/**
 * @file mgmpintvec.h This file contains mgmpintvec, a <vector> of gmpint, with associated
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
 * This file contains mgmpintvec, a <vector> of gmpint, with associated
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

template<typename myT>
class myVecP : public NTL::Vec<myT>, public lbcrypto::BigVectorInterface<myVecP<myT>,myT>, public lbcrypto::Serializable {

public:

	myVecP(): Vec<myT>() {m_modulus_state = GARBAGE;}

	//constructors without moduli
	explicit myVecP(const size_t length): Vec<myT>(INIT_SIZE, length) {m_modulus_state = GARBAGE;}
	myVecP(INIT_SIZE_TYPE, const long length): Vec<myT>(INIT_SIZE, length) {m_modulus_state = GARBAGE;}


	//copy
	// copy ctors with vector inputs
	explicit myVecP(const myVecP<myT> &a);

	//movecopy
	myVecP(myVecP<myT> &&a);

	//constructors with moduli
	//ctor myT moduli
	myVecP(const long n, const myT &q);

	//constructors with moduli and initializer lists
	myVecP(const long n, const myT &q, std::initializer_list<uint64_t> rhs);
	myVecP(const long n, const myT &q, std::initializer_list<std::string> rhs);

	//copy with myT moduli
	myVecP(const myVecP<myT> &a, const myT &q);

	//ctor with char * moduli
	myVecP(size_t n, const std::string &sq);

	//copy with char * moduli
	myVecP(const myVecP<myT> &a, const std::string &sq);

	//ctor with uint64_t moduli
	myVecP(size_t n, uint64_t q);

	//copy with uint64_t moduli
	myVecP(const myVecP<myT> &a, const uint64_t q);

	//destructor
	~myVecP() {}

	/**
	* ostream operator to output vector values to console
	*
	* @param os is the std ostream object.
	* @param &ptr_obj is the BigVectorImpl object to be printed.
	* @return std ostream object which captures the vector values.
	*/
	friend std::ostream& operator<<(std::ostream& os, const myVecP<myT> &ptr_obj) {
		auto len = ptr_obj.GetLength();
		os<<"[";
		for(size_t i=0; i < len; i++) {
			os<< ptr_obj.at(i);
			os << ((i == (len-1))?"]":" ");
		}
		return os;
	}

	//adapters
	myVecP(std::vector<std::string>& s); //without modulus

	myVecP(std::vector<std::string>& s, const myT &q); // with modulus
	myVecP(std::vector<std::string>& s, const char *sq); // with modulus
	myVecP(std::vector<std::string>& s, const uint64_t q); // with modulusu

	const myVecP& operator=(const myVecP &a);
	const myVecP& operator=(myVecP &&a);


	const myVecP& operator=(std::initializer_list<uint64_t> rhs);
	const myVecP& operator=(std::initializer_list<int32_t> rhs);
	const myVecP& operator=(std::initializer_list<std::string> rhs);
	const myVecP& operator=(uint64_t rhs);

	void clear(myVecP& x); //why isn't this inhereted?

	// NOTE the underlying Vec does not have a no-bounds-checking operator[]
	myT& at(size_t i) {
		return this->NTL::Vec<myT>::at(i);
	}

	const myT& at(size_t i) const {
		return this->NTL::Vec<myT>::at(i);
	}

	// the following are like writing to this->at(i) but with modulus implied.
	void atMod(size_t index, const myT&value) {
		// must be set modulo
		if (isModulusSet())
			this->at(index) = value%m_modulus;
		else //must be set directly
			this->at(index) = value;
	}

	void atMod(size_t index, const std::string& str){
		// must be set modulo
		if (isModulusSet())
			this->at(index) = myT(str)%m_modulus;
		else //must be set directly
			this->at(index) = myT(str);
	}

	/**
	* operators to get a value at an index.
	* @param idx is the index to get a value at.
	* @return is the value at the index.
	*/
	myT& operator[](size_t idx) { return this->at(idx); }
	const myT& operator[](size_t idx) const { return this->at(idx); }

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

	static inline myVecP Single(const myT& val, const myT &modulus) {
		bool dbg_flag = false;
		DEBUG("single in");
		myVecP vec(1);
		DEBUG("a");
		vec.SetModulus(modulus);
		DEBUG("b");
		vec[0] = val;
		DEBUG("single out");
		return vec;
	};

	//comparison.

	//arithmetic
	//scalar modulus

	myVecP Mod(const myT& b) const;
	const myVecP& ModEq(const myT& b);

	myVecP ModByTwo() const;
	const myVecP& ModByTwoEq();

	void SwitchModulus(const myT& newModulus);

	myVecP ModAdd(const myT& b) const {
		ModulusCheck("Warning: myVecP::ModAdd");
		myVecP ans(*this);
		ans.ModAddEq(b);
		return ans;
	}

	const myVecP& ModAddEq(const myT& b) {
		ModulusCheck("Warning: myVecP::ModAdd");
		for(usint i=0;i<this->GetLength();i++){
			this->operator[](i).ModAddEq(b, this->m_modulus);
		}
		return *this;
	}

	void modadd_p(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural version

	myVecP ModAddAtIndex(size_t i, const myT &b) const;

	myVecP ModAdd(const myVecP& b) const {
		ArgCheckVector(b, "myVecP ModAdd()");
		myVecP ans(*this);
		ans.ModAddEq(b);
		return ans;
	}

	const myVecP& ModAddEq(const myVecP& b) {
		ArgCheckVector(b, "myVecP ModAddEq()");
		for(usint i=0;i<this->GetLength();i++){
			this->operator[](i).ModAddEq(b[i], this->m_modulus);
		}
		return *this;
	}

	//scalar
	myVecP ModSub(const myT& b) const {
		ModulusCheck("Warning: myVecP::ModSub");
		myVecP ans(*this);
		ans.ModSubEq(b);
		return ans;
	}

	const myVecP& ModSubEq(const myT& b) {
		ModulusCheck("Warning: myVecP::ModSubEq");
		for(usint i=0;i<this->GetLength();i++){
			this->operator[](i).ModSubEq(b, this->m_modulus);
		}
		return (*this);
	}

	//vector
	myVecP ModSub(const myVecP& b) const {
		ArgCheckVector(b, "myVecP ModSub()");
		myVecP ans(*this);
		ans.ModSubEq(b);
		return ans;
	}

	const myVecP& ModSubEq(const myVecP& b) {
		ArgCheckVector(b, "myVecP ModSubEq()");
		for(usint i=0;i<this->GetLength();i++){
			this->operator[](i).ModSubEq(b[i], this->m_modulus);
		}
		return (*this);
	}

	//procecural
	void modsub_p(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

	//scalar
	myVecP ModMul(const myT& b) const {
		ModulusCheck("Warning: myVecP::ModMul");
		myVecP ans(*this);
		ans.ModMulEq(b);
		return ans;
	}

	const myVecP& ModMulEq(const myT& b) {
		ModulusCheck("Warning: myVecP::ModMul");
		for(usint i=0;i<this->GetLength();i++){
			this->operator[](i).ModMulEq(b, this->m_modulus);
		}
		return (*this);
	}

	//vector
	myVecP ModMul(const myVecP& b) const {
		ArgCheckVector(b, "myVecP Mul()");
		myVecP ans(*this);
		ans.ModMulEq(b);
		return ans;
	}

	const myVecP& ModMulEq(const myVecP& b) {
		ArgCheckVector(b, "myVecP Mul()");
		for(usint i=0;i<this->GetLength();i++){
			this->operator[](i).ModMulEq(b[i], this->m_modulus);
		}
		return (*this);
	}

	void modmul_p(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

	/**
	 * Scalar exponentiation.
	 *
	 * @param &b is the scalar to modulo exponentiate at all locations.
	 * @return is the result of the exponentiation operation.
	 */
	myVecP Exp(const myT &b) const;
	myVecP ModExp(const myT &b) const;

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
		this->m_modulus= myT(value);
		this->m_modulus_state = INITIALIZED;
		DEBUG("this->modulus = "<<this->m_modulus);
		// ZZ_p::init(this->m_modulus);
		//this->Renormalize();
	};

	//sets modulus and the NTL init function myT argument
	void SetModulus(const myT& value){
		bool dbg_flag = false;
		DEBUG("SetModulus(const myT& "<<value<<")");
		if (value == myT(0)) {
			PALISADE_THROW( lbcrypto::palisade_error, "SetModulus(myT) cannot be zero");
		}
		this->m_modulus= value;
		DEBUG("this->modulus = "<<this->m_modulus);
		this->m_modulus_state = INITIALIZED;
	}

	//sets modulus and the NTL init function string argument
	inline void SetModulus(const std::string& value){
		bool dbg_flag = false;
		DEBUG("SetModulus(const string& "<<value<<")");
		this->m_modulus = myT(value);
		if (this->m_modulus == myT(0)) {
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
		if (this->m_modulus == myT(0)) {
			PALISADE_THROW( lbcrypto::palisade_error, "SetModulus(myVecP) cannot be zero");
		}
		this->m_modulus_state = INITIALIZED;
		DEBUG("this->modulus = "<<this->m_modulus);
		//ZZ_p::init(this->m_modulus);
		//this->Renormalize();
	};

	const myT& GetModulus() const {
		if (this->isModulusSet()){
			return (this->m_modulus);
		}else{
			PALISADE_THROW(lbcrypto::config_error, "modulus not set");
		}
	}

	inline int CopyModulus(const myVecP& rhs){
		bool dbg_flag = false;
		DEBUG("CopyModulus(const myVecP& modulus is "<<rhs.m_modulus);
		DEBUG("CopyModulus(const myVecP& modulus_state is "<<rhs.m_modulus_state);
		this->m_modulus = rhs.m_modulus;
		this->m_modulus_state = rhs.m_modulus_state;
		if (isModulusSet()){
			return (0);
		} else{
			this->m_modulus_state = GARBAGE;
			return (-1);
		}
	}

	size_t GetLength(void) const {
		return this->length();
	}

	void resize(size_t n) {
		//resize is the STL::vector standard call for this functionality
		this->SetLength(n); //SetLength() is an NTL call
	}

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
	//use when argument to function is myT
	void ModulusCheck(std::string msg) const {
		if (!isModulusSet())
			PALISADE_THROW( lbcrypto::palisade_error, msg + " uninitialized this->modulus" );
	}

	//utility function to check argument consistency for vector vector fns
	//use when argument to function is myVecP
	void ArgCheckVector(const myVecP &b, std::string fname) const {
		if(this->m_modulus!=b.m_modulus) {
			PALISADE_THROW( lbcrypto::palisade_error, fname+" modulus vector modulus vector op of different moduli");
		}else if (!isModulusSet()) {
			PALISADE_THROW( lbcrypto::palisade_error, fname+" modulus vector modulus vector op GARBAGE  moduli");
		}else if(this->GetLength()!=b.GetLength()){
			PALISADE_THROW( lbcrypto::palisade_error,  fname+" vectors of different lengths");
		}
	}

	//used to make sure all entries in this are <=current modulus
	void Renormalize(void) {
		bool dbg_flag = false;
		DEBUG("mgmpintvec Renormalize modulus"<<m_modulus);
		DEBUG("mgmpintvec size"<< this->GetLength());
		//loop over each entry and fail if !=
		for (size_t i = 0; i < this->GetLength(); ++i) {
			(*this)[i] %=m_modulus;
			DEBUG("this ["<<i<<"] now "<< (*this)[i]);
		}
	}

	myT m_modulus;
	//TODO: BE 2 has gotten rid of this, we may too.
	enum ModulusState {
		GARBAGE,INITIALIZED //note different order, Garbage is the default state
	};
	//enum to store the state of the
	ModulusState m_modulus_state;

protected:
	bool IndexCheck(size_t index) const {
		if(index >= this->GetLength())
			return false;
		return true;
	}

}; //template class ends



} // namespace NTL ends

#endif // LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H

