/**
 * @file ubint.cpp  This file contains the main class for unsigned big integers: ubint. Big
 * integers are represented as arrays of machine native unsigned integers. The
 * native integer type is supplied as a template parameter.  Currently
 * implementation based on uint32_t and uint64_t is
 * supported. a native double the base integer size is also needed.
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

#define _SECURE_SCL 0 // to speed up VS
#include "../backend.h"

#include <iostream>
#include <fstream>
#include "time.h"
#include <chrono>

#include "../../utils/debug.h"

#define LimbReserveHint 4  // hint for reservation of limbs

namespace exp_int {

//MOST REQUIRED STATIC CONSTANTS INITIALIZATION

//constant static member variable initialization of m_uintBitLength which is equal to number of bits in the unit data type
//permitted values: 8,16,32
template<typename limb_t>
//const uschar ubint<limb_t>::m_uintBitLength = UIntBitWidth<limb_t>::value;
const usint ubint<limb_t>::m_limbBitLength = sizeof(limb_t)*8;

//constant static member variable initialization of m_logUintBitLength which is equal to log of number of bits in the unit data type
//permitted values: 3,4,5
template<typename limb_t>
//const uschar ubint<limb_t>::m_log2LimbBitLength = LogDtype<limb_t>::value;
const usint ubint<limb_t>::m_log2LimbBitLength = Log2<m_limbBitLength>::value;

//constant static member variable initialization of m_uintMax which is maximum value of unit data type
template<typename limb_t>
const limb_t ubint<limb_t>::m_MaxLimb = std::numeric_limits<limb_t>::max();

//optimized ceiling function after division by number of bits in the limb data type.
template<typename limb_t>
usint ubint<limb_t>::ceilIntByUInt(const limb_t Number){
	//mask to perform bitwise AND
	static limb_t mask = m_limbBitLength-1;

	if(!Number)
		return 1;

	if((Number&mask)!=0)
		return (Number>>m_log2LimbBitLength)+1;
	else
		return Number>>m_log2LimbBitLength;
}

//CONSTRUCTORS
template<typename limb_t>
ubint<limb_t>::ubint()
{
	// builds a ubint that defaults to zero

	bool dbg_flag = false;		// if true then print dbg output
	DEBUG("ubint() ctor");
	// BBI bare ctor() generates a valid zero. mimic that activity
	m_MSB = 0;
	m_value.reserve(LimbReserveHint);
	m_value.push_back((limb_t)0);
	m_state = INITIALIZED;

}


template<typename limb_t>
ubint<limb_t>::ubint(const uint64_t initval){
	bool dbg_flag = false;		// if true then print dbg output
	uint64_t init = initval; //non const var
	//setting the MSB
	usint msb = 0;

	msb = lbcrypto::GetMSB64(init);
	DEBUG("ctor(uint64_t:"<<init<<")");
	DEBUG( "msb " <<msb);
	DEBUG( "maxlimb "<<m_MaxLimb);

	DEBUG( "initial size "<< m_value.size());

	if (init <= m_MaxLimb) {
		//init fits in first limb entry
		m_value.push_back((limb_t)init);
		DEBUG("single limb size now "<<m_value.size());
	}
#ifdef UBINT_32 //does not occur for UBINT_64
	else {
		usint ceilInt = ceilIntByUInt(msb);
		DEBUG("mulit limb ceilIntByUInt ="<<ceilInt);
		//setting the values of the array
		this->m_value.reserve(ceilInt);
		for(usint i= 0;i<ceilInt;++i){
			DEBUG("i " << i);
			m_value.push_back((limb_t)init);
			init>>=m_limbBitLength;
			DEBUG("init now  " << init);
		}

	}
#endif
	this->m_MSB = msb;
	m_state = INITIALIZED;

	DEBUG("final msb ="<<msb);

}

// ctor(string)
template<typename limb_t>
ubint<limb_t>::ubint(const std::string& str){
	bool dbg_flag = false;		// if true then print dbg output

	DEBUG("ctor(str "<<str<<")");
	//memory allocation step
	//m_value = new limb_t[m_nSize]; //todosmartpointer
	//setting the array values from the string

	AssignVal(str);
	//state set
	m_state = INITIALIZED;
	DEBUG("final msb ="<<this->m_MSB);
}

//copy constructor
template<typename limb_t>
ubint<limb_t>::ubint(const ubint& rhs){
	bool dbg_flag = false;		// if true then print dbg output
	if (rhs.m_state == GARBAGE)
		std::cout<<"copy garbage"<<std::endl;

	if (rhs.m_value.size()<0)
		std::cout<<"copy size<0"<<std::endl;

	DEBUG("copy ctor(&bint)");

	//memory allocation step
	this->m_MSB=rhs.m_MSB; //copy MSB
	//copy values
	this->m_value = rhs.m_value; // this occasionally fails may have been

	//set state
	m_state = rhs.m_state;
	DEBUG("final msb ="<<this->m_MSB);
}

//move copy cconstructor
template<typename limb_t>
ubint<limb_t>::ubint(ubint &&rhs){
	bool dbg_flag = false;		// if true then print dbg output
	DEBUG("move copy ctor(&bint)");

	//copy MSB
	m_MSB = rhs.m_MSB;

	//swap (move) assignment
	m_value.swap(rhs.m_value);

	//set state
	m_state = rhs.m_state;
}

//this is the zero allocator for the palisade matrix class
template<typename limb_t>
unique_ptr<ubint<limb_t>> ubint<limb_t>::Allocator() {
	return lbcrypto::make_unique<exp_int::ubint<limb_t>>();
};

template<typename limb_t>
ubint<limb_t>::~ubint()
{
	bool dbg_flag = false;		// if true then print dbg output

	DEBUG("dtor() m_value.size is "<<m_value.size());
	//vector is cleaned up by stl when it goes out of scope
	DEBUG("leaving dtor");
}

/**
 *Converts the ubint to a usint unsigned integer or returns the first
 *m_limbBitLength bits of the ubint.  Splits the ubint into bit length of uint data
 *type and then uses shift and add to form the  unsigned
 *integer.
 */
template<typename limb_t>
usint ubint<limb_t>::ConvertToUsint() const{
	usint result = 0;
	if (m_value.size()==0)
		throw std::logic_error("ConvertToUsint() on uninitialized bint");
	if (sizeof(limb_t)>=sizeof(usint)){
		result = m_value[0];
	} else {
		//Case where limb_t is less bits than output size
		//add number of limbs needed to make output
		size_t msbTest = sizeof(usint)*8;
		if (msbTest > m_MSB)
			msbTest = m_MSB;
		usint ceilInt = ceilIntByUInt(msbTest);
		//copy the values by shift and add
		for (usint i = 0; i < ceilInt; i++){
			usint tmp = this->m_value[i];
			tmp <<= (m_limbBitLength*i);
			result += tmp;
		}
	}
	return result;
}

template<typename limb_t>
uint64_t ubint<limb_t>::ConvertToInt() const{  //todo: deprecate this to Usint
	return this->ConvertToUint64();
}


//Converts the ubint to uint32_t using the std library functions.
template<typename limb_t>
uint32_t ubint<limb_t>::ConvertToUint32() const{
	uint32_t result = 0;
	if (m_value.size()==0)
		throw std::logic_error("ConvertToUint32() on uninitialized bint");

	if (sizeof(limb_t)>=sizeof(uint32_t)){
		result = (uint32_t)m_value[0];
	} else {
		//Case where limb_t is less bits than uint32_t
		size_t msbTest = sizeof(uint32_t)*8;
		if (msbTest > m_MSB)
			msbTest = m_MSB;
		usint ceilInt = ceilIntByUInt(msbTest);
		//copy the values by shift and add
		for (usint i = 0; i < ceilInt; i++){
			uint32_t tmp = this->m_value[i];
			tmp  <<= (m_limbBitLength*i);
			result += tmp;
		}
	}
	return result;
}

//Converts the ubint to uint64_t using the std library functions.
template<typename limb_t>
uint64_t ubint<limb_t>::ConvertToUint64() const{
	bool dbg_flag = false;		// if true then print dbg output
	uint64_t result = 0;
	if (m_value.size()==0)
		throw std::logic_error("ConvertToUint64() on uninitialized bint");
	if (sizeof(limb_t)>=sizeof(uint64_t)){
		DEBUG("mvalue0 " << m_value[0]);
		result = m_value[0];
		DEBUG("result1 " << result);
		result = (uint64_t)m_value[0];
		DEBUG("result2 " << result);
	} else {
		//Case where limb_t is less bits than uint64_t
		size_t msbTest = sizeof(uint64_t)*8;
		if (msbTest > m_MSB)
			msbTest = m_MSB;
		usint ceilInt = ceilIntByUInt(msbTest);
		DEBUG("msbTest " << msbTest);
		DEBUG("ceilint " << ceilInt);
		//copy the values by shift and add
		for (usint i = 0; i < ceilInt; i++){
			DEBUG("i "<< i << "v " << this->m_value[i]);
			DEBUG("shift "<< (m_limbBitLength*i));
			DEBUG("preresult " << result);
			uint64_t tmp  = this->m_value[i];
			tmp <<= (m_limbBitLength*i);
			result += tmp;
			DEBUG("postresult " << result);
		}
	}
	return result;
}


// the following conversions all throw
//Converts the ubint to float using the std library functions.
template<typename limb_t>
float ubint<limb_t>::ConvertToFloat() const{
	if (m_value.size()==0)
		throw std::logic_error("ConvertToFloat() on uninitialized bint");
	float ans;
	try {
		ans = std::stof(this->ToString());
	} catch (const std::exception& e) {
		throw std::logic_error("ConvertToFloat() parse error converting to float");
		ans = -1.0; //TODO: this signifies an error...
	}
	return ans;
}

//Converts the ubint to double using the std library functions.
template<typename limb_t>
double ubint<limb_t>::ConvertToDouble() const{
	if (m_value.size()==0)
		throw std::logic_error("ConvertToDouble() on uninitialized bint");
	double ans;
	try {
		ans = std::stod(this->ToString());
	} catch (const std::exception& e) {
		throw std::logic_error("ConvertToDouble() parse error converting to double");
		ans = -1.0;
	}
	return ans;
}

//Converts the ubint to long double using the std library functions.
template<typename limb_t>
long double ubint<limb_t>::ConvertToLongDouble() const{
	if (m_value.size()==0)
		throw std::logic_error("ConvertToLongDouble() on uninitialized bint");
	long double ans;
	try {
		ans = std::stold(this->ToString());
	} catch (const std::exception& e) {
		throw std::logic_error("ConvertToLongDouble() parse error converting to long double");
		ans = -1.0;
	}
	return ans;

}

//copy allocator
template<typename limb_t>
const ubint<limb_t>&  ubint<limb_t>::operator=(const ubint &rhs){
	if(this!=&rhs){
		this->m_MSB = rhs.m_MSB;
		this->m_state = rhs.m_state;
		this->m_value = rhs.m_value;
	}
	return *this;
}

/**
 *	Left Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *	Shifting is done by the shifting the limb type numbers.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over prop.
 */
template<typename limb_t>
ubint<limb_t>  ubint<limb_t>::LShift(usshort shift) const{
	bool dbg_flag = false;
	//garbage check
	if(m_state==State::GARBAGE)
		throw std::logic_error("<< on uninitialized bint");
	//trivial case
	if(this->m_MSB==0)
		return ubint(0);

	ubint ans(*this);

	//compute the number of whole limb shifts
	usint shiftByLimb = shift>>m_log2LimbBitLength;
	//ans.m_value.reserve(shiftByLimb+this->m_value.size());

	//compute the remaining number of bits to shift
	limb_t remainingShift = (shift&(m_limbBitLength-1));

	DEBUG("l2lbl "<< m_log2LimbBitLength);
	DEBUG("totalshift "<< shift);
	DEBUG("shiftByLimb "<<shiftByLimb);
	DEBUG("remainingShift "<<remainingShift);
	DEBUG("size "<<m_value.size());

	//first shift by the # remainingShift bits
	if(remainingShift!=0){
		limb_t oFlow = 0;
		Dlimb_t temp = 0;
		size_t i;

		DEBUG("m_MSB "<<m_MSB);
		DEBUG("ilimit "<<ceilIntByUInt(m_MSB));


		for(i=0; i<ceilIntByUInt(m_MSB); ++i){
			DEBUG("bit shift ");
			temp = ans.m_value[i];
			temp <<=remainingShift;
			ans.m_value[i] = (limb_t)temp + oFlow;
			oFlow = temp >> m_limbBitLength;
		}

		if(oFlow) {//there is an overflow set of bits.
			if (i<ans.m_value.size()){
				ans.m_value[i] = oFlow;
			} else {
				ans.m_value.push_back(oFlow);
			}
		}
		ans.m_MSB += remainingShift;

	}

	if(shiftByLimb!=0){
		usint currentSize = ans.m_value.size();
		DEBUG("CURRENT SIZE "<<currentSize);
		ans.m_value.resize(currentSize+shiftByLimb); // allocate more storage
		DEBUG("resize is  "<<ans.m_value.size());
		for (int i = currentSize-1; i>=0; i-- ) {  //shift limbs required # of indicies
			DEBUG("to : "<<i+shiftByLimb<< "from "<<i );
			ans.m_value[i+shiftByLimb] = ans.m_value[i];
		}
		//zero out the 'shifted in' limbs
		for (int i = shiftByLimb -1 ; i>=0; i-- ) {
			DEBUG("clear : "<<i);
			ans.m_value[i] = 0;
		}
		DEBUG("new size is  "<<ans.m_value.size());

	}

	ans.m_MSB += shiftByLimb*m_limbBitLength;
	DEBUG("final MSB "<<ans.m_MSB);
	//ans.SetMSB();
	//DEBUG("final MSB check "<<ans.m_MSB);
	return ans;

}

/**
 *	Left Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *	Shifting is done by the shifting the limb type numbers.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over prop.
 */
template<typename limb_t>
const ubint<limb_t>&  ubint<limb_t>::LShiftEq(usshort shift) {
	bool dbg_flag = false;
	if(m_state==State::GARBAGE)
		throw std::logic_error("<<= on uninitialized bint");
	if(this->m_MSB==0) {
		return *this;
	} else {

		//compute the number of whole limb shifts
		usint shiftByLimb = shift>>m_log2LimbBitLength;

		//compute the remaining number of bits to shift
		limb_t remainingShift = (shift&(m_limbBitLength-1));

		DEBUG("l2lbl "<< m_log2LimbBitLength);
		DEBUG("totalshift "<< shift);
		DEBUG("shiftByLimb "<<shiftByLimb);
		DEBUG("remainingShift "<<remainingShift);
		DEBUG("size "<<m_value.size());

		//first shift by the # remainingShift bits
		if(remainingShift!=0){
			limb_t oFlow = 0;
			Dlimb_t temp = 0;
			size_t i;

			DEBUG("m_MSB "<<m_MSB);
			DEBUG("ilimit "<<ceilIntByUInt(m_MSB));


			for(i=0; i<ceilIntByUInt(m_MSB); ++i){
				DEBUG("bit shift ");

				//can optimize here further.
				temp = m_value[i];
				temp <<=remainingShift;
				m_value[i] = (limb_t)temp + oFlow;
				oFlow = temp >> m_limbBitLength;
			}

			if(oFlow) {//there is an overflow set of bits.
				if (i<m_value.size()){
					m_value[i] = oFlow;
				} else {
					m_value.push_back(oFlow);
				}
			}
			m_MSB += remainingShift;

		}

		if(shiftByLimb!=0){
			usint currentSize = m_value.size();
			DEBUG("CURRENT SIZE "<<currentSize);
			m_value.resize(currentSize+shiftByLimb); // allocate more storage
			DEBUG("resize is  "<<m_value.size());
			for (int i = currentSize-1; i>=0; i-- ) {  //shift limbs required # of indicies
				DEBUG("to : "<<i+shiftByLimb<< "from "<<i );
				m_value[i+shiftByLimb] = m_value[i];
			}
			//zero out the 'shifted in' limbs
			for (int i = shiftByLimb -1 ; i>=0; i-- ) {
				DEBUG("clear : "<<i);
				m_value[i] = 0;
			}
			DEBUG("new size is  "<<m_value.size());
		}

		m_MSB += shiftByLimb*m_limbBitLength;
		DEBUG("final MSB "<<m_MSB);
		//ans.SetMSB();
		//DEBUG("final MSB check "<<ans.m_MSB);
		return *this;
	}
}

/**Right Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *	Shifting is done by the shifting the limb type numbers in the array to the right.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template<typename limb_t>
ubint<limb_t>  ubint<limb_t>::RShift(usshort shift) const{
	bool dbg_flag = false;
	//garbage check
	if(m_state==State::GARBAGE)
		throw std::logic_error("Value not initialized");

	//trivial cases
	if(this->m_MSB==0 || this->m_MSB <= shift)
		return ubint(0);


	ubint ans(*this);
	//compute the number of whole limb shifts
	usint shiftByLimb = shift>>m_log2LimbBitLength;

	//compute the remaining number of bits to shift
	limb_t remainingShift = (shift&(m_limbBitLength-1));


	DEBUG("l2lbl "<< m_log2LimbBitLength);
	DEBUG("totalshift "<< shift);
	DEBUG("shiftByLimb "<<shiftByLimb);
	DEBUG("remainingShift "<<remainingShift);
	DEBUG("size "<<m_value.size());

	//first shift by the number of whole limb shifts
	if(shiftByLimb!=0){

		if (shiftByLimb >ans.m_value.size())
			DEBUG("LOGIC ERROR size is " <<ans.m_value.size());


		for(auto i =  shiftByLimb; i < ans.m_value.size(); ++i){
			DEBUG("limb shift ");
			ans.m_value[i-shiftByLimb] = ans.m_value[i];
		}
		//zero out upper  "shifted in" limbs
		for(usint i = 0; i< shiftByLimb; ++i){
			DEBUG("limb zereo");
			ans.m_value.pop_back();
		}

		//msb adjusted to show the shifts
		ans.m_MSB -= shiftByLimb<<m_log2LimbBitLength;

	}

	//remainderShift bit shifts
	if(remainingShift!=0){

		limb_t overFlow = 0;
		limb_t oldVal;
		limb_t maskVal = (1<<(remainingShift))-1;
		limb_t compShiftVal = m_limbBitLength- remainingShift;

		usint startVal = ceilIntByUInt(ans.m_MSB);
		//perform shifting by bits by calculating the overflow
		//oveflow is added after the shifting operation

		DEBUG("maskVal "<< maskVal);
		DEBUG("startVal "<< startVal);
		DEBUG("compShiftVal " << compShiftVal);

		for(int i = startVal -1 ; i>=0;i--){
			DEBUG("bit shift "<<i);
			oldVal = ans.m_value[i];
			ans.m_value[i] = (ans.m_value[i]>>remainingShift) + overFlow;

			overFlow = (oldVal &  maskVal);
			overFlow <<= compShiftVal ;
		}

		ans.m_MSB -= remainingShift;

	}

	ans.NormalizeLimbs();

	DEBUG("final MSB "<<ans.m_MSB);
	ans.SetMSB();
	DEBUG("final MSB check "<<ans.m_MSB);
	return ans;
}


/**Right Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *	Shifting is done by the shifting the limb type numbers in the array to the right.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template<typename limb_t>
const ubint<limb_t>&  ubint<limb_t>::RShiftEq(usshort shift){
	bool dbg_flag = false;

	//garbage check
	if(m_state==State::GARBAGE)
		throw std::logic_error("Value not initialized");

	//trivial cases
	if(this->m_MSB==0)
		return *this;
	if(this->m_MSB <= shift){
		this->m_value.clear(); //zero out this
		this->m_value.push_back(0);
		this->m_MSB=0;
	}

	//compute the number of whole limb shifts
	usint shiftByLimb = shift>>m_log2LimbBitLength;

	//compute the remaining number of bits to shift
	limb_t remainingShift = (shift&(m_limbBitLength-1));


	DEBUG("l2lbl "<< m_log2LimbBitLength);
	DEBUG("totalshift "<< shift);
	DEBUG("shiftByLimb "<<shiftByLimb);
	DEBUG("remainingShift "<<remainingShift);
	DEBUG("size "<<m_value.size());

	//first shift by the number of whole limb shifts
	if(shiftByLimb!=0){

		if (shiftByLimb >this->m_value.size())
			DEBUG("LOGIC ERROR size is " <<this->m_value.size());


		for(auto i =  shiftByLimb; i < this->m_value.size(); ++i){
			DEBUG("limb shift ");
			this->m_value[i-shiftByLimb] = this->m_value[i];
		}
		//zero out upper  "shifted in" limbs
		for(usint i = 0; i< shiftByLimb; ++i){
			DEBUG("limb zereo");
			this->m_value.pop_back();
		}

		//msb adjusted to show the shifts
		this->m_MSB -= shiftByLimb<<m_log2LimbBitLength;

	}

	//remainderShift bit shifts
	if(remainingShift!=0){

		limb_t overFlow = 0;
		limb_t oldVal;
		limb_t maskVal = (1<<(remainingShift))-1;
		limb_t compShiftVal = m_limbBitLength- remainingShift;

		usint startVal = ceilIntByUInt(this->m_MSB);
		//perform shifting by bits by calculating the overflow
		//oveflow is added after the shifting operation

		DEBUG("maskVal "<< maskVal);
		DEBUG("startVal "<< startVal);
		DEBUG("compShiftVal " << compShiftVal);

		for(int i = startVal -1 ; i>=0;i--){
			DEBUG("bit shift "<<i);
			oldVal = this->m_value[i];
			this->m_value[i] = (this->m_value[i]>>remainingShift) + overFlow;

			overFlow = (oldVal &  maskVal);
			overFlow <<= compShiftVal ;
		}

		this->m_MSB -= remainingShift;

	}

	this->NormalizeLimbs();

	DEBUG("final MSB "<<this->m_MSB);
	this->SetMSB();
	DEBUG("final MSB check "<<this->m_MSB);
	return *this;
}

template<typename limb_t>
usint ubint<limb_t>::GetMSB() const {
	return m_MSB;
}

template<typename limb_t>
usint ubint<limb_t>::GetNumberOfLimbs() const {
	return m_value.size();
}

template<typename limb_t>
const std::string ubint<limb_t>::GetState()const{

	switch(m_state) {
	case INITIALIZED:
		return "INITIALIZED";
		break;
	case GARBAGE:
		return "GARBAGE";
		break;
	default:
		throw std::logic_error("GetState() on uninitialized bint"); //shouldn't happen
	}
}

/** Addition operation:
 *  Algorithm used is usual school book sum and carry-over, expect for that radix is 2^m_bitLength.
 */
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::Plus(const ubint& b) const{
	bool dbg_flag = false;		// if true then print dbg output
	//two operands A and B for addition, A is the greater one, B is the smaller one
	DEBUG("Plus");
	const ubint* A = NULL;
	const ubint* B = NULL;
	//check for garbage initializations
	if(this->m_state==GARBAGE){
		throw std::logic_error("Plus() to uninitialized bint");
	}
	if(b.m_state==GARBAGE){
		throw std::logic_error("Plus() from uninitialized bint");
	}

	//Assignment of pointers, A assigned the higher value and B assigned the lower value
	if(*this>b){
		A = this; B = &b;
	}
	else {A = &b; B = this;}

	if(B->m_MSB==0)
		return ubint(*A);

	ubint result;
	//note make sure result has no limbs as we are adding them below.
	result.m_value.clear();
	result.m_state = INITIALIZED;

	DEBUG("result initial size "<<result.m_value.size());
	//overflow variable
	Dlimb_t ofl=0;

	//position from A to end addition
	limb_t ceilIntA = ceilIntByUInt(A->m_MSB);
	//position from B to end addition
	limb_t ceilIntB = ceilIntByUInt(B->m_MSB);

	usint i;//

	DEBUG("ceilIntA "<<ceilIntA);
	DEBUG("ceilIntB "<<ceilIntB);

	DEBUG("size a "<< A->m_value.size());
	DEBUG("size b "<< A->m_value.size());



	for(i=0; i<ceilIntB; ++i){ //loop over limbs low to high till you reach the end of the smaller one
		DEBUG("i "<<i);

		//      DEBUG("ofl "<<ofl);  //todo fix <<ostream for Dlimb_t (when it is 128 bits

		DEBUG("Alimb "<<A->m_value[i]);
		DEBUG("Blimb "<<B->m_value[i]);

		ofl =(Dlimb_t)A->m_value[i]+ (Dlimb_t)B->m_value[i]+ofl;//sum of the two int and the carry over

		// DEBUG("newofl "<<ofl);

		result.m_value.push_back((limb_t)ofl);
		ofl>>=m_limbBitLength;//current overflow

		//DEBUG("shiftofl "<<ofl);

	}

	// we have an overflow at the end
	if(ofl){
		for(; i<ceilIntA; ++i){ //keep looping over the remainder of the larger value
			DEBUG("oi "<<i);
			ofl = (Dlimb_t)A->m_value[i]+ofl;//sum of the two int and the carry over

			result.m_value.push_back((limb_t)ofl);
			ofl>>=m_limbBitLength;//current overflow
		}

		if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
			DEBUG("push(1)");
			result.m_value.push_back(1);
		}
	} else { //there is no overflow at the end
		for(; i<ceilIntA; ++i){
			DEBUG("push "<<i);
			result.m_value.push_back(A->m_value[i]);
		}
	}
	result.SetMSB();//Set the MSB.


	DEBUG("final MSB "<<result.m_MSB);

	return result;
}

/** Sub operation:
 *  Algorithm used is usual school book borrow and subtract, except for that radix is 2^m_bitLength.
 */
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::Minus(const ubint& b) const{
	bool dbg_flag = false;
	DEBUG("Sub");
	//check for garbage initialization
	if(this->m_state==GARBAGE){
		throw std::logic_error("Sub() to uninitialized bint");
	}
	if(b.m_state==GARBAGE){
		throw std::logic_error("Sub() to uninitialized bint");
	}
	//return 0 if b is higher than *this as there is no support for negative number
	if(!(*this>b)){
		DEBUG("in Sub, b > a return zero");
		return std::move(ubint(0));
	}
	size_t cntr=0,current=0;

	ubint result(*this);

	DEBUG ("result starts out");
	DEBUGEXP(result.GetInternalRepresentation());

	//array position in A to end substraction (a is always larger than b now)
	int endValA = ceilIntByUInt(this->m_MSB);
	//array position in B to end substraction
	int endValB = ceilIntByUInt(b.m_MSB);

	DEBUG("a ");
	DEBUGEXP(this->GetInternalRepresentation());
	DEBUGEXP(std::hex<<this->GetInternalRepresentation()<<std::dec);
	DEBUG("b ");
	DEBUGEXP(b.GetInternalRepresentation());
	DEBUGEXP(std::hex<<b.GetInternalRepresentation()<<std::dec);
	DEBUGEXP(endValA);
	DEBUGEXP(endValB);

	for(size_t i=0; i<b.m_value.size(); ++i){
		DEBUG ("limb  "<<i);
		DEBUG ("a limb "<<this->m_value[i]);
		DEBUG ("res limb "<<result.m_value[i]);
		DEBUG ("b limb "<<b.m_value[i]);
		if(result.m_value[i]<b.m_value[i]){ //carryover condition need to borrow from higher limbs.
			DEBUG ("borrow at "<<i);
			current=i;
			cntr = current+1;
			//find the first nonzero limb
			if (cntr>=result.m_value.size()){
				std::cout<<"error seek past end of result "<<std::endl;
			}
			while(result.m_value[cntr]==0){
				DEBUG("FF at cntr" <<cntr);
				result.m_value[cntr]=m_MaxLimb; //set all the zero limbs to all FFs (propagate the 1)
				cntr++;
			}
			DEBUG("decrement at " << cntr);
			result.m_value[cntr]--; // and eventually borrow 1 from the first nonzero limb we find
			DEBUG("sub with borrow at " <<i);
			result.m_value[i]=result.m_value[i]+(m_MaxLimb - b.m_value[i]) +1; // and add the it to the current limb
		} else {       //usual subtraction condition
			DEBUG("sub no borrow at " <<i);
			result.m_value[i]=result.m_value[i]- b.m_value[i];
		}
		DEBUG ("res limb "<<i<<" finally "<<result.m_value[i]);

	}
	result.NormalizeLimbs();
	result.SetMSB();
	DEBUG("result msb now "<<result.m_MSB);
	//return the result
	DEBUG ("Returning");
	return std::move(result);

}

/** -=
 *  Algorithm used is usual school book borrow and subtract, except for that radix is 2^m_bitLength.
 */
template<typename limb_t>
const ubint<limb_t>& ubint<limb_t>::MinusEq(const ubint& b) {
	bool dbg_flag = false;
	DEBUG("Sub");
	//check for garbage initialization
	if(this->m_state==GARBAGE){
		throw std::logic_error("Sub() to uninitialized bint");
	}
	if(b.m_state==GARBAGE){
		throw std::logic_error("Sub() to uninitialized bint");
	}
	//return 0 if b is higher than *this as there is no support for negative number
	if(!(*this>b)){
		DEBUG("in Sub, b > a return zero");
		*this = 0;
		return *this;
	}
	size_t cntr=0,current=0;

	DEBUG ("result starts out");
	DEBUGEXP(this->GetInternalRepresentation());

	//array position in A to end subtraction (a is always larger than b now)
	int endValA = ceilIntByUInt(this->m_MSB);
	//array position in B to end subtraction
	int endValB = ceilIntByUInt(b.m_MSB);

	DEBUG("a ");
	DEBUGEXP(this->GetInternalRepresentation());
	DEBUGEXP(std::hex<<this->GetInternalRepresentation()<<std::dec);
	DEBUG("b ");
	DEBUGEXP(b.GetInternalRepresentation());
	DEBUGEXP(std::hex<<b.GetInternalRepresentation()<<std::dec);
	DEBUGEXP(endValA);
	DEBUGEXP(endValB);

	for(size_t i=0; i<b.m_value.size(); ++i){
		DEBUG ("limb  "<<i);
		DEBUG ("a limb "<<this->m_value[i]);
		DEBUG ("res limb "<<this->m_value[i]);
		DEBUG ("b limb "<<b.m_value[i]);
		if(this->m_value[i]<b.m_value[i]){ //carryover condition need to borrow from higher limbs.
			DEBUG ("borrow at "<<i);
			current=i;
			cntr = current+1;
			//find the first nonzero limb
			if (cntr>=this->m_value.size()){
				std::cout<<"error seek past end of result "<<std::endl;
			}
			while(this->m_value[cntr]==0){
				DEBUG("FF at cntr" <<cntr);
				this->m_value[cntr]=m_MaxLimb; //set all the zero limbs to all FFs (propagate the 1)
				cntr++;
			}
			DEBUG("decrement at " << cntr);
			this->m_value[cntr]--; // and eventually borrow 1 from the first nonzero limb we find
			DEBUG("sub with borrow at " <<i);
			this->m_value[i]=this->m_value[i]+(m_MaxLimb - b.m_value[i]) +1; // and add the it to the current limb
		} else {       //usual subtraction condition
			DEBUG("sub no borrow at " <<i);
			this->m_value[i]=this->m_value[i]- b.m_value[i];
		}
		DEBUG ("res limb "<<i<<" finally "<<this->m_value[i]);

	}
	this->NormalizeLimbs();
	this->SetMSB();
	DEBUG("result msb now "<<this->m_MSB);
	//return the result
	DEBUG ("Returning");
	return *this;

}

/** Multiply operation:
 *  Algorithm used is usual school book shift and add after multiplication, except for that radix is 2^m_bitLength.
 */
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::Times(const ubint& b) const{
	bool dbg_flag = false;
	DEBUG("Times");

	ubint ans(0);
	//check for garbage initialized objects
	if(b.m_MSB==0 || b.m_state==GARBAGE ||this->m_state==GARBAGE || this->m_MSB==0){
		return ans;
	}
	//check for trivial condtions
	if(b.m_MSB==1)
		return ubint(*this);

	if(this->m_MSB==1)
		return std::move(ubint(b)); //todo check this? don't think standard move is what we want.

	//position of B in the array where the multiplication should start
	//limb_t ceilLimb = b.m_value.size();
	//Multiplication is done by getting a limb_t from b and multiplying it with *this
	//after multiplication the result is shifted and added to the final answer

	size_t nSize = this->m_value.size();
	size_t bSize = b.m_value.size();
	ubint tmpans;
	ans.m_value.reserve(nSize+bSize);
	tmpans.m_value.reserve(nSize+1);

	for(size_t i= 0;i< bSize;++i){
		DEBUG("i "<<i);
		//ubint tmp2;
		//////
		tmpans.m_value.clear(); //make sure there are no limbs to start.
		Dlimb_t limbb(b.m_value[i]);

		//position in the array to start multiplication
		//
		//variable to capture the overflow
		Dlimb_t temp=0;
		//overflow value
		limb_t ofl=0;


		DEBUG("mibl A:"<<this->ToString() );
		//DEBUG("mibl B:"<<limbb );
		DEBUG("ans.size() now " <<ans.m_value.size());
		DEBUGEXP(ans.GetInternalRepresentation());

		usint ix= 0;
		while (ix<i){
			tmpans.m_value.push_back(0); //equivalent of << shift
			//could use insert
			++ix;
		}

		for(auto itr: m_value){
			DEBUG("mullimb i"<<i);
			temp = ((Dlimb_t)itr*(Dlimb_t)limbb) + ofl;
			//DEBUG("temp "<<temp); //todo fix when ostream<< works for 128 bit

			tmpans.m_value.push_back((limb_t)temp);
			ofl = temp>>m_limbBitLength;
			DEBUG("ans.size() now " <<ans.m_value.size());
			DEBUGEXP(tmpans.GetInternalRepresentation());
		}
		//check if there is any final overflow
		if(ofl){
			DEBUG("mullimb ofl "<<ofl);
			tmpans.m_value.push_back(ofl);
		}

		//usint nSize = m_value.size();
		tmpans.m_state = INITIALIZED;
		tmpans.SetMSB();
		DEBUG("ans.size() final " <<ans.m_value.size());
		DEBUGEXP(tmpans.GetInternalRepresentation());
		DEBUG("mibl ans "<<ans.ToString());
		/////

		//ans += tmpans<<=(i)*m_limbBitLength;
		ans += tmpans;
		//ans += (this->MulIntegerByLimb(b.m_value[i]))<<=(i)*m_limbBitLength;
		// usint tmp1 = (i)*m_limbBitLength;
		// DEBUG("tmp1 "<<tmp1);
		// tmp2 = (this->MulIntegerByLimb(b.m_value[i])) <<= tmp1;
		// DEBUG("tmp2 "<<tmp2.ToString());
		// ans += tmp2;

		DEBUG("ans now "<<ans.ToString());
	}

	return ans;
}

/** Multiply operation:
 *  Algorithm used is usual school book shift and add after multiplication, except for that radix is 2^m_bitLength.
 */
template<typename limb_t>
const ubint<limb_t>& ubint<limb_t>::TimesEq(const ubint& b) {
	*this = this->Times(b);
	return *this;
}

template<typename limb_t>
const ubint<limb_t>& ubint<limb_t>::PlusEq(const ubint& b) {
	bool dbg_flag = false;		// if true then print dbg output
	DEBUG("in +=");
	//check for garbage initializations
	if(this->m_state==GARBAGE){
		throw std::logic_error("+= to uninitialized bint");
	}
	if(b.m_state==GARBAGE){
		throw std::logic_error("+= from uninitialized bint");
	}

	if(b.m_MSB==0){ //b==0
		DEBUG("b ==0");
		return (*this);
	}
	if(this->m_MSB==0){ //a==0
		DEBUG("a ==0");
		*this = b;
		return (*this);
	}

	//overflow variable
	Dlimb_t ofl=0;

	size_t sizeThis = this->m_value.size();
	size_t sizeB = b.m_value.size();

	usint i;//

	DEBUG("sizeThis "<<sizeThis);
	DEBUG("sizeB "<<sizeB);

	DEBUG("size this "<< this->m_value.size());
	DEBUG("size b "<< b.m_value.size());
	bool thisIsBigger = sizeThis>sizeB;
	size_t sizeSmall= (sizeThis<sizeB)?sizeThis:sizeB;


	for(i=0; i<sizeSmall; ++i){ //loop over limbs low to high till you reach the end of the smaller one
		DEBUG("i "<<i);

		//      DEBUG("ofl "<<ofl);  //todo fix <<ostream for Dlimb_t (when it is 128 bits

		DEBUG("thislimb "<<this->m_value[i]);
		DEBUG("blimb "<<b.m_value[i]);

		ofl =(Dlimb_t)this->m_value[i]+ (Dlimb_t)b.m_value[i]+ofl;//sum of the two int and the carry over

		// DEBUG("newofl "<<ofl);

		this->m_value[i]=(limb_t)ofl;
		ofl>>=m_limbBitLength;//current overflow

		//DEBUG("shiftofl "<<ofl);

	}
	if (thisIsBigger) {
		// we have an overflow at the of the shorter word, so we need to
		if(ofl){
			for(; i<sizeThis; ++i){ //keep looping over the remainder of the larger value
				DEBUG("oi "<<i);
				ofl = (Dlimb_t)this->m_value[i]+ofl;//sum of the two int and the carry over
				this->m_value[i] = (limb_t)ofl;
				ofl>>=m_limbBitLength;//current overflow
			}
			if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
				DEBUG("push(1)");
				this->m_value.push_back(1);
			}
		}
	}else{

		// B is bigger and we have an overflow at the of the shorter word, so we need to
		if(ofl){
			for(; i<sizeB; ++i){ //keep looping over the remainder of the larger value
				DEBUG("oi "<<i);
				ofl = (Dlimb_t)b.m_value[i]+ofl;//sum of the two int and the carry over

				this->m_value.push_back((limb_t)ofl);
				ofl>>=m_limbBitLength;//current overflow
			}

			if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
				DEBUG("push(1)");
				this->m_value.push_back(1);
			}
		} else { //there is no overflow at the end, just copy the rest
			for(; i<sizeB; ++i){
				DEBUG("push "<<i);
				this->m_value.push_back(b.m_value[i]);
			}
		}
	}
	this->SetMSB();//Set the MSB.
	DEBUG("final MSB "<<this->m_MSB);
	return *this;
}

/** Multiply operation helper function:
 *  Algorithm used is usual school book multiplication.
 *  This function is used in the Multiplication of two ubint objects
 * note this function is deprecated
 */
template<typename limb_t>
inline ubint<limb_t> ubint<limb_t>::MulIntegerByLimb(limb_t b) const{
	bool dbg_flag = false;
	DEBUG("MulIntegerByLimb");
	if(this->m_state==GARBAGE)
		throw std::logic_error("MulIntegerByLimb() of uninitialized bint");
	if(b==0 || this->m_MSB==0)
		return ubint(0);

	ubint ans;
	//ans.m_value.reserve(this->m_value.size()+1);
	ans.m_value.clear(); //make sure there are no limbs to start.

	//position in the array to start multiplication
	//
	size_t endVal = this->m_value.size();
	DEBUG("endVal"<<endVal);
	//variable to capture the overflow
	Dlimb_t temp=0;
	//overflow value
	limb_t ofl=0;
	size_t i= 0;

	DEBUG("mibl A:"<<this->ToString() );
	DEBUG("mibl B:"<<b );
	DEBUG("ans.size() now " <<ans.m_value.size());
	DEBUGEXP(ans.GetInternalRepresentation());

	for(;i<endVal ;++i){
		DEBUG("mullimb i"<<i);
		temp = ((Dlimb_t)m_value[i]*(Dlimb_t)b) + ofl;
		//DEBUG("temp "<<temp); //todo fix when ostream<< works for 128 bit

		ans.m_value.push_back((limb_t)temp);
		ofl = temp>>m_limbBitLength;
		DEBUG("ans.size() now " <<ans.m_value.size());
		DEBUGEXP(ans.GetInternalRepresentation());

	}
	//check if there is any final overflow
	if(ofl){
		DEBUG("mullimb ofl "<<ofl);
		ans.m_value.push_back(ofl);
	}

	//usint nSize = m_value.size();
	ans.m_state = INITIALIZED;
	ans.SetMSB();
	DEBUG("ans.size() final " <<ans.m_value.size());
	DEBUGEXP(ans.GetInternalRepresentation());
	DEBUG("mibl ans "<<ans.ToString());

	return ans;
}

/* q[0], r[0], u[0], and v[0] contain the LEAST significant words.
     (The sequence is in little-endian order).

     This is a fairly precise implementation of Knuth's Algorithm D, for a
     binary computer with base b = 2**(32|64). The caller supplies:
     1. Space q for the quotient, m - n + 1 words (at least one).
     2. Space r for the remainder (optional), n words.
     3. The dividend u, m words, m >= 1.
     4. The divisor v, n words, n >= 2.
     The most significant digit of the divisor, v[n-1], must be nonzero.  The
     dividend u may have leading zeros; this just makes the algorithm take
     longer and makes the quotient contain more leading zeros.  A value of
     NULL may be given for the address of the remainder to signify that the
     caller does not want the remainder.
     The program does not alter the input parameters u and v.
     The quotient and remainder returned may have leading zeros.  The
     function itself returns a value of 0 for success and 1 for invalid
     parameters (e.g., division by 0).
     For now, we must have m >= n.  Knuth's Algorithm D also requires
     that the dividend be at least as long as the divisor.  (In his terms,
     m >= 0 (unstated).  Therefore m+n >= n.) */

inline const int nlz64(uint64_t x) { //todo: needs to be flexible and select the appropriate nlz based on limb size..
	int n;

	if (x == 0) return(64);
	n = 0;
	if (x <= 0x000000FF) {n = n +32; x = x <<32;}
	if (x <= 0x0000FFFF) {n = n +16; x = x <<16;}
	if (x <= 0x00FFFFFF) {n = n + 8; x = x << 8;}
	if (x <= 0x0FFFFFFF) {n = n + 4; x = x << 4;}
	if (x <= 0x3FFFFFFF) {n = n + 2; x = x << 2;}
	if (x <= 0x7FFFFFFF) {n = n + 1;}
	return n;
}

inline const int nlz32(uint32_t x) { //todo: needs to be flexible.
	int n;

	if (x == 0) return(32);
	n = 0;
	if (x <= 0x0000FFFF) {n = n +16; x = x <<16;}
	if (x <= 0x00FFFFFF) {n = n + 8; x = x << 8;}
	if (x <= 0x0FFFFFFF) {n = n + 4; x = x << 4;}
	if (x <= 0x3FFFFFFF) {n = n + 2; x = x << 2;}
	if (x <= 0x7FFFFFFF) {n = n + 1;}
	return n;
}
//todo figure out a C++ way to do this....
#ifdef UBINT_32 //32  bit code
#undef nlz
#define nlz(x) nlz32(x)
#endif

#ifdef UBINT_64 //64  bit code
#undef nlz
#define nlz(x) nlz64(x)
#endif

//#define max(x, y) ((x) > (y) ? (x) : (y))

//returns quotient and remainder
template<typename limb_t>
int ubint<limb_t>::divqr_vect(ubint& qin, ubint& rin, const ubint& uin, const ubint& vin) const{

	vector<limb_t>&q = (qin.m_value);
	vector<limb_t>&r = (rin.m_value);
	const vector<limb_t>&u = (uin.m_value);
	const vector<limb_t>&v = (vin.m_value);

	int m = u.size();
	int n = v.size();

	q.resize(m-n+1);


	const Dlimb_t ffs = (Dlimb_t)m_MaxLimb; // Number  (2**64)-1.
	const Dlimb_t b = (Dlimb_t)m_MaxLimb+1; // Number base (2**64).

	Dlimb_t qhat;                   // Estimated quotient digit.
	Dlimb_t rhat;                   // A remainder.64
	Dlimb_t p;                      // Product of two digits.
	Sdlimb_t t, k;
	int s, i, j;

	if (m < n || n <= 0 || v[n-1] == 0){
		std::cout<< "Error in divqr_vect m, n, v[n-1] " << m <<", "<< n << ", " << v[n-1] << std::endl;
		return 1;                         // Return if invalid param.
	}
	if (n == 1) {                        // Take care of
		k = 0;                            // the case of a
		for (j = m - 1; j >= 0; j--) {    // single-digit
			q[j] = (k*b + u[j])/v[0];      // divisor here.
			k = (k*b + u[j]) - q[j]*v[0];
		}
		if (r.size() != 0) r[0]=k;
		return 0;
	}

	/* Normalize by shifting v left just enough so that its high-order
       bit is on, and shift u left the same amount. We may have to append a
       high-order digit on the dividend; we do that unconditionally. */

	s = nlz(v[n-1]);             // 0 <= s <= m_limbBitLenghth-1.
	// std::cout<< "nlz of " << v[n-1]  << " = "<<  s;
	// vn = (limb_t *)alloca(4*n);
	vector<limb_t> vn(n);
	for (i = n - 1; i > 0; i--)
		vn[i] = (v[i] << s) | ((Dlimb_t)v[i-1] >> (m_limbBitLength-s));
	vn[0] = v[0] << s;

	//un = (limb_t *)alloca(4*(m + 1));
	vector<limb_t> un(m+1);

	un[m] = (Dlimb_t)u[m-1] >> (m_limbBitLength-s);
	for (i = m - 1; i > 0; i--)
		un[i] = (u[i] << s) | ((Dlimb_t)u[i-1] >> (m_limbBitLength-s));
	un[0] = u[0] << s;

	for (j = m - n; j >= 0; j--) {       // Main loop.
		// Compute estimate qhat of q[j].
		qhat = (un[j+n]*b + un[j+n-1])/vn[n-1];
		rhat = (un[j+n]*b + un[j+n-1]) - qhat*vn[n-1];
		again:
		if (qhat >= b || qhat*vn[n-2] > b*rhat + un[j+n-2])
		{ qhat = qhat - 1;
		rhat = rhat + vn[n-1];
		if (rhat < b) goto again;
		}

		// Multiply and subtract.
		k = 0;
		for (i = 0; i < n; i++) {
			p = qhat*vn[i];
			//t = un[i+j] - k - (p & 0xFFFFFFFFLL);
			//t = un[i+j] - k - (p & 0xFFFFFFFFFFFFFFFFLL);
			t = un[i+j] - k - (p & ffs);
			un[i+j] = t;
			k = (p >> m_limbBitLength) - (t >> m_limbBitLength);
		}
		t = un[j+n] - k;
		un[j+n] = t;

		q[j] = qhat;              // Store quotient digit.
		if (t < 0) {              // If we subtracted too
			q[j] = q[j] - 1;       // much, add back.
			k = 0;
			for (i = 0; i < n; i++) {
				t = (Dlimb_t)un[i+j] + vn[i] + k;
				un[i+j] = t;
				k = t >> m_limbBitLength;
			}
			un[j+n] = un[j+n] + k;
		}
	} // End j.
	// the caller wants the remainder, unnormalize
	// it and pass it back.
	r.resize(n);
	for (i = 0; i < n-1; i++)
		r[i] = (un[i] >> s) | ((Dlimb_t)un[i+1] << (m_limbBitLength-s));
	r[n-1] = un[n-1] >> s;

	return 0;
}

//quotient only
template<typename limb_t>
int ubint<limb_t>::divq_vect(ubint& qin, const ubint& uin, const ubint& vin) const{

	vector<limb_t>&q = (qin.m_value);
	const vector<limb_t>&u = (uin.m_value);
	const vector<limb_t>&v = (vin.m_value);

	int m = u.size();
	int n = v.size();

	q.resize(m-n+1);


	const Dlimb_t ffs = (Dlimb_t)m_MaxLimb; // Number  (2**64)-1.
	const Dlimb_t b = (Dlimb_t)m_MaxLimb+1; // Number base (2**64).

	Dlimb_t qhat;                   // Estimated quotient digit.
	Dlimb_t rhat;                   // A remainder.64
	Dlimb_t p;                      // Product of two digits.
	Sdlimb_t t, k;
	int s, i, j;

	if (m < n || n <= 0 || v[n-1] == 0){
		std::cout<< "Error in divq_vect m, n, v[n-1] " << m <<", "<< n << ", " << v[n-1] << std::endl;
		return 1;                         // Return if invalid param.
	}
	if (n == 1) {                        // Take care of
		k = 0;                            // the case of a
		for (j = m - 1; j >= 0; j--) {    // single-digit
			q[j] = (k*b + u[j])/v[0];      // divisor here.
			k = (k*b + u[j]) - q[j]*v[0];
		}

		return 0;
	}

	/* Normalize by shifting v left just enough so that its high-order
       bit is on, and shift u left the same amount. We may have to append a
       high-order digit on the dividend; we do that unconditionally. */

	s = nlz(v[n-1]);             // 0 <= s <= m_limbBitLenghth-1.
	// std::cout<< "nlz of " << v[n-1]  << " = "<<  s;
	// vn = (limb_t *)alloca(4*n);
	vector<limb_t> vn(n);
	for (i = n - 1; i > 0; i--)
		vn[i] = (v[i] << s) | ((Dlimb_t)v[i-1] >> (m_limbBitLength-s));
	vn[0] = v[0] << s;

	//un = (limb_t *)alloca(4*(m + 1));
	vector<limb_t> un(m+1);

	un[m] = (Dlimb_t)u[m-1] >> (m_limbBitLength-s);
	for (i = m - 1; i > 0; i--)
		un[i] = (u[i] << s) | ((Dlimb_t)u[i-1] >> (m_limbBitLength-s));
	un[0] = u[0] << s;

	for (j = m - n; j >= 0; j--) {       // Main loop.
		// Compute estimate qhat of q[j].
		qhat = (un[j+n]*b + un[j+n-1])/vn[n-1];
		rhat = (un[j+n]*b + un[j+n-1]) - qhat*vn[n-1];
		again:
		if (qhat >= b || qhat*vn[n-2] > b*rhat + un[j+n-2])
		{ qhat = qhat - 1;
		rhat = rhat + vn[n-1];
		if (rhat < b) goto again;
		}

		// Multiply and subtract.
		k = 0;
		for (i = 0; i < n; i++) {
			p = qhat*vn[i];
			//t = un[i+j] - k - (p & 0xFFFFFFFFLL);
			//t = un[i+j] - k - (p & 0xFFFFFFFFFFFFFFFFLL);
			t = un[i+j] - k - (p & ffs);
			un[i+j] = t;
			k = (p >> m_limbBitLength) - (t >> m_limbBitLength);
		}
		t = un[j+n] - k;
		un[j+n] = t;

		q[j] = qhat;              // Store quotient digit.
		if (t < 0) {              // If we subtracted too
			q[j] = q[j] - 1;       // much, add back.
			k = 0;
			for (i = 0; i < n; i++) {
				t = (Dlimb_t)un[i+j] + vn[i] + k;
				un[i+j] = t;
				k = t >> m_limbBitLength;
			}
			un[j+n] = un[j+n] + k;
		}
	} // End j.
	return 0;
}
///////
//remainder only
template<typename limb_t>
int ubint<limb_t>::divr_vect(ubint& rin, const ubint& uin, const ubint& vin) const{
#ifdef OLD_DIV
	vector<limb_t>&r = (rin.m_value);
	const vector<limb_t>&u = (uin.m_value);
	const vector<limb_t>&v = (vin.m_value);

	int m = u.size();
	int n = v.size();
#else
	vector<limb_t>&r = (rin.m_value);
	limb_t const *u = (uin.m_value.data());
	const vector<limb_t>&v = (vin.m_value);

	int m = uin.m_value.size();
	int n = v.size();



#endif

	const Dlimb_t ffs = (Dlimb_t)m_MaxLimb; // Number  (2**64)-1.
	const Dlimb_t b = (Dlimb_t)m_MaxLimb+1; // Number base (2**64).

	Dlimb_t qhat;                   // Estimated quotient digit.
	Dlimb_t rhat;                   // A remainder.64
	Dlimb_t p;                      // Product of two digits.
	Sdlimb_t t, k;
	int s, i, j;

	if (m < n || n <= 0 || v[n-1] == 0){
		std::cout<< "Error in divr_vect m, n, v[n-1] " << m <<", "<< n << ", " << v[n-1] << std::endl;
		return 1;                         // Return if invalid param.
	}
	if (n == 1) {                        // Take care of
		vector<limb_t>q(m-n+1);
		//q.resize(m-n+1);

		k = 0;                            // the case of a
		for (j = m - 1; j >= 0; j--) {    // single-digit
			q[j] = (k*b + u[j])/v[0];      // divisor here.
			k = (k*b + u[j]) - q[j]*v[0];
		}
		r.resize(n);
		r[0]=k;
		return 0;
	}

	/* Normalize by shifting v left just enough so that its high-order
       bit is on, and shift u left the same amount. We may have to append a
       high-order digit on the dividend; we do that unconditionally. */

	s = nlz(v[n-1]);             // 0 <= s <= m_limbBitLenghth-1.
	// std::cout<< "nlz of " << v[n-1]  << " = "<<  s;
#ifdef OLD_DIV
	vector<limb_t> vn(n);
	vector<limb_t> un(m+1);
#else
	limb_t *vn = (limb_t *)alloca(sizeof(limb_t)*n);
	limb_t *un = (limb_t *)alloca(sizeof(limb_t)*(m + 1));
#endif
	for (i = n - 1; i > 0; i--)
		vn[i] = (v[i] << s) | ((Dlimb_t)v[i-1] >> (m_limbBitLength-s));
	vn[0] = v[0] << s;



	un[m] = (Dlimb_t)u[m-1] >> (m_limbBitLength-s);
	for (i = m - 1; i > 0; i--)
		un[i] = (u[i] << s) | ((Dlimb_t)u[i-1] >> (m_limbBitLength-s));
	un[0] = u[0] << s;

	for (j = m - n; j >= 0; j--) {       // Main loop.
		// Compute estimate qhat of q[j].
		qhat = (un[j+n]*b + un[j+n-1])/vn[n-1];
		rhat = (un[j+n]*b + un[j+n-1]) - qhat*vn[n-1];
		again:
		if (qhat >= b || qhat*vn[n-2] > b*rhat + un[j+n-2])
		{ qhat = qhat - 1;
		rhat = rhat + vn[n-1];
		if (rhat < b) goto again;
		}

		// Multiply and subtract.
		k = 0;
		for (i = 0; i < n; i++) {
			p = qhat*vn[i];
			//t = un[i+j] - k - (p & 0xFFFFFFFFLL);
			//t = un[i+j] - k - (p & 0xFFFFFFFFFFFFFFFFLL);
			t = un[i+j] - k - (p & ffs);
			un[i+j] = t;
			k = (p >> m_limbBitLength) - (t >> m_limbBitLength);
		}
		t = un[j+n] - k;
		un[j+n] = t;

		//q[j] = qhat;              // Store quotient digit.
		if (t < 0) {              // If we subtracted too
			//q[j] = q[j] - 1;       // much, add back.
			k = 0;
			for (i = 0; i < n; i++) {
				t = (Dlimb_t)un[i+j] + vn[i] + k;
				un[i+j] = t;
				k = t >> m_limbBitLength;
			}
			un[j+n] = un[j+n] + k;
		}
	} // End j.

	// the caller wants the remainder, unnormalize
	// it and pass it back.
#ifdef OLD_DIV
	r.resize(n);
#endif
	for (i = 0; i < n-1; i++)
		r[i] = (un[i] >> s) | ((Dlimb_t)un[i+1] << (m_limbBitLength-s));
	r[n-1] = un[n-1] >> s;

	return 0;
}

/* Division operation:
 *  Algorithm used is usual school book long division , except for that radix is 2^m_bitLength.
 *  Optimization done: Uses bit shift operation for logarithmic convergence.
 */
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::DividedBy(const ubint& b) const{
	//check for garbage initialization and 0 condition
	if(b.m_state==GARBAGE)
		throw std::logic_error("DividedBy() Divisor uninitialised");

	if(b==0)
		throw std::logic_error("DividedBy() Divisor is zero");

	if(b.m_MSB>this->m_MSB)
		return std::move(ubint(0)); // Kurt and Yuriy want this.

	if(this->m_state==GARBAGE)
		throw std::logic_error("DividedBy() Dividend uninitialised");

	else if(b==*this)
		return std::move(ubint(1));

	ubint ans;
	int f;
	f = divq_vect((ans), (*this),  (b));
	if (f!= 0)
		throw std::logic_error("DividedBy() error");
	ans.NormalizeLimbs();
	ans.m_state = INITIALIZED;
	ans.SetMSB();
	return ans;

}

//FIXME must be in-place
template<typename limb_t>
const ubint<limb_t>& ubint<limb_t>::DividedByEq(const ubint& b) {
	//check for garbage initialization and 0 condition
	if(b.m_state==GARBAGE)
		throw std::logic_error("DividedByEq() Divisor uninitialised");

	if(b==0)
		throw std::logic_error("DividedByEq() Divisor is zero");

	if(b.m_MSB>this->m_MSB)
		return *this = 0;

	if(this->m_state==GARBAGE)
		throw std::logic_error("DividedByEq() Dividend uninitialised");

	else if(b==*this)
		return *this = 1;

	ubint ans;
	int f;
	f = divq_vect((ans), (*this),  (b));
	if (f!= 0)
		throw std::logic_error("DividedByEq() error");
	ans.NormalizeLimbs();
	ans.m_state = INITIALIZED;
	ans.SetMSB();
	return *this = ans;

}

//Initializes the vector of limbs from the string equivalent of ubint
// also sets MSB
//Algorithm used is repeated division by 2
//Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
template<typename limb_t>
void ubint<limb_t>::AssignVal(const std::string& vin){
	//Todo: eliminate m_limbBitLength, make dynamic instead

	bool dbg_flag = false;	// if true then print dbg output
	DEBUG("AssignVal ");
	DEBUG("vin: "<< vin);


	std::string v = vin;
	DEBUG("v1: "<< v);
	// strip off leading zeros from the input string
	v.erase(0, v.find_first_not_of('0'));
	// strip off leading spaces from the input string
	v.erase(0, v.find_first_not_of(' '));
	if (v.size() == 0) {
		//caustic case of input string being all zeros
		v = "0"; //set to one zero
	}
	DEBUG("v2: "<< v);


	uschar *DecValue;//array of decimal values
	size_t arrSize=v.length();

	//memory allocated for decimal array
	DecValue = new uschar[arrSize]; //todo smartpointer

	for(size_t i=0;i<arrSize;i++)//store the string to decimal array
		DecValue[i] = (uschar) stoi(v.substr(i,1));

	if (dbg_flag) {
		std::cout << "decval1 ";
		for(size_t i=0;i<arrSize;i++)
			std::cout <<(usint)DecValue[i] << " ";//for debug purpose
		std::cout << std::endl;
	}

	//clear the current value of m_value;
	m_value.clear();

	size_t zptr = 0;
	//index of highest non-zero number in decimal number
	//define  bit register array
	uschar *bitArr = new uschar[m_limbBitLength](); //todo smartpointer

	int cnt=m_limbBitLength-1;
	//cnt is a pointer to the bit position in bitArr, when bitArr is compelete it is ready to be transfered to Value
	while(zptr!=arrSize){
		bitArr[cnt]=DecValue[arrSize-1]%2;
		//start divide by 2 in the DecValue array
		for(size_t i=zptr;i<arrSize-1;i++){
			DecValue[i+1]= (DecValue[i]%2)*10 + DecValue[i+1];
			DecValue[i]>>=1;
		}
		DecValue[arrSize-1]>>=1;
		//division ends here
#ifdef DEBUG_DECVALUE
		for(int i=zptr;i<arrSize;i++)
			cout<<(short)DecValue[i];//for debug purpose
		cout<<endl;
#endif
		cnt--;
		if(cnt==-1){//cnt = -1 indicates bitArr is ready for transfer
			cnt=m_limbBitLength-1;
			DEBUG("push back " <<  UintInBinaryToDecimal(bitArr));
			m_value.push_back( UintInBinaryToDecimal(bitArr));
		}
		if(DecValue[zptr]==0)zptr++;//division makes Most significant digit zero, hence we increment zptr to next value
		if(zptr==arrSize&&DecValue[arrSize-1]==0){
			m_value.push_back(UintInBinaryToDecimal(bitArr));//Value assignment
		}
	}

	m_state = INITIALIZED;
	NormalizeLimbs(); //normalize the limbs
	SetMSB(); //sets the MSB correctly

	delete []bitArr;
	delete[] DecValue;//deallocate memory

	if (dbg_flag) {
		std::cout << "in AssignVal m_value ";
		for(size_t i=0;i<m_value.size();i++)
			std::cout <<m_value[i] << " ";//for debug purpose
		std::cout << std::endl;
		std::cout << "in AssignVal m_value hex ";
		for(size_t i=0;i<m_value.size();i++)
			std::cout << std::hex <<m_value[i] <<  " ";//for debug purpose
		std::cout <<std::dec << std::endl;

		std::cout << "in AssignVal m_value hex ";
		for(size_t i=0;i<m_value.size();i++)
			std::cout << std::hex <<m_value[i] <<  " ";//for debug purpose
		std::cout <<std::dec << std::endl;
	}
	DEBUG("in AssignVal msb now "<< m_MSB );
	DEBUG("in AssignVal msb now "<< m_MSB );

}

template<typename limb_t>
void ubint<limb_t>::SetMSB()
{
	m_MSB = 0;
	if(this->m_state==GARBAGE){
		throw std::logic_error("SetMSB() of uninitialized bint");
	}

	m_MSB = (m_value.size()-1) * m_limbBitLength; //figure out bit location of all but last limb
	m_MSB+= GetMSBlimb_t(m_value.back()); //add the value of that last limb.
}

//guessIdx is the index of largest limb_t number in array.
template<typename limb_t>
void ubint<limb_t>::SetMSB(usint guessIdxChar){

	m_MSB = (m_value.size() - guessIdxChar - 1)*m_limbBitLength;
	m_MSB += GetMSBlimb_t(m_value[guessIdxChar]);
}

template<typename limb_t>
void ubint<limb_t>::SetValue(const std::string& str){
	ubint::AssignVal(str);
}

//Algorithm used: optimized division algorithm
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::Mod(const ubint& modulus) const{
	bool dbg_flag = false;

	//check for garbage initialisation
	if(this->m_state==GARBAGE)
		throw std::logic_error("Mod() of uninitialized bint");
	if(modulus.m_state==GARBAGE)
		throw std::logic_error("Mod() using uninitialized bint as modulus");

	if(modulus==0)
		throw std::logic_error("Mod() using zero modulus");

	if(modulus.m_value.size()>1 && modulus.m_value.back()==0)
		throw std::logic_error("Mod() using unnormalized  modulus");

	//return the same value if value is less than modulus
	if (this->m_MSB < modulus.m_MSB){
		return std::move(ubint(*this));
	}
	if ((this->m_MSB == modulus.m_MSB)&&(*this<modulus)){
		DEBUG("this< modulus");
		return std::move(ubint(*this));
	}

	//use simple masking operation if modulus is 2
	if(modulus.m_MSB==2 && modulus.m_value[0]==2){
		if(this->m_value[0]%2==0)
			return ubint(0);
		else
			return ubint(1);
	}

#ifndef UBINT_64

	// return the remainder of the divided by operation
	ubint ans(0);
	if (dbg_flag){
		DEBUG("modulus ");
		DEBUGEXP(modulus.GetInternalRepresentation());
	}

	int f;
#ifndef OLD_DIV
	ans.m_value.resize(modulus.m_value.size());
#endif

	f = divr_vect(ans,  *this,  modulus);
	if (f!= 0)
		throw std::logic_error("Mod() divr error");

	ans.NormalizeLimbs();
	ans.SetMSB();
	ans.m_state = INITIALIZED;
	DEBUGEXP(ans.GetInternalRepresentation());
	return(ans);

#else //radically slow for 64 bit version.
	int initial_shift = 0;
	//No of initial left shift that can be performed which will make it comparable to the current value.
	DEBUG("in Mod this "<<*this);
	DEBUG("in Mod thismsb "<<this->m_MSB);
	DEBUG("in Mod mod "<<modulus);
	DEBUG("in Mod modmsb "<<modulus.m_MSB);

	if(this->m_MSB > modulus.m_MSB)
		initial_shift=this->m_MSB - modulus.m_MSB -1;
	DEBUG("initial_shift "<<initial_shift);

	ubint j = modulus<<initial_shift;
	ubint result(*this);
	ubint temp;
	while(true){
		//exit criteria
		if(result<modulus) break;
		if (result.m_MSB > j.m_MSB) {
			temp = j<<1;
			if (result.m_MSB == j.m_MSB + 1) {
				if(result>temp){
					j=temp;
				}
			}
		}
		//subtracting the running remainder by a multiple of modulus
		result -= j;
		initial_shift = j.m_MSB - result.m_MSB +1;
		if(result.m_MSB-1>=modulus.m_MSB){
			DEBUG("j before "<<j<< " initial_shift "<<initial_shift);
			j>>=initial_shift;
		} else {
			j = modulus;
			DEBUG("j = "<<j);
		}
	}
	DEBUGEXP(std::hex<<this->GetInternalRepresentation()<<std::dec);
	result.NormalizeLimbs();
	result.SetMSB();
	return result;
#endif
}

template<typename limb_t>
const ubint<limb_t>& ubint<limb_t>::ModEq(const ubint& modulus) {
	bool dbg_flag = false;

	//check for garbage initialisation
	if(this->m_state==GARBAGE)
		throw std::logic_error("ModEq() of uninitialized bint");
	if(modulus.m_state==GARBAGE)
		throw std::logic_error("ModEq() using uninitialized bint as modulus");

	if(modulus==0)
		throw std::logic_error("ModEq() using zero modulus");

	if(modulus.m_value.size()>1 && modulus.m_value.back()==0)
		throw std::logic_error("ModEq() using unnormalized  modulus");

	//return the same value if value is less than modulus
	if (this->m_MSB < modulus.m_MSB){
		return *this;
	}
	if ((this->m_MSB == modulus.m_MSB)&&(*this<modulus)){
		DEBUG("this< modulus");
		return *this;
	}

	//use simple masking operation if modulus is 2
	if(modulus.m_MSB==2 && modulus.m_value[0]==2){
		if(this->m_value[0]%2==0)
			return *this = 0;
		else
			return *this = 1;
	}

#ifndef UBINT_64

	// FIXME do this in place!
	// return the remainder of the divided by operation
	ubint ans(0);
	if (dbg_flag){
		DEBUG("modulus ");
		DEBUGEXP(modulus.GetInternalRepresentation());
	}

	int f;
#ifndef OLD_DIV
	ans.m_value.resize(modulus.m_value.size());
#endif

	f = divr_vect(ans,  *this,  modulus);
	if (f!= 0)
		throw std::logic_error("Mod() divr error");

	ans.NormalizeLimbs();
	ans.SetMSB();
	ans.m_state = INITIALIZED;
	DEBUGEXP(ans.GetInternalRepresentation());
	return *this = ans;

#else //radically slow for 64 bit version.
	int initial_shift = 0;
	//No of initial left shift that can be performed which will make it comparable to the current value.
	DEBUG("in Mod this "<<*this);
	DEBUG("in Mod thismsb "<<this->m_MSB);
	DEBUG("in Mod mod "<<modulus);
	DEBUG("in Mod modmsb "<<modulus.m_MSB);

	if(this->m_MSB > modulus.m_MSB)
		initial_shift=this->m_MSB - modulus.m_MSB -1;
	DEBUG("initial_shift "<<initial_shift);

	ubint j = modulus<<initial_shift;
	ubint result(*this);
	ubint temp;
	while(true){
		//exit criteria
		if(result<modulus) break;
		if (result.m_MSB > j.m_MSB) {
			temp = j<<1;
			if (result.m_MSB == j.m_MSB + 1) {
				if(result>temp){
					j=temp;
				}
			}
		}
		//subtracting the running remainder by a multiple of modulus
		result -= j;
		initial_shift = j.m_MSB - result.m_MSB +1;
		if(result.m_MSB-1>=modulus.m_MSB){
			DEBUG("j before "<<j<< " initial_shift "<<initial_shift);
			j>>=initial_shift;
		} else {
			j = modulus;
			DEBUG("j = "<<j);
		}
	}
	DEBUGEXP(std::hex<<this->GetInternalRepresentation()<<std::dec);
	result.NormalizeLimbs();
	result.SetMSB();
	return result;
#endif
}


template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModBarrett(const ubint& modulus, const ubint& mu) const{
#ifdef NO_BARRETT	
	ubint ans(*this);
	ans.ModEq(modulus);
	return(ans);
#else
	if(*this<modulus){
		return std::move(ubint(*this));
	}
	ubint z(*this);
	ubint q(*this);

	usint n = modulus.m_MSB;
	usint alpha = n + 3;
	int beta = -2;

	q>>=n + beta;
	q*=mu;
	q>>=alpha-beta;
	z-=q*modulus;

	if(z>=modulus)
		z-=modulus;

	return z;
#endif
}

template<typename limb_t>
void  ubint<limb_t>::ModBarrettInPlace(const ubint& modulus, const ubint& mu) {
	this->ModEq( modulus );
	return;
}


//Extended Euclid algorithm used to find the multiplicative inverse
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModInverse(const ubint& modulus) const{

	bool dbg_flag = false;

	if(m_state==GARBAGE || modulus.m_state==GARBAGE)
		throw std::logic_error("ModInverse of uninitialized bint");

	DEBUG("Modinverse");
	DEBUG("THIS VALUE "<< this->ToString());
	DEBUG("modulus "<<modulus.ToString());

	// the max number of iterations should be < 2^k where k ==  min(bitsize (inputs))
	//todo: consider breaking out of the loop if this limit exceeded. the only issue is that the loop counter could would need to be an ubint.


	std::vector<ubint> mods;
	std::vector<ubint> quotient;
	mods.push_back(ubint(modulus));
	if (*this>modulus){
		mods.push_back(this->Mod(modulus));
		//DEBUG("Pushed mod");
	} else {
		mods.push_back(ubint(*this));
		//DEBUG("Pushed this");
	}

	ubint first(mods[0]);
	ubint second(mods[1]);
	ubint result;

	if(mods[1]==1){
		result = 1;
		return result;
	}

	//Error if modulus is 0
	if(second==0){
		throw std::logic_error("ZERO HAS NO INVERSE");
	}


	usint ncycle = 0;
	while(true){
		//DEBUG("**north cycle");
		DEBUG("first "<<first.ToString());
		DEBUG("second "<<second.ToString());
		if (second==0) { // cannot take mod(0);
			mods.push_back(0);//FLAG bottom out
		}else{
			mods.push_back(first.Mod(second));
		}
		//DEBUG("Mod step passed");
		if (second==0){// cannot take mod(0);
			quotient.push_back(0);
		}else {
			quotient.push_back(first.DividedBy(second));
		}
		DEBUG("Division step passed");
		DEBUG("i "<<ncycle);
		DEBUG(" modsback "<<mods.back().ToString());

		if(mods.back()==1){
			//DEBUG("break");
			break;
		}
		if(mods.back()==0){
			throw std::logic_error("ModInverse() inverse not found");
		}

		first = second;
		second = mods.back();
		DEBUG("first "<<first.ToString());
		DEBUG("second "<<second.ToString());

		if (dbg_flag) ncycle++;
		//if (ncycle >100) break; // for debug only
	}
	//DEBUG("MI ncycle "<<ncycle);
	mods.clear();
	mods.push_back(ubint(0));
	mods.push_back(ubint(1));

	first = mods[0];
	second = mods[1];
	//SOUTH ALGORITHM

	size_t limtest = quotient.size()-1;
	for(int i=limtest; i>=0;i--){
		mods.push_back(quotient[i]*second + first);
		first = second;
		second = mods.back();
	}

	if(quotient.size()%2==1){
		result = (modulus - mods.back());
	}
	else{
		result = ubint(mods.back());
	}

	DEBUG("MI: "<<result.ToString());
	return result;

}

template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModAdd(const ubint& b, const ubint& modulus) const{
	ubint a(*this);
	ubint b_op(b);

	//reduce this to a value lower than modulus
	if(*this >= modulus){
		a.ModEq(modulus);
	}
	//reduce b to a value lower than modulus
	if(b >= modulus){
		b_op.ModEq(modulus);
	}

	a.PlusEq(b_op);
	return a.ModEq(modulus);
}

template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModAddFast(const ubint& b, const ubint& modulus) const{
	return this->Plus(b).Mod(modulus);
}

template<typename limb_t>
const ubint<limb_t>& ubint<limb_t>::ModAddEq(const ubint& b, const ubint& modulus) {
	this->PlusEq(b);
	this->ModEq(modulus);
	return *this;
}


template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModSub(const ubint& b, const ubint& modulus) const{
	ubint a(*this);
	ubint b_op(b);

	//reduce this to a value lower than modulus
	if(*this >= modulus){
		a.ModEq(modulus);
	}
	//reduce b to a value lower than modulus
	if(b >= modulus){
		b_op.ModEq(modulus);
	}

	if(a>=b_op){
		a.MinusEq(b_op);
		a.ModEq(modulus);
	}
	else{
		a.PlusEq(modulus);
		a.MinusEq(b_op);
	}

	return a;
}

template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModSubFast(const ubint& b, const ubint& modulus) const{
	ubint a(*this);

	if(a>=b){
		a.MinusEq(b);
		a.ModEq(modulus);
	}
	else{
		a.PlusEq(modulus);
		a.MinusEq(b);
	}

	return a;
}

template<typename limb_t>
const ubint<limb_t>& ubint<limb_t>::ModSubEq(const ubint& b, const ubint& modulus) {
	ubint b_op(b);

	//reduce this to a value lower than modulus
	if(*this >= modulus){
		this->ModEq(modulus);
	}
	//reduce b to a value lower than modulus
	if(b >= modulus){
		b_op.ModEq(modulus);
	}

	if(*this >= b_op) {
		this->MinusEq(b_op);
		this->ModEq(modulus);
	}
	else {
		this->PlusEq(modulus);
		this->MinusEq(b_op);
	}

	return *this;
}

template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModMul(const ubint& b, const ubint& modulus) const{

	ubint a(*this);
	bool dbg_flag = false;
	DEBUG("ModMul");

	ubint ans(0);
	//check for garbage initialized objects
	if(b.m_MSB==0 || b.m_state==GARBAGE || a.m_state==GARBAGE || a.m_MSB==0){
		return ans;
	}
	//check for trivial conditions
	if(b.m_MSB==1)
		return a;

	if(a.m_MSB==1)
		return b;

	//position of B in the array where the multiplication should start
	//limb_t ceilLimb = b.m_value.size();
	//Multiplication is done by getting a limb_t from b and multiplying it with *this
	//after multiplication the result is shifted and added to the final answer

	size_t nSize = a.m_value.size();
	size_t bSize = b.m_value.size();
	ubint tmpans;
	ans.m_value.reserve(nSize+bSize);
	tmpans.m_value.reserve(nSize+bSize);

	for(size_t i= 0;i< bSize;++i){
		DEBUG("i "<<i);
		tmpans.m_value.clear(); //make sure there are no limbs to start.
		Dlimb_t limbb(b.m_value[i]);

		//variable to capture the overflow
		Dlimb_t temp=0;
		//overflow value
		limb_t ofl=0;

		DEBUG("mibl A:"<<a.ToString() );
		// DEBUG("mibl B:"<<limbb );
		DEBUG("ans.size() now " <<ans.m_value.size());
		DEBUGEXP(ans.GetInternalRepresentation());

		usint ix= 0;
		while (ix<i){
			tmpans.m_value.push_back(0); //equivalent of << shift
			//could use insert
			++ix;
		}

		for(auto itr: a.m_value){
			DEBUG("mullimb i"<<i);
			temp = ((Dlimb_t)itr*(Dlimb_t)limbb) + ofl;

			tmpans.m_value.push_back((limb_t)temp);
			ofl = temp>>a.m_limbBitLength;
			DEBUG("ans.size() now " <<ans.m_value.size());
			DEBUGEXP(tmpans.GetInternalRepresentation());

		}
		//check if there is any final overflow
		if(ofl){
			DEBUG("mullimb ofl "<<ofl);
			tmpans.m_value.push_back(ofl);
		}

		//usint nSize = m_value.size();
		tmpans.m_state = INITIALIZED;
		tmpans.SetMSB();
		DEBUG("ans.size() final " <<ans.m_value.size());
		DEBUGEXP(tmpans.GetInternalRepresentation());

		DEBUG("mibl ans "<<ans.ToString());

		//      ans += (tmpans<<=(i)*a.m_limbitLength);
		ans += tmpans;
		ans = ans.Mod(modulus);
		DEBUG("ans now "<<ans.ToString());
	}
	return ans;
}

// FIXME make this skip the mod
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModMulFast(const ubint& b, const ubint& modulus) const{
	return this->ModMul(b, modulus);
}

// FIXME make this in-place!
template<typename limb_t>
const ubint<limb_t>& ubint<limb_t>::ModMulEq(const ubint& b, const ubint& modulus) {
	*this = this->ModMul(b, modulus);
	return *this;
}

//the following is deprecated
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModBarrettMul(const ubint& b, const ubint& modulus,const ubint& mu) const{
#ifdef NO_BARRETT
	return this->ModMul(b, modulus);

#else
	ubint a(*this);
	ubint bb(b);

	//if a is greater than q reduce a to its mod value
	if(*this>modulus)
		a.ModBarrettInPlace(modulus,mu);

	//if b is greater than q reduce b to its mod value
	if(b>modulus)
		bb.ModBarrettInPlace(modulus,mu);

	a.TimesEq(bb);
	a.ModBarrettInPlace(modulus,mu);
	return a;
#endif
}


//the following is deprecated
template<typename limb_t>
void ubint<limb_t>::ModBarrettMulInPlace(const ubint& b, const ubint& modulus,const ubint& mu) {
#ifdef NO_BARRETT
	this->ModMulEq(b, modulus);
	return ;

#else
	ubint bb(b);

	//if this is greater than q reduce a to its mod value
	if(*this>modulus)
		this->ModBarrettInPlace(modulus,mu);

	//if b is greater than q reduce b to its mod value
	if(b>modulus)
		bb.ModBarrettInPlace(modulus,mu);

	this->TimesEq(bb);
	this->ModBarrettInPlace(modulus, mu);

	return;

#endif
}


//the following is deprecated
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModBarrettMul(const ubint& b, const ubint& modulus,const ubint mu_arr[BARRETT_LEVELS]) const{
#ifdef NO_BARRETT
	ubint ans(*this);
	return ans.ModMul(b, modulus);
#else
	ubint a(*this);
	ubint bb(b);

	//if a is greater than q reduce a to its mod value
	if(*this>modulus)
		a.ModBarrettInPlace(modulus,mu_arr);

	//if b is greater than q reduce b to its mod value
	if(b>modulus)
		bb.ModBarrettInPlace(modulus,mu_arr);

	a.TimesEq(bb);
	a.ModBarrettInPlace(modulus,mu_arr);
	return a;
#endif    
}


//the following is deprecated
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModBarrett(const ubint& modulus, const ubint mu_arr[BARRETT_LEVELS+1]) const{
#ifdef NO_BARRETT
	ubint ans(*this);
	ans.ModEq(modulus);
	return(ans);
#else
	if(*this<modulus){
		ubint z(*this);
		return z;
	}
	ubint z(*this);
	ubint q(*this);

	usint n = modulus.m_MSB;
	//level is set to the index between 0 and BARRET_LEVELS - 1
	usint level = (this->m_MSB-1-n)*BARRETT_LEVELS/(n+1)+1;
	usint gamma = (n*level)/BARRETT_LEVELS;

	usint alpha = gamma + 3;
	int beta = -2;

	const ubint& mu = mu_arr[level];

	q>>=n + beta;
	q=q*mu;
	q>>=alpha-beta;
	z-=q*modulus;

	if(z>=modulus)
		z-=modulus;

	return z;
#endif
}


//Modular Exponentiation using Square and Multiply Algorithm
//reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::ModExp(const ubint& b, const ubint& modulus) const{
	bool dbg_flag = false;
	TimeVar t;
	DEBUG("ModExp() ==================");
	TIC(t);

	DEBUG("a: "<<this->ToString());
	DEBUG("b: "<<b.ToString());
	DEBUG("mod: "<<modulus.ToString());

	//mid is intermidiate value that calculates mid^2%q
	ubint mid = this->Mod(modulus);
	DEBUG("mid: "<<mid.ToString());

	//product calculates the running product of mod values
	ubint product(1);

	//Exp is used for spliting b to bit values/ bit extraction
	ubint Exp(b);

	unsigned int loops =0;
#if 1
	while(true){

		//product is multiplied only if lsb bitvalue is 1
		if(Exp.m_value[0]%2==1){
			product = product*mid;
		}

		//running product is calculated
		if(product>modulus){
			product = product.Mod(modulus);
		}

		//DEBUG("product "<<product);
		//divide by 2 and check even to odd to find bit value
		Exp = Exp>>1;
		if(Exp==0)break;

		//DEBUG("Exp "<<Exp);

		//mid calculates mid^2%q
		mid = mid*mid;
		mid = (mid.Mod(modulus));
		//DEBUG("mid: "<<mid);
		//std::cout<<"."<<std::flush;
		loops++;
	}
#else
	while(true){

		//product is multiplied only if lsb bitvalue is 1
		if((Exp.m_value[0]&1)==1){
			product = product.ModMul(mid,modulus);
		}

		//DEBUG("product "<<product);
		//divide by 2 and check even to odd to find bit value
		Exp >>=1;
		if(Exp==0)break;

		//DEBUG("Exp "<<Exp);

		//mid calculates mid^2%q

		mid = (mid.ModMul(mid,modulus));
		//DEBUG("mid: "<<mid);
		//std::cout<<"."<<std::flush;
		loops++;
	}

#endif

	//std::cout<<std::endl;
	DEBUG("Modexp "<<loops<<" loops, time ms "<<TOC_MS(t));
	return product;
}

template<typename limb_t>
const std::string ubint<limb_t>::ToString() const{
	//todo get rid of m_numDigitInPrintval make dynamic
	if (m_value.size()==0)
		throw std::logic_error("ToString() on uninitialized bint");

	//this string object will store this ubint's value
	std::string bbiString;

	//create reference for the object to be printed
	ubint<limb_t> *print_obj;

	usint counter;

	//initiate to object to be printed
	print_obj = new ubint<limb_t>(*this);  //todo smartpointer

	//print_obj->PrintValueInDec();

	//print_VALUE array stores the decimal value in the array
	uschar *print_VALUE = new uschar[m_numDigitInPrintval];  //todo smartpointer

	//reset to zero
	for(size_t i=0;i<m_numDigitInPrintval;i++)
		*(print_VALUE+i)=0;

	//starts the conversion from base r to decimal value
	for(size_t i=print_obj->m_MSB;i>0;i--){

		//print_VALUE = print_VALUE*2
		ubint<limb_t>::double_bitVal(print_VALUE);

		//adds the bit value to the print_VALUE
		ubint<limb_t>::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));


	}

	//find the first occurence of non-zero value in print_VALUE
	for(counter=0;counter<m_numDigitInPrintval-1;counter++){
		if((int)print_VALUE[counter]!=0)break;
	}

	//append this ubint's digits to this method's returned string object
	for (; counter < m_numDigitInPrintval; counter++) {
		bbiString += std::to_string(print_VALUE[counter]);
	}

	delete [] print_VALUE;
	//deallocate the memory since values are inserted into the ostream object
	delete print_obj;

	return bbiString;

}

//Compares the current object with the ubint a.
template<typename limb_t>
inline int ubint<limb_t>::Compare(const ubint& a) const
{
	bool dbg_flag = false;		// if true then print dbg output
	if(this->m_state==GARBAGE || a.m_state==GARBAGE)
		throw std::logic_error("ERROR Compare() against uninitialized bint\n");

	DEBUG("comparing this "<< this->ToString());
	DEBUGEXP(std::hex<<this->GetInternalRepresentation()<<std::dec);

	DEBUG("a "<<a.ToString());
	DEBUGEXP(std::hex<<a.GetInternalRepresentation()<<std::dec);

	//check MSBs to get quick answer
	if(this->m_MSB<a.m_MSB)
		return -1;
	else if(this->m_MSB>a.m_MSB)
		return 1;
	if(this->m_MSB==a.m_MSB){
		//check each limb in descending order
		for(int i=m_value.size()-1 ;i>=0; i--){
			DEBUG("i "<<i);
			DEBUG("a "<<this->m_value[i]);
			DEBUG("b "<<a.m_value[i]);

			if (this->m_value[i]>a.m_value[i]) //b>a
				return 1;
			else if (this->m_value[i]<a.m_value[i]) //a>b
				return -1;
		}
	}
	return 0; //bottom out? then the same
}





template<typename limb_t>
ubint<limb_t> ubint<limb_t>::MultiplyAndRound(const ubint &p, const ubint &q) const {
	ubint ans(*this);
	ans *= p;
	ans = ans.DivideAndRound(q);

	return ans;
}


template<typename limb_t>
ubint<limb_t> ubint<limb_t>::DivideAndRound(const ubint &q) const {
	bool dbg_flag = false;

	//check for garbage initialization and 0 condition
	//check for garbage initialization and 0 condition
	if(q.m_state==GARBAGE)
		throw std::logic_error("DivideAndRound() Divisor uninitialised");

	if(q==0)
		throw std::logic_error("DivideAndRound() Divisor is zero");

	ubint halfQ(q>>1);
	DEBUG("halfq "<<halfQ.ToString());

	if (*this < q) {
		if (*this <= halfQ)
			return ubint(0);
		else
			return ubint(1);
	}
	//=============
	ubint ans(0);
	ubint rv(0);

	int f;

	DEBUG( "*this "<<this->ToString());
	DEBUG("q "<<q.ToString());

	f = divqr_vect(ans, rv,  *this,  q);
	if (f!= 0)
		throw std::logic_error("Divqr() error in DivideAndRound");

	ans.NormalizeLimbs();
	rv.NormalizeLimbs();

	ans.m_state = INITIALIZED;
	ans.SetMSB();
	rv.m_state = INITIALIZED;
	rv.SetMSB();
	DEBUG("ans "<<ans.ToString());
	DEBUG("rv "<<rv.ToString());


	DEBUG("ans "<<ans.ToString());
	DEBUG("rv "<<rv.ToString());


	//==============


	//Rounding operation from running remainder
	if (!(rv <= halfQ)) {
		ans += 1;
		DEBUG("added1 ans "<<ans.ToString());
	}
	return ans;

}

// helper functions convert a ubint in and out of a string of
// characters the encoding is Base64-like: the first 6 or 11 6-bit
// groupings are Base64 encoded

// precomputed shift amounts for each 6 bit chunk
static const usint b64_shifts[] = { 0, 6, 12, 18, 24, 30, 36, 42, 48, 54, 60};
static const usint B64MASK = 0x3F;

// this for encoding...mapping 0.. 2^6-1 to an ascii char
static char to_base64_char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// and this for decoding...
template<typename limb_t>
inline limb_t ubint<limb_t>::base64_to_value(const char &b64) {
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

//Serialize ubint by concatnating 6bits converted to an ascii character together, and terminating with '|'
//note modulus is ignored
template<typename limb_t>
const std::string ubint<limb_t>::SerializeToString(const ubint<limb_t>& modulus) const {
	bool dbg_flag = false;

	std::string ans = "";

	for (auto fromP = m_value.begin(); fromP!=m_value.end(); fromP++){
		DEBUG(" ser "<<std::hex<<" "<<*fromP<<std::dec);

		ans += to_base64_char[((*fromP) >> b64_shifts[0]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[1]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[2]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[3]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[4]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[5]) & B64MASK];
#ifdef UBINT_64
		ans += to_base64_char[((*fromP) >> b64_shifts[6]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[7]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[8]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[9]) & B64MASK];
		ans += to_base64_char[((*fromP) >> b64_shifts[10]) & B64MASK];
		DEBUG("UBINT_64");
#endif
	}
	ans += "|"; //mark end of word.
	DEBUG("ans ser "<<ans);
	return ans;
}

//Deserialize ubint by building limbs 6 bits at a time
//returns input cp with stripped chars for decoded myZZ
//note modulus is ignored
template<typename limb_t>
const char * ubint<limb_t>::DeserializeFromString(const char *cp, const ubint<limb_t>& modulus){
	bool dbg_flag = false;

	m_value.clear();
	while( *cp != '\0' && *cp != '|' ) {
		limb_t converted =  base64_to_value(*cp++) << b64_shifts[0];
		converted |= base64_to_value(*cp++) << b64_shifts[1];
		converted |= base64_to_value(*cp++) << b64_shifts[2];
		converted |= base64_to_value(*cp++) << b64_shifts[3];
		converted |= base64_to_value(*cp++) << b64_shifts[4];
		converted |= base64_to_value(*cp++) << b64_shifts[5];
#ifdef UBINT_64
		converted |= base64_to_value(*cp++) << b64_shifts[6];
		converted |= base64_to_value(*cp++) << b64_shifts[7];
		converted |= base64_to_value(*cp++) << b64_shifts[8];
		converted |= base64_to_value(*cp++) << b64_shifts[9];
		converted |= base64_to_value(*cp++) << b64_shifts[10];
#endif
		DEBUG(" deser "<<converted);
		DEBUG(" deser "<<std::hex<<" "<<converted<<std::dec);
		m_value.push_back(converted);

	}

	SetMSB();
	m_state = INITIALIZED;

	if (*cp == '|') {		// if end of ubint strip of separator
		cp++;
	}
	return cp;
}

template<typename limb_t>
bool ubint<limb_t>::Serialize(lbcrypto::Serialized* serObj) const{

	if( !serObj->IsObject() )
		return false;

	lbcrypto::SerialItem bbiMap(rapidjson::kObjectType);

	bbiMap.AddMember("IntegerType", IntegerTypeName(), serObj->GetAllocator());
	bbiMap.AddMember("Value", this->ToString(), serObj->GetAllocator());
	serObj->AddMember("BigIntegerImpl", bbiMap, serObj->GetAllocator());
	return true;
}

template<typename limb_t>
bool ubint<limb_t>::Deserialize(const lbcrypto::Serialized& serObj){
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
	AssignVal(vIt->value.GetString());
	return true;
}



//helper functions
template<typename limb_t>
bool ubint<limb_t>::isPowerOfTwo(const ubint& m_numToCheck){
	usint m_MSB = m_numToCheck.m_MSB;
	for(int i=m_MSB-1;i>0;i--){
		if((int)m_numToCheck.GetBitAtIndex(i) == 1){
			return false;
		}
	}
	return true;
}

template<typename limb_t>
usint ubint<limb_t>::GetDigitAtIndexForBase(usint index, usint base) const{

	usint DigitLen = ceil(log2(base));

	usint digit = 0;
	usint newIndex = 1 + (index - 1)*DigitLen;
	for (usint i = 1; i < base; i = i * 2)
	{
		digit += GetBitAtIndex(newIndex)*i;
		newIndex++;
	}
	return digit;

}

//Splits the binary string to equi sized chunks and then populates the internal array values.
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::BinaryStringToUbint(const std::string& vin){
	bool dbg_flag = false;		// if true then print dbg output
	DEBUG("BinaryStringToUbint ");
	std::string v = vin;
	// strip off leading spaces from the input string
	v.erase(0, v.find_first_not_of(' '));
	// strip off leading zeros from the input string
	v.erase(0, v.find_first_not_of('0'));

	if (v.size() == 0) {
		//caustic case of input string being all zeros
		v = "0"; //set to one zero
	}

	ubint value;
	value.m_value.clear(); //clear out all limbs
	usint len = v.length();
	usint cntr = ceilIntByUInt(len);
	std::string val;
	Dlimb_t partial_value = 0;

	for (usint i = 0; i < cntr; i++) 	  {//loop over limbs

		if (len>((i + 1)*m_limbBitLength))
			val = v.substr((len - (i + 1)*m_limbBitLength), m_limbBitLength);
		else
			val = v.substr(0, len%m_limbBitLength);
		for (usint j = 0; j < val.length(); j++){
			partial_value += std::stoi(val.substr(j, 1));
			partial_value <<= 1;
		}
		partial_value >>= 1;
		value.m_value.push_back((limb_t)partial_value);
		partial_value = 0;
	}
	value.m_MSB = (cntr - 1)*m_limbBitLength;
	value.m_MSB += GetMSBlimb_t(value.m_value.back());
	DEBUG("computed msb" << value.m_MSB);
	value.m_state = INITIALIZED;
	value.SetMSB();
	DEBUG("true msb" <<value.m_MSB);
	return value;
}

//deprecated vesion needs renaming
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::BitStringToBigInteger(const std::string& vin){
	ubint ans;
	return ans.BinaryStringToUbint(vin);
}


//Recursive Exponentiation function
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::Exp(usint p) const{
	if (p == 0) return 1;
	ubint x(*this);
	if (p == 1) return x;

	ubint tmp = x.Exp(p/2);
	if (p%2 == 0) return tmp * tmp;
	else return tmp * tmp * x;
}


//Algoritm used is shift and add
template<typename limb_t>
limb_t ubint<limb_t>::UintInBinaryToDecimal(uschar *a){
	limb_t Val = 0;
	limb_t one =1;
	for(int i=m_limbBitLength-1;i>=0;i--){
		Val+= one**(a+i);
		one<<=1;
		*(a+i)=0;
	}

	return Val;
}

//&&&

//&&&
template<typename limb_t>
void ubint<limb_t>::double_bitVal(uschar* a){

	uschar ofl=0;
	for(int i=m_numDigitInPrintval-1;i>-1;i--){
		*(a+i)<<=1;
		if(*(a+i)>9){
			*(a+i)=*(a+i)-10+ofl;
			ofl=1;
		} else {
			*(a+i)=*(a+i)+ofl;
			ofl = 0;
		}

	}
}

template<typename limb_t>
void ubint<limb_t>::add_bitVal(uschar* a,uschar b){
	uschar ofl=0;
	*(a+m_numDigitInPrintval-1)+=b;
	for(int i=m_numDigitInPrintval-1;i>-1;i--){
		*(a+i) += ofl;
		if(*(a+i)>9){
			*(a+i)=0;
			ofl=1;
		}

	}
}

//NormalizeLimbs() function
template<typename limb_t>
void ubint<limb_t>::NormalizeLimbs(void) {
	//go through the most significant limbs and pop off any zero limbs we missed
	//note, ubint = 0 must  have one limb == 0;
	for (usint i = this->m_value.size()-1; i >= 1; i--){
		if (!this->m_value.back()) {
			this->m_value.pop_back();
			//std::cout<<"popped "<<std::endl;
		} else {
			break;
		}
	}
	return ;
}



template<typename limb_t>
uschar ubint<limb_t>::GetBitAtIndex(usint index) const{
	if(index<=0){
		std::cout<<"Invalid index \n";
		return 0;
	}
	else if (index > m_MSB)
		return 0;
	limb_t result;
	int idx =ceilIntByUInt(index)-1;//idx is the index of the character array
	limb_t temp = this->m_value[idx];
	limb_t bmask_counter = index%m_limbBitLength==0? m_limbBitLength:index%m_limbBitLength;//bmask is the bit number in the 8 bit array
	limb_t bmask = 1;
	for(size_t i=1;i<bmask_counter;i++)
		bmask<<=1;//generate the bitmask number
	result = temp&bmask;//finds the bit in  bit format
	result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
	return (uschar)result;
}

template<typename limb_t>
void ubint<limb_t>::SetIntAtIndex(usint idx, limb_t value){
	if (idx >= m_value.size())
		throw std::logic_error("Index Invalid");
	this->m_value[idx] = value;
}

/*
    This method can be used to oconvert int to ubint
 */
template<typename limb_t>
ubint<limb_t> ubint<limb_t>::UsintToUbint(usint m){

	return ubint(m);

}



/* method to print out compiler constants */
template<typename limb_t>
void ubint<limb_t>::PrintIntegerConstants(void) {

	std::cout << "sizeof UINT8_C "<< sizeof (UINT8_C(1)) << std::endl;
	std::cout << "sizeof UINT16_C "<< sizeof (UINT16_C(1)) << std::endl;
	std::cout << "sizeof UINT32_C "<< sizeof (UINT32_C(1)) << std::endl;
	std::cout << "sizeof UINT64_C "<< sizeof (UINT64_C(1)) << std::endl;

	std::cout << "sizeof uint8_t "<< sizeof (uint8_t) << std::endl;
	std::cout << "sizeof uint16_t "<< sizeof (uint16_t) << std::endl;
	std::cout << "sizeof uint32_t "<< sizeof (uint32_t) << std::endl;
	std::cout << "sizeof uint64_t "<< sizeof (uint64_t) << std::endl;
#ifdef UBINT_64
	//std::cout << "sizeof UINT128_C "<< sizeof (UINT128_C(1)) << std::endl;
	//dbc commented out  unsupported on some machines
	std::cout << "sizeof uint128_t "<< sizeof (uint128_t) << std::endl;
#endif

}

template class ubint<expdtype>;

//to stream internal representation
template std::ostream& operator << <expdtype>(std::ostream& os, const std::vector<expdtype>& v);

} // namespace exp_int ends
