/*
 * @file binint.cpp This file contains the integer manipulation functionality.
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
Description:
	This class provides a class for big integers.
*/

#include "../backend.h"
#include "../../utils/serializable.h"
#include "../../utils/debug.h"

namespace cpu_int {

//MOST REQUIRED STATIC CONSTANTS INITIALIZATION

//constant static member variable initialization of m_uintBitLength which is equal to number of bits in the unit data type
//permitted values: 8,16,32
template<typename uint_type,usint BITLENGTH>
const uschar BigInteger<uint_type,BITLENGTH>::m_uintBitLength = UIntBitWidth<uint_type>::value;

template<typename uint_type,usint BITLENGTH>
const usint BigInteger<uint_type,BITLENGTH>::m_numDigitInPrintval = BITLENGTH/cpu_int::LOG2_10;

//constant static member variable initialization of m_logUintBitLength which is equal to log of number of bits in the unit data type
//permitted values: 3,4,5
template<typename uint_type,usint BITLENGTH>
const uschar BigInteger<uint_type,BITLENGTH>::m_logUintBitLength = LogDtype<uint_type>::value;

//constant static member variable initialization of m_nSize which is size of the array of unit data type
template<typename uint_type,usint BITLENGTH>
const usint BigInteger<uint_type,BITLENGTH>::m_nSize = BITLENGTH%m_uintBitLength==0 ? BITLENGTH/m_uintBitLength : BITLENGTH/m_uintBitLength + 1;

//constant static member variable initialization of m_uintMax which is maximum value of unit data type
template<typename uint_type,usint BITLENGTH>
const uint_type BigInteger<uint_type,BITLENGTH>::m_uintMax = std::numeric_limits<uint_type>::max();

// DTS:
// this seems to be the traditional "round up to the next power of two" function, except that ceilIntByUInt(0) == 1
//
// ((number+(1<<m_uintBitLength)-1)>>m_uintBitLength);
// where m_uintBitLength = 8*sizeof(uint_type)
//
//optimized ceiling function after division by number of bits in the interal data type.
template<typename uint_type,usint BITLENGTH>
uint_type BigInteger<uint_type,BITLENGTH>::ceilIntByUInt(const uint_type Number){
	//mask to perform bitwise AND
	//static uint_type mask = m_uintBitLength-1;
	uint_type mask = m_uintBitLength - 1;

	if ((Number&mask) != 0)
		return (Number >> m_logUintBitLength) + 1;
	else if (!Number)
		return 1;
	else
		return Number>>m_logUintBitLength;
}

//CONSTRUCTORS
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH>::BigInteger()
{
	memset(this->m_value, 0, sizeof(this->m_value));
	//MSB set to zero since value set to 0
	this->m_MSB = 0;

}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH>::BigInteger(uint64_t init){
	//setting the MSB
	usint msb = lbcrypto::GetMSB64(init);
	this->m_MSB = msb;

	uint_type ceilInt = ceilIntByUInt(msb);
	int i = m_nSize - 1;
	//setting the values of the array
	for(;i>= (int)(m_nSize-ceilInt);i--){
		this->m_value[i] = (uint_type)init;
		init>>=m_uintBitLength;
	}
	for(;i>=0;i--) {
		this->m_value[i] = 0;
	}
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH>::BigInteger(const std::string& str){
	//setting the array values from the string
	AssignVal(str);
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH>::BigInteger(const BigInteger& bigInteger){
	m_MSB = bigInteger.m_MSB;
	//copy array values
	for (size_t i=0; i < m_nSize; ++i) {
		m_value[i] = bigInteger.m_value[i];
	}
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH>::BigInteger(BigInteger&& bigInteger){
	m_MSB = std::move(bigInteger.m_MSB);
	for (size_t i=0; i < m_nSize; ++i) {
		m_value[i] = std::move(bigInteger.m_value[i]);
	}
}

template<typename uint_type,usint BITLENGTH>
unique_ptr<BigInteger<uint_type,BITLENGTH>> BigInteger<uint_type,BITLENGTH>::Allocator() {
	return lbcrypto::make_unique<cpu_int::BigInteger<uint_type,BITLENGTH>>();
};

/*
*Converts the BigInteger to unsigned integer or returns the first 32 bits of the BigInteger.
*Splits the BigInteger into bit length of uint data type and then uses shift and add to form the 32 bit unsigned integer.
*/
template<typename uint_type, usint BITLENGTH>
uint64_t BigInteger<uint_type, BITLENGTH>::ConvertToInt() const{
	uint64_t result = 0;

	//set num to number of equisized chunks
	usint num = 64 / m_uintBitLength;

	usint ceilInt = m_nSize - ceilIntByUInt(m_MSB);
	//copy the values by shift and add
	for (usint i = 0; i < num && (m_nSize - i - 1) >= ceilInt; i++){
		result += ((uint64_t)this->m_value[m_nSize - i - 1] << (m_uintBitLength*i));
	}
	if (this->m_MSB >= 64) {
		throw std::logic_error("Convert To Int");
		std::cerr<<"BBI::Warning ConvertToInt() Loss of precision. "<<std::endl;
		std::cerr<<"input  "<< *this<<std::endl;			
		std::cerr<<"result  "<< result<<std::endl;			
	}

	return result;
}

//Converts the BigInteger to double using the std library functions.
template<typename uint_type, usint BITLENGTH>
double BigInteger<uint_type,BITLENGTH>::ConvertToDouble() const{
	return std::stod(this->ToString());
}

template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>&  BigInteger<uint_type,BITLENGTH>::operator=(const BigInteger &rhs){

	if(this!=&rhs){
	    this->m_MSB = rhs.m_MSB;
		for (size_t i=0; i < m_nSize; ++i) {
			m_value[i] = rhs.m_value[i];
		}
	}
	
	return *this;
}

template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>&  BigInteger<uint_type,BITLENGTH>::operator=(BigInteger &&rhs){

	if(this!=&rhs){
	    this->m_MSB = std::move(rhs.m_MSB);
	    for( size_t i=0; i < m_nSize; i++ )
	    		this->m_value[i] = std::move(rhs.m_value[i]);
	}

	return *this;
}

/*
*	Left Shift is done by splitting the number of shifts into
*1. Multiple of the bit length of uint data type.
*	Shifting is done by the shifting the uint type numbers.
*2. Shifts between 1 to bit length of uint data type.
*   Shifting is done by using bit shift operations and carry over propagation.
*/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH>  BigInteger<uint_type,BITLENGTH>::LShift(usshort shift) const{

	if(this->m_MSB==0)
		return 0;

	BigInteger ans(*this);
	//check for OVERFLOW
	if((ans.m_MSB+shift) > BITLENGTH )
		throw std::logic_error("OVERFLOW");

	usint shiftByUint = shift>>m_logUintBitLength;

	usshort remShift = (shift&(m_uintBitLength-1));

	if(remShift!=0){
		uint_type endVal = m_nSize - ceilIntByUInt(m_MSB);
		uint_type oFlow = 0;
		Duint_type temp = 0;
		int i;
		// DTS- BUG FIX!!!!! (signed < unsigned(0) is always true)
		for(i=m_nSize-1;i>=static_cast<int>(endVal);i--){
			temp = ans.m_value[i];
			temp <<=remShift;
			ans.m_value[i] = (uint_type)temp + oFlow;
			oFlow = temp >> m_uintBitLength;
		}
		if(i>-1)
			ans.m_value[i] = oFlow;

		ans.m_MSB += remShift;

	}

	if(shiftByUint!=0){
		usint i= m_nSize - ceilIntByUInt(ans.m_MSB);
		for(;i<m_nSize;i++){
			ans.m_value[i-shiftByUint] = ans.m_value[i]; 
		}

		for(usint j=0;j<shiftByUint;j++)
			ans.m_value[m_nSize-1-j] = 0;

	}


	ans.m_MSB += shiftByUint*m_uintBitLength;	

	return ans;

}

/*
*	Left Shift is done by splitting the number of shifts into
*1. Multiple of the bit length of uint data type.
*	Shifting is done by the shifting the uint type numbers.
*2. Shifts between 1 to bit length of uint data type.
*   Shifting is done by using bit shift operations and carry over propagation.
*/
template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>&  BigInteger<uint_type,BITLENGTH>::LShiftEq(usshort shift){

	if(this->m_MSB==0)
		return *this;

	//first check whether shifts are possible without overflow
	if(this->m_MSB+shift > BITLENGTH)
		throw std::logic_error ("OVERFLOW");

	//calculate the no.of shifts
	usint shiftByUint = shift>>m_logUintBitLength;

	uint_type remShift = (shift&(m_uintBitLength-1));

	if(remShift!=0){

		uint_type endVal = m_nSize-ceilIntByUInt(this->m_MSB);
		uint_type oFlow = 0;
		Duint_type temp = 0;
		int i ;
		// DTS- BUG FIX!!!!! (endVal may be computed <0)
		for(i=m_nSize-1; i>= static_cast<int>(endVal); i--){
			temp = this->m_value[i];
			temp <<= remShift;
			this->m_value[i] = (uint_type)temp + oFlow;
			oFlow = temp>>m_uintBitLength;		
		}

		if(i>-1)
			this->m_value[i] = oFlow;

		this->m_MSB += remShift;

	}

	if(shiftByUint!=0){
		usint i= m_nSize-ceilIntByUInt(this->m_MSB);
		for(;i<m_nSize;i++){
			this->m_value[i-shiftByUint] = this->m_value[i]; 
		}

		for(usint i=0;i<shiftByUint;i++)
			this->m_value[m_nSize-1-i] = 0;

	}


	this->m_MSB += shiftByUint*m_uintBitLength;	

	return *this;

}

/*Right Shift is done by splitting the number of shifts into
*1. Multiple of the bit length of uint data type.
*	Shifting is done by the shifting the uint type numbers in the array to the right.
*2. Shifts between 1 to bit length of uint data type.
*   Shifting is done by using bit shift operations and carry over propagation.
*/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH>  BigInteger<uint_type,BITLENGTH>::RShift(usshort shift) const{

	//trivial cases
	if(this->m_MSB==0 || this->m_MSB <= shift)
		return BigInteger(0);
	 
	
	BigInteger ans(*this);
	//no of array shifts
	usint shiftByUint = shift>>m_logUintBitLength;
	//no of bit shifts
	uint_type remShift = (shift&(m_uintBitLength-1));

	if(shiftByUint!=0){
		//termination index counter
		usint endVal= m_nSize-ceilIntByUInt(ans.m_MSB);
		usint j= endVal;
		//array shifting operation
		for(int i= m_nSize-1-shiftByUint;i>=static_cast<int>(endVal);i--){
			ans.m_value[i+shiftByUint] = ans.m_value[i];
		}
		//msb adjusted to show the shifts
		ans.m_MSB -= shiftByUint<<m_logUintBitLength;
		//nulling the removed uints from the array
		while(shiftByUint>0){
			ans.m_value[j] = 0;
			shiftByUint--;
			j++;
		}

	}
	//bit shifts
	if(remShift!=0){

		uint_type overFlow = 0;
		uint_type oldVal;
		uint_type maskVal = ((uint_type)1<<(remShift))-1;
		uint_type compShiftVal = m_uintBitLength- remShift;

		usint startVal = m_nSize - ceilIntByUInt(ans.m_MSB);
		//perform shifting by bits by calculating the overflow
		//oveflow is added after the shifting operation
		for( ;startVal<m_nSize;startVal++){

			oldVal = ans.m_value[startVal];

			ans.m_value[startVal] = (ans.m_value[startVal]>>remShift) + overFlow;

			overFlow = (oldVal &  maskVal);
			overFlow <<= compShiftVal ;
		}

		ans.m_MSB -= remShift;

	}

	return ans;



}


/*Right Shift is done by splitting the number of shifts into
*1. Multiple of the bit length of uint data type.
*	Shifting is done by the shifting the uint type numbers in the array to the right.
*2. Shifts between 1 to bit length of uint data type.
*   Shifting is done by using bit shift operations and carry over propagation.
*/
template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>&  BigInteger<uint_type,BITLENGTH>::RShiftEq(usshort shift){

	if(this->m_MSB==0 )
		return *this;
	else if(this->m_MSB<=shift){
		*this = 0;
		return *this;
	}

	//no of array shifts
	int shiftByUint = shift>>m_logUintBitLength;
	//no of bit shifts
	uschar remShift = (shift&(m_uintBitLength-1));
	//perform shifting in arrays
	if(shiftByUint!=0){

		int endVal= m_nSize-ceilIntByUInt(this->m_MSB);
		int j= endVal;
		
		for(int i= m_nSize-1-shiftByUint; i>=endVal; i--){
			this->m_value[i+shiftByUint] = this->m_value[i];
		}
		//adjust shift to reflect left shifting 
		this->m_MSB -= shiftByUint<<m_logUintBitLength;

		while(shiftByUint>0){
			this->m_value[j] = 0;
			shiftByUint--;
			j++;
		}

		
	}

	
	//perform shift by bits if any
	if(remShift!=0){

		uint_type overFlow = 0;
		uint_type oldVal;
		uint_type maskVal = ((uint_type)1<<(remShift))-1;
		uint_type compShiftVal = m_uintBitLength- remShift;

		usint startVal = m_nSize - ceilIntByUInt(this->m_MSB);
		//shift and add the overflow from the previous position
		for( ;startVal<m_nSize;startVal++){

			oldVal = this->m_value[startVal];

			this->m_value[startVal] = (this->m_value[startVal]>>remShift) + overFlow;

			overFlow = (oldVal &  maskVal);
			overFlow <<= compShiftVal ;
		}

		this->m_MSB -= remShift;

	}

	return *this;	

}

/*
 * This function is only used for serialization
 *
 * The scheme here is to take the integer 6 bits at a time and encode it into a Base64 encoding
 * For efficiency's sake, we convert to a signed number and put in a - for negative numbers
 * We preface with a base64 encoding of the length, followed by a sign (to delineate length from number)
 */
template<typename uint_type,usint BITLENGTH>
const std::string BigInteger<uint_type,BITLENGTH>::SerializeToString(const BigInteger& modulus) const {

	// numbers go from high to low -1, -2, ... +modulus/2, modulus/2 - 1, ... ,1, 0
	bool isneg = false;
	BigInteger signedVal;
	if( modulus == 0 || *this < modulus>>1 ) // divide by 2
		signedVal = *this;
	else {
		signedVal = modulus - *this;
		isneg = true;
	}

	std::string ser = "";
	uint32_t len = signedVal.GetMSB();

	// encode len
	bool foundNum = false;
	// first two bits
	int first = len>>30;
	if( first != 0 ) {
		foundNum = true;
		ser += lbcrypto::value_to_base64( first );
	}
	for(int i=30; i>0; i-=6) {
		unsigned char b = lbcrypto::get_6bits_atoffset(len,i);
		if( b == 0 && !foundNum ) continue;
		foundNum = true;
		ser += lbcrypto::value_to_base64( b );
	}
	if( !foundNum )
		ser += lbcrypto::value_to_base64(0);

	ser += isneg ? "-" : "*"; // separate encoded len from encoded number
	for( int i=len; i>0; i-=6 )
		ser += lbcrypto::value_to_base64(signedVal.Get6BitsAtIndex(i));
	return ser;
}

template<typename uint_type, usint BITLENGTH>
const char *BigInteger<uint_type, BITLENGTH>::DeserializeFromString(const char *str, const BigInteger& modulus){

	// first decode the length
	uint32_t len = 0;

	while(true) {
		if( *str == '-' || *str == '*' ) break;
		len = len<<6 | lbcrypto::base64_to_value(*str++);
	}

	bool isneg = false;
	if( *str++ == '-' ) {
		isneg = true;
	}

	BigInteger value(0);

	for( ; len > 6 ; len -= 6 ) {
		value = (value<<6) + BigInteger(lbcrypto::base64_to_value(*str++));
	}

	if( len )
		value = (value<<len) + BigInteger(lbcrypto::base64_to_value(*str++));

	if( isneg )
		value = (modulus - value);

	*this = value;

	return str;
}


template<typename uint_type, usint BITLENGTH>
bool BigInteger<uint_type, BITLENGTH>::Serialize(lbcrypto::Serialized* serObj) const{
    
    if( !serObj->IsObject() )
      return false;
    
    lbcrypto::SerialItem bbiMap(rapidjson::kObjectType);
    
    bbiMap.AddMember("IntegerType", IntegerTypeName(), serObj->GetAllocator());
    bbiMap.AddMember("Value", this->ToString(), serObj->GetAllocator());
    serObj->AddMember("BigIntegerImpl", bbiMap, serObj->GetAllocator());
    return true;
    
  }
  
template<typename uint_type, usint BITLENGTH>
bool BigInteger<uint_type, BITLENGTH>::Deserialize(const lbcrypto::Serialized& serObj){
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
  
template<typename uint_type,usint BITLENGTH>
usint BigInteger<uint_type,BITLENGTH>::GetMSB()const{
	return m_MSB;
}

/* Addition operation:
*  Algorithm used is usual school book sum and carry-over, expect for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::Plus(const BigInteger& b) const{
	
	//two operands A and B for addition, A is the greater one, B is the smaller one
    const BigInteger* A = NULL;
	const BigInteger* B = NULL;

	//Assignment of pointers, A assigned the higher value and B assigned the lower value
	if(*this>b){
		A = this; B = &b;
	}
	else {A = &b; B = this;}

	if(B->m_MSB==0)
		return BigInteger(*A);

	BigInteger result;

	//overflow variable
	Duint_type ofl=0;
	//position from A to start addition
	uint_type ceilIntA = ceilIntByUInt(A->m_MSB);
	//position from B to start addition
	uint_type ceilIntB = ceilIntByUInt(B->m_MSB);
	size_t i;//counter
        // DTS: TODO: verify that the sign/unsigned compare is valid here. it seems to have the same form as the bugs fixed above, but i did not observe any crashes in this function (perhaps it was never exercised)
        // a safer alternative would be something like what follows (the loops i fixed above could use the same structure; note all variables become unsigned and all loop indices start from zero):
        // for (usint j = 0; j < m_nSize - CeilIntB /*&& j < m_nSize*/; ++j) {
        //    usint i = m_nSize - 1 -j ;
        //    ...
        // }
	for(i=m_nSize-1;i>=m_nSize-ceilIntB;i--){
		ofl =(Duint_type)A->m_value[i]+ (Duint_type)B->m_value[i]+ofl;//sum of the two int and the carry over
		result.m_value[i] = (uint_type)ofl;
		ofl>>=m_uintBitLength;//current overflow
	}

	if(ofl){
		for(;i>=m_nSize-ceilIntA;i--){
			ofl = (Duint_type)A->m_value[i]+ofl;//sum of the two int and the carry over
			result.m_value[i] = (uint_type)ofl;
			ofl>>=m_uintBitLength;//current overflow
		}

		if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
			result.m_value[m_nSize-ceilIntA-1] = 1;
			result.m_MSB = A->m_MSB + 1;
		}
		else{
			result.m_MSB = (m_nSize - i - 2)*m_uintBitLength;
			result.m_MSB += GetMSBUint_type(result.m_value[++i]);
		}
	}
	else{
		for(;i>=m_nSize-ceilIntA;i--){
			result.m_value[i] = A->m_value[i];
		}
		result.m_MSB =  (m_nSize - i - 2)*m_uintBitLength;
		result.m_MSB += GetMSBUint_type(result.m_value[++i]);
	}

	return result;
}

/* Addition operation:
*  Algorithm used is usual school book sum and carry-over, expect for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>& BigInteger<uint_type,BITLENGTH>::PlusEq(const BigInteger& b) {

	// edge cases of adding 0 or adding to 0
	if( b.m_MSB == 0 )
		return *this;
	if( this->m_MSB == 0 )
		return *this = b;

	//overflow variable
	Duint_type ofl=0;
	uint_type firstLoopCeil, secondLoopCeil;
	size_t i;//counter

	const BigInteger* larger = NULL;
	if( *this>b ) {
		larger = this;
		firstLoopCeil = ceilIntByUInt(b.m_MSB);
		secondLoopCeil = ceilIntByUInt(this->m_MSB);
	}
	else {
		larger = &b;
		firstLoopCeil = ceilIntByUInt(this->m_MSB);
		secondLoopCeil = ceilIntByUInt(b.m_MSB);
	}

	for( i=m_nSize-1; i>=m_nSize-firstLoopCeil; i-- ) {
		ofl =(Duint_type)this->m_value[i]+ (Duint_type)b.m_value[i]+ofl;//sum of the two int and the carry over
		this->m_value[i] = (uint_type)ofl;
		ofl>>=m_uintBitLength;//current overflow
	}

	if( ofl ) {
		for(;i>=m_nSize-secondLoopCeil;i--){
			ofl = (Duint_type)larger->m_value[i]+ofl;//sum of the two int and the carry over
			this->m_value[i] = (uint_type)ofl;
			ofl>>=m_uintBitLength;//current overflow
		}

		if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
			this->m_value[m_nSize-secondLoopCeil-1] = 1;
			this->m_MSB = larger->m_MSB + 1;
		}
		else{
			this->m_MSB = (m_nSize - i - 2)*m_uintBitLength;
			this->m_MSB += GetMSBUint_type(this->m_value[++i]);
		}
	}
	else{
		for(;i>=m_nSize-secondLoopCeil;i--){
			this->m_value[i] = larger->m_value[i];
		}
		this->m_MSB =  (m_nSize - i - 2)*m_uintBitLength;
		this->m_MSB += GetMSBUint_type(this->m_value[++i]);
	}

	return *this;
}

/* Minus operation:
*  Algorithm used is usual school book borrow and subtract, except for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::Minus(const BigInteger& b) const{

	//return 0 if b is higher than *this as there is no support for negative number
	if(!(*this>b))
		return 0;

        // DTS: note: these variables are confusing. if you look close you will find (a) they are only inside the inner if block (cntr=0 is superfluous); (b) current simply equals i (neither changes after the current=i assignment); and (c) the while loop needs to check cntr >= 0 (when m_value[] == 0...)
	int cntr=0,current=0;
	
        // DTS: (see Plus(), above) this function uses [signed] int for endValA and endValB, unlike all the similar loops in the previous functions
	BigInteger result(*this);
	//array position in A to end subtraction
	volatile int endValA = m_nSize-ceilIntByUInt(this->m_MSB);
	//array position in B to end subtraction
	int endValB = m_nSize-ceilIntByUInt(b.m_MSB);
	int i;
	for(i=m_nSize-1;i>=endValB;i--){
		//carryover condtion
		if(result.m_value[i]<b.m_value[i]){
			current=i;
			cntr = current-1;
			//assigning carryover value
			// DTS: added check against cntr being < 0 (I think)
			while(cntr>=0 && result.m_value[cntr]==0){
				result.m_value[cntr]=m_uintMax;cntr--;
			}
			// DTS: probably need to check cntr >= 0 here, too
			result.m_value[cntr]--;
			result.m_value[i]=result.m_value[i]+m_uintMax+1- b.m_value[i];		
		}
		//usual subtraction condition
		else{
			result.m_value[i]=result.m_value[i]- b.m_value[i];
		}
		cntr=0;
	}

	while(result.m_value[endValA]==0){
		endValA++;
	}
	//reset the MSB after subtraction
	result.m_MSB = (m_nSize-endValA-1)*m_uintBitLength + GetMSBUint_type(result.m_value[endValA]);

	//return the result
	return result;

}

/* Minus operation:
*  Algorithm used is usual school book borrow and subtract, except for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>& BigInteger<uint_type,BITLENGTH>::MinusEq(const BigInteger& b) {

	//return 0 if b is higher than *this as there is no support for negative number
	if(!(*this>b)) {
		*this = BigInteger(0);
		return *this;
	}

        // DTS: note: these variables are confusing. if you look close you will find (a) they are only inside the inner if block (cntr=0 is superfluous); (b) current simply equals i (neither changes after the current=i assignment); and (c) the while loop needs to check cntr >= 0 (when m_value[] == 0...)
	int cntr=0,current=0;

        // DTS: (see Plus(), above) this function uses [signed] int for endValA and endValB, unlike all the similar loops in the previous functions.

	//array position in A to end subtraction
	volatile int endValA = m_nSize-ceilIntByUInt(this->m_MSB);
	//array position in B to end subtraction
	int endValB = m_nSize-ceilIntByUInt(b.m_MSB);
	int i;
	for(i=m_nSize-1;i>=endValB;i--){
		//carryover condtion
		if(this->m_value[i]<b.m_value[i]){
			current=i;
			cntr = current-1;
			//assigning carryover value
			// DTS: added check against cntr being < 0 (I think)
			while(cntr>=0 && this->m_value[cntr]==0){
				this->m_value[cntr]=m_uintMax;cntr--;
			}
			// DTS: probably need to check cntr >= 0 here, too
			this->m_value[cntr]--;
			this->m_value[i]=this->m_value[i]+m_uintMax+1- b.m_value[i];
		}
		//usual subtraction condition
		else{
			this->m_value[i]=this->m_value[i]- b.m_value[i];
		}
		cntr=0;
	}

	while(this->m_value[endValA]==0){
		endValA++;
	}
	//reset the MSB after subtraction
	this->m_MSB = (m_nSize-endValA-1)*m_uintBitLength + GetMSBUint_type(this->m_value[endValA]);

	return *this;

}

/* Times operation:
*  Algorithm used is usual school book shift and add after multiplication, except for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type, BITLENGTH>::Times(const BigInteger& b) const {

	//if one of them is zero
	if (b.m_MSB == 0 || this->m_MSB == 0) {
		return 0;
	}

	//check for trivial conditions
	if (b.m_MSB == 1) {
		return *this;
	}
	if (this->m_MSB == 1) {
		return b;
	}
	
	BigInteger ans;

	//position of B in the array where the multiplication should start
	uint_type ceilInt = ceilIntByUInt(b.m_MSB);
	//Multiplication is done by getting a uint_type from b and multiplying it with *this
	//after multiplication the result is shifted and added to the final answer
	BigInteger temp;
	for(size_t i= m_nSize-1;i>= m_nSize-ceilInt;i--){
		this->MulByUintToInt(b.m_value[i], &temp);
		ans += temp <<= (m_nSize-1-i)*m_uintBitLength;
	}

	return ans;
}

/* Times operation:
*  Algorithm used is usual school book shift and add after multiplication, except for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>& BigInteger<uint_type, BITLENGTH>::TimesEq(const BigInteger& b) {
	*this = this->Times(b);
	return *this;
}

/* Times operation:
*  Algorithm used is usual school book multiplication.
*  This function is used in the Multiplication of two BigInteger objects
*/
template<typename uint_type,usint BITLENGTH>
void BigInteger<uint_type,BITLENGTH>::MulByUintToInt(const uint_type b, BigInteger* ans) const {
	
	if(b==0 || this->m_MSB==0) {
		*ans = 0;
		return;
	}
	
	//position in the array to start multiplication
	usint endVal = m_nSize-ceilIntByUInt(m_MSB);
	//variable to capture the overflow
	Duint_type temp=0;
	//overflow value
	uint_type ofl=0;
	size_t i= m_nSize-1;

	for(;i>=endVal ;i--){
		temp = ((Duint_type)m_value[i]*(Duint_type)b) + ofl;
		ans->m_value[i] = (uint_type)temp;
		ofl = temp>>m_uintBitLength;
	}
	//check if there is any final overflow
	if(ofl){
		ans->m_value[i]=ofl;
	}
	ans->m_MSB = (m_nSize-1-endVal)*m_uintBitLength;

	//set the MSB after the final computation
	ans->m_MSB += GetMSBDUint_type(temp);

	return;
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::MulByUint(const uint_type b) const {
	BigInteger ans;
	MulByUintToInt(b, &ans);
	return ans;
}

/* Division operation:
*  Algorithm used is usual school book long division , except for that radix is 2^m_bitLength.
*  Optimization done: Uses bit shift operation for logarithmic convergence.
*/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::DividedBy(const BigInteger& b) const{
	
	//check for the 0 condition
	if(b==0)
		throw std::logic_error("DIVISION BY ZERO");

	if(b.m_MSB>this->m_MSB)
		return 0;
	else if(b==*this)
		return 1;

	BigInteger ans;

	//normalised_dividend = result*quotient
	BigInteger normalised_dividend( this->Minus( this->Mod(b) ) );
	//Number of array elements in Divisor
	uint_type ncharInDivisor = ceilIntByUInt(b.m_MSB);
	//Number of array elements in Normalised_dividend
	uint_type ncharInNormalised_dividend = ceilIntByUInt(normalised_dividend.m_MSB);
	//variable to store the running dividend
	BigInteger running_dividend;
	//variable to store the running remainder
	BigInteger runningRemainder;
	BigInteger expectedProd;
	BigInteger estimateFinder;

	//Initialize the running dividend
	for(usint i=0;i<ncharInDivisor;i++){
		running_dividend.m_value[ m_nSize-ncharInDivisor+i] = normalised_dividend.m_value[ m_nSize-ncharInNormalised_dividend+i]; 
	}
	running_dividend.m_MSB = GetMSBUint_type(running_dividend.m_value[m_nSize-ncharInDivisor]) + (ncharInDivisor-1)*m_uintBitLength;
	
	uint_type estimate=0;
	uint_type maskBit = 0;
	uint_type shifts =0;
	usint ansCtr = m_nSize - ncharInNormalised_dividend+ncharInDivisor-1;
	//Long Division Computation to determine quotient
	for(usint i=ncharInNormalised_dividend-ncharInDivisor;;){
		//Get the remainder from the Modulus operation
		runningRemainder = running_dividend.Mod(b);
		//Compute the expected product from the running dividend and remainder
		expectedProd = running_dividend-runningRemainder;
		estimateFinder = expectedProd;
		
		estimate =0;
		
		//compute the quotient
		if(expectedProd>b){	
			while(estimateFinder.m_MSB > 0){
				/*
				if(expectedProd.m_MSB-b.m_MSB==m_uintBitLength){
					maskBit= (uint_type)1<<(m_uintBitLength-1);
				}
				else
					maskBit= (uint_type)1<<(expectedProd.m_MSB-b.m_MSB);
					*/
				shifts = estimateFinder.m_MSB-b.m_MSB;
				if(shifts==m_uintBitLength){
					maskBit= (uint_type)1<<(m_uintBitLength-1);
				}
				else
					maskBit= (uint_type)1<<(shifts);
				
				if((b.MulByUint(maskBit))>estimateFinder){
					maskBit>>=1;
					estimateFinder-= b<<(shifts-1);
				}
				else if(shifts==m_uintBitLength)
					estimateFinder-= b<<(shifts-1);
				else
					estimateFinder-= b<<shifts;
				
				estimate |= maskBit;
			}
			
		}
		else if(expectedProd.m_MSB==0)
			estimate = 0;
		else
			estimate = 1; 
		//assigning the quotient in the result array
		ans.m_value[ansCtr] = estimate;
		ansCtr++;		
		if(i==0)
			break;
		//Get the next uint element from the divisor and proceed with long division
		if(running_dividend.m_MSB==0){
			running_dividend.m_MSB=GetMSBUint_type(normalised_dividend.m_value[m_nSize-i]);
		}
		else
			running_dividend = runningRemainder<<m_uintBitLength;

		running_dividend.m_value[ m_nSize-1] = normalised_dividend.m_value[m_nSize-i];	
		if (running_dividend.m_MSB == 0)
			running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
		i--;
	}
	ansCtr = m_nSize - ncharInNormalised_dividend+ncharInDivisor-1;
	//Loop to the MSB position
	while(ans.m_value[ansCtr]==0){
		ansCtr++;
	}
	//Computation of MSB value 
	ans.m_MSB = GetMSBUint_type(ans.m_value[ansCtr]) + (m_nSize-1-ansCtr)*m_uintBitLength;

	return ans;

}

// FIXME this really doesn't divide in place...
/* Division operation:
*  Algorithm used is usual school book long division , except for that radix is 2^m_bitLength.
*  Optimization done: Uses bit shift operation for logarithmic convergence.
*/
template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>& BigInteger<uint_type,BITLENGTH>::DividedByEq(const BigInteger& b) {

	//check for the 0 condition
	if(b==0)
		throw std::logic_error("DIVISION BY ZERO");

	if(b.m_MSB>this->m_MSB) {
		*this = 0;
		return *this;
	}
	else if(b==*this) {
		*this = 1;
		return *this;
	}

	BigInteger ans;

	//normalised_dividend = result*quotient
	BigInteger normalised_dividend( this->Minus( this->Mod(b) ) );
	//Number of array elements in Divisor
	uint_type ncharInDivisor = ceilIntByUInt(b.m_MSB);
	//Number of array elements in Normalised_dividend
	uint_type ncharInNormalised_dividend = ceilIntByUInt(normalised_dividend.m_MSB);
	//variable to store the running dividend
	BigInteger running_dividend;
	//variable to store the running remainder
	BigInteger runningRemainder;
	BigInteger expectedProd;
	BigInteger estimateFinder;

	//Initialize the running dividend
	for(usint i=0;i<ncharInDivisor;i++){
		running_dividend.m_value[ m_nSize-ncharInDivisor+i] = normalised_dividend.m_value[ m_nSize-ncharInNormalised_dividend+i];
	}
	running_dividend.m_MSB = GetMSBUint_type(running_dividend.m_value[m_nSize-ncharInDivisor]) + (ncharInDivisor-1)*m_uintBitLength;

	uint_type estimate=0;
	uint_type maskBit = 0;
	uint_type shifts =0;
	usint ansCtr = m_nSize - ncharInNormalised_dividend+ncharInDivisor-1;
	//Long Division Computation to determine quotient
	for(usint i=ncharInNormalised_dividend-ncharInDivisor;;){
		//Get the remainder from the Modulus operation
		runningRemainder = running_dividend.Mod(b);
		//Compute the expected product from the running dividend and remainder
		expectedProd = running_dividend-runningRemainder;
		estimateFinder = expectedProd;

		estimate =0;

		//compute the quotient
		if(expectedProd>b){
			while(estimateFinder.m_MSB > 0){
				/*
				if(expectedProd.m_MSB-b.m_MSB==m_uintBitLength){
					maskBit= (uint_type)1<<(m_uintBitLength-1);
				}
				else
					maskBit= (uint_type)1<<(expectedProd.m_MSB-b.m_MSB);
					*/
				shifts = estimateFinder.m_MSB-b.m_MSB;
				if(shifts==m_uintBitLength){
					maskBit= (uint_type)1<<(m_uintBitLength-1);
				}
				else
					maskBit= (uint_type)1<<(shifts);

				if((b.MulByUint(maskBit))>estimateFinder){
					maskBit>>=1;
					estimateFinder-= b<<(shifts-1);
				}
				else if(shifts==m_uintBitLength)
					estimateFinder-= b<<(shifts-1);
				else
					estimateFinder-= b<<shifts;

				estimate |= maskBit;
			}

		}
		else if(expectedProd.m_MSB==0)
			estimate = 0;
		else
			estimate = 1;
		//assgning the quotient in the result array
		ans.m_value[ansCtr] = estimate;
		ansCtr++;
		if(i==0)
			break;
		//Get the next uint element from the divisor and proceed with long division
		if(running_dividend.m_MSB==0){
			running_dividend.m_MSB=GetMSBUint_type(normalised_dividend.m_value[m_nSize-i]);
		}
		else
			running_dividend = runningRemainder<<m_uintBitLength;

		running_dividend.m_value[ m_nSize-1] = normalised_dividend.m_value[m_nSize-i];
		if (running_dividend.m_MSB == 0)
			running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
		i--;
	}
	ansCtr = m_nSize - ncharInNormalised_dividend+ncharInDivisor-1;
	//Loop to the MSB position
	while(ans.m_value[ansCtr]==0){
		ansCtr++;
	}
	//Computation of MSB value
	ans.m_MSB = GetMSBUint_type(ans.m_value[ansCtr]) + (m_nSize-1-ansCtr)*m_uintBitLength;

	*this = ans;
	return *this;
}

//Initializes the array of uint_array from the string equivalent of BigInteger
//Algorithm used is repeated division by 2
//Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
template<typename uint_type,usint BITLENGTH>
void BigInteger<uint_type,BITLENGTH>::AssignVal(const std::string& v){
        bool dbg_flag = false;
	uschar *DecValue;//array of decimal values
	int arrSize=v.length();
	
	//memory allocated for decimal array
	DecValue = new uschar[arrSize];
	
	for(int i=0;i<arrSize;i++)//store the string to decimal array
		DecValue[i] = (uschar) atoi(v.substr(i,1).c_str());

	DEBUG("v=" << v);
	if( dbg_flag )
		for( int i=0;i<arrSize;i++)
			DEBUG("DecValue[" << i << "]=" << (int)DecValue[i]);

	int zptr = 0;
	//index of highest non-zero number in decimal number
	//define  bit register array
	uschar *bitArr = new uschar[m_uintBitLength]();
	
	int bitValPtr=m_nSize-1;
	//bitValPtr is a pointer to the Value char array, initially pointed to the last char
	//we increment the pointer to the next char when we get the complete value of the char array
	
	int cnt=m_uintBitLength-1;
	DEBUG("bitValPtr " << bitValPtr << " cnt " << cnt);
	//cnt8 is a pointer to the bit position in bitArr, when bitArr is complete it is ready to be transfered to Value
	while(zptr!=arrSize){
		bitArr[cnt]=DecValue[arrSize-1]%2;
		//start divide by 2 in the DecValue array
		for(int i=zptr;i<arrSize-1;i++){
			DecValue[i+1]= (DecValue[i]%2)*10 + DecValue[i+1];
			DecValue[i]>>=1;
		}
		DecValue[arrSize-1]>>=1;
		//division ends here
		cnt--;
		if(cnt==-1){//cnt = -1 indicates bitArr is ready for transfer
			if( bitValPtr < 0 )
				throw std::logic_error("string " + v + " cannot fit into BigInteger");

			cnt=m_uintBitLength-1;
			m_value[bitValPtr--]= UintInBinaryToDecimal(bitArr);//UintInBinaryToDecimal converts bitArr to decimal and resets the content of bitArr.
		}

		if(DecValue[zptr]==0)
			zptr++;//division makes Most significant digit zero, hence we increment zptr to next value
		if(zptr==arrSize && DecValue[arrSize-1]==0) {
			if( bitValPtr < 0 )
				throw std::logic_error("string " + v + " cannot fit into BigInteger");

			m_value[bitValPtr]=UintInBinaryToDecimal(bitArr);//Value assignment
		}
	}

	SetMSB(bitValPtr);
	delete []bitArr;
	delete[] DecValue;//deallocate memory

}

template<typename uint_type,usint BITLENGTH>
void BigInteger<uint_type,BITLENGTH>::SetMSB()
{

	m_MSB = 0;
	
	for(usint i=0;i<m_nSize;i++)//loops to find first nonzero number in char array
		if((Duint_type)m_value[i]!=0){
			
			m_MSB = (m_nSize-i-1)*m_uintBitLength; 
			m_MSB+= GetMSBUint_type(m_value[i]);
			break;
		}
}

//guessIdx is the index of largest uint_type number in array.
template<typename uint_type, usint BITLENGTH>
void BigInteger<uint_type, BITLENGTH>::SetMSB(usint guessIdxChar){

	m_MSB = (m_nSize - guessIdxChar - 1)*m_uintBitLength;
	m_MSB += GetMSBUint_type(m_value[guessIdxChar]);
}

template<typename uint_type, usint BITLENGTH>
void BigInteger<uint_type, BITLENGTH>::SetValue(const std::string& str){
	AssignVal(str);
}

//Algorithm used: Repeated subtraction by a multiple of modulus, which will be referred to as "Classical Modulo Reduction Algorithm"
//Complexity: O(log(*this)-log(modulus))
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::Mod(const BigInteger& modulus) const{
	//return the same value if value is less than modulus
	if(*this<modulus){
		return *this;
	}
	//masking operation if modulus is 2
	if(modulus.m_MSB==2 && modulus.m_value[m_nSize-1]==2){
		if(this->m_value[m_nSize-1]%2==0)
			return 0;
		else
			return 1;
	}
	
	Duint_type initial_shift = 0;
	//No of initial left shift that can be performed which will make it comparable to the current value.
	if(this->m_MSB > modulus.m_MSB)
		initial_shift=this->m_MSB - modulus.m_MSB -1;
	
	BigInteger j = modulus<<initial_shift;
	
	BigInteger result(*this);

	BigInteger temp;
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
			j>>=initial_shift;
		}
		else{ 
			j = modulus;
		}

	}

	return result;
}

//Algorithm used: Repeated subtraction by a multiple of modulus, which will be referred to as "Classical Modulo Reduction Algorithm"
//Complexity: O(log(*this)-log(modulus))
template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>& BigInteger<uint_type,BITLENGTH>::ModEq(const BigInteger& modulus) {
	//return the same value if value is less than modulus
	if(*this<modulus){
		return *this;
	}
	//masking operation if modulus is 2
	if(modulus.m_MSB==2 && modulus.m_value[m_nSize-1]==2){
		if(this->m_value[m_nSize-1]%2==0)
			return *this = 0;
		else
			return *this = 1;
	}

	Duint_type initial_shift = 0;
	//No of initial left shift that can be performed which will make it comparable to the current value.
	if(this->m_MSB > modulus.m_MSB)
		initial_shift=this->m_MSB - modulus.m_MSB -1;

	BigInteger j = modulus<<initial_shift;

	BigInteger temp;
	while(true){
		//exit criteria
		if(*this < modulus) break;
		if (this->m_MSB > j.m_MSB) {
			temp = j<<1;
			if (this->m_MSB == j.m_MSB + 1) {
				if(*this>temp){
					j=temp;
				}
			}
		}
		//subtracting the running remainder by a multiple of modulus
		*this -= j;

		initial_shift = j.m_MSB - this->m_MSB +1;
		if(this->m_MSB-1>=modulus.m_MSB){
			j>>=initial_shift;
		}
		else{
			j = modulus;
		}

	}

	return *this;
}

/*
Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
@article{knezevicspeeding,
  title={Speeding Up Barrett and Montgomery Modular Multiplications},
  author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
}
We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally 
proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail 
in the PhD thesis of the author published at
http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n + 3).
Generally speaking, the value of \alpha should be \ge \gamma + 1, where \gamma + n is the number of digits in the dividend.
We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3). The value of \mu
is computed by BigVector::ModMult.

*/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModBarrett(const BigInteger& modulus, const BigInteger& mu) const{
	
	if(*this<modulus){
		return BigInteger(*this);
	}
	BigInteger z(*this);
	BigInteger q(*this);

	unsigned int n = modulus.m_MSB;
	unsigned int alpha = n + 3;
	int beta = -2;

	q>>=n + beta;
	q = q*mu;
	q>>=alpha-beta;
	z-=q*modulus;
	
	if(!(z<modulus))
		z-=modulus;
	
	return z;

}

/*
In-place version of ModBarrett
Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
@article{knezevicspeeding,
title={Speeding Up Barrett and Montgomery Modular Multiplications},
author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
}
We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally
proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail
in the PhD thesis of the author published at
http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n + 3).
Generally speaking, the value of \alpha should be \ge \gamma + 1, where \gamma + n is the number of digits in the dividend.
We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3). The value of \mu
is computed by BigVector::ModMult.

*/
template<typename uint_type, usint BITLENGTH>
void BigInteger<uint_type, BITLENGTH>::ModBarrettInPlace(const BigInteger& modulus, const BigInteger& mu) {

	if (*this<modulus) {
		return;
	}

	BigInteger q(*this);

	unsigned int n = modulus.m_MSB;
	unsigned int alpha = n + 3;
	int beta = -2;

	q >>= n + beta;
	q = q*mu;
	q >>= alpha - beta;
	*this -= q*modulus;

	if (!(*this<modulus))
		*this -= modulus;

	return;

}

/*
Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
@article{knezevicspeeding,
  title={Speeding Up Barrett and Montgomery Modular Multiplications},
  author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
}
We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally 
proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail 
in the PhD thesis of the author published at
http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
We take \alpha equal to n + 3. In this case, we work with an array of precomputed \mu values.
**/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModBarrett(const BigInteger& modulus, const BigInteger mu_arr[BARRETT_LEVELS+1]) const{

	if(*this<modulus){
		BigInteger z(*this);
		return z;
	}
	BigInteger z(*this);
	BigInteger q(*this);

	usint n = modulus.m_MSB;
	//level is set to the index between 0 and BARRET_LEVELS - 1
	usint level = (this->m_MSB-1-n)*BARRETT_LEVELS/(n+1)+1;
	usint gamma = (n*level)/BARRETT_LEVELS;

	usint alpha = gamma + 3;
	int beta = -2;

	const BigInteger& mu = mu_arr[level];

	q>>=n + beta;
	q=q*mu;
	q>>=alpha-beta;
	z-=q*modulus;
	
	if(z>=modulus)
		z-=modulus;
	
	return z;

}

/*
 * in place version.
 */
template<typename uint_type,usint BITLENGTH>
void BigInteger<uint_type,BITLENGTH>::ModBarrettInPlace(const BigInteger& modulus, const BigInteger mu_arr[BARRETT_LEVELS+1]) {

	if(*this<modulus){
		return;
	}

	BigInteger q(*this);

	usint n = modulus.m_MSB;
	//level is set to the index between 0 and BARRET_LEVELS - 1
	usint level = (this->m_MSB-1-n)*BARRETT_LEVELS/(n+1)+1;
	usint gamma = (n*level)/BARRETT_LEVELS;

	usint alpha = gamma + 3;
	int beta = -2;

	const BigInteger& mu = mu_arr[level];

	q>>=n + beta;
	q=q*mu;
	q>>=alpha-beta;
	*this -= q*modulus;

	if(*this >= modulus)
		*this -= modulus;

	return;

}

//Extended Euclid algorithm used to find the multiplicative inverse
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModInverse(const BigInteger& modulus) const{
	
	BigInteger result;

	std::vector<BigInteger> mods;
	std::vector<BigInteger> quotient;
	mods.push_back(BigInteger(modulus));
	if (*this>modulus)
		mods.push_back(this->Mod(modulus));
	else
		mods.push_back(BigInteger(*this));

	BigInteger first(mods[0]);
	BigInteger second(mods[1]);
	if(mods[1]==1){
		result = 1;
		return result;
	}

	//Inverse of zero does not exist
	if(second==0)
	{
		throw std::logic_error("Zero does not have a ModInverse");
	}

	
	//NORTH ALGORITHM
	while(true){
		mods.push_back(first.Mod(second));
		quotient.push_back(first.DividedBy(second));
		if(mods.back()==1)
			break;
		if(mods.back()==0){
			std::string msg = this->ToString() + " does not have a ModInverse using " + modulus.ToString();
			throw std::logic_error(msg);
		}
		
		first = second;
		second = mods.back();
	}

	mods.clear();
	mods.push_back(0);
	mods.push_back(1);

	first = mods[0];
	second = mods[1];
	//SOUTH ALGORITHM
	for(int i=quotient.size()-1;i>=0;i--){
		mods.push_back(quotient[i]*second + first);
		first = second;
		second = mods.back();
	}

	
	if(quotient.size()%2==1){
		result = (modulus - mods.back());
	}
	else{
		result = BigInteger(mods.back());
	}

	mods.clear();
	quotient.clear();

	return result;

}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModAdd(const BigInteger& b, const BigInteger& modulus) const{
	BigInteger a(*this);
	BigInteger bb(b);

	if( a >= modulus ) a.ModEq(modulus);
	if( bb >= modulus ) bb.ModEq(modulus);
	a.PlusEq(bb);
	return a.ModEq(modulus);
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModAddFast(const BigInteger& b, const BigInteger& modulus) const{
	return this->Plus(b).Mod(modulus);
}

template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>& BigInteger<uint_type,BITLENGTH>::ModAddEq(const BigInteger& b, const BigInteger& modulus) {
	this->PlusEq(b);
	this->ModEq(modulus);
	return *this;
}

//Optimized Mod Addition using ModBarrett
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModBarrettAdd(const BigInteger& b, const BigInteger& modulus,const BigInteger mu_arr[BARRETT_LEVELS]) const{
	return this->Plus(b).ModBarrett(modulus,mu_arr);
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModBarrettAdd(const BigInteger& b, const BigInteger& modulus,const BigInteger& mu) const{
	return this->Plus(b).ModBarrett(modulus,mu);
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModSub(const BigInteger& b, const BigInteger& modulus) const{
	BigInteger a(*this);
	BigInteger b_op(b);

	//reduce this to a value lower than modulus
	if(a >= modulus){
		a.ModEq(modulus);
	}
	//reduce b to a value lower than modulus
	if(b >= modulus){
		b_op.ModEq(modulus);
	}

	if(a >= b_op){
		a.MinusEq(b_op);
		a.ModEq(modulus);
	}
	else{
		a.PlusEq(modulus);
		a.MinusEq(b_op);
	}
	return a;
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModSubFast(const BigInteger& b, const BigInteger& modulus) const{
	BigInteger a(*this);

	if(a >= b){
		a.MinusEq(b);
		a.ModEq(modulus);
	}
	else{
		a.PlusEq(modulus);
		a.MinusEq(b);
	}
	return a;
}

template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>& BigInteger<uint_type,BITLENGTH>::ModSubEq(const BigInteger& b, const BigInteger& modulus) {
	BigInteger b_op(b);

	//reduce this to a value lower than modulus
	if(*this >= modulus){
		this->ModEq(modulus);
	}
	//reduce b to a value lower than modulus
	if(b >= modulus){
		b_op.ModEq(modulus);
	}

	if(*this >= b_op){
		this->ModEq(b_op);
		this->ModEq(modulus);
	}
	else{
		this->PlusEq(modulus);
		this->MinusEq(b_op);
	}

	return *this;
}

//Optimized Mod Substraction using ModBarrett
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModBarrettSub(const BigInteger& b, const BigInteger& modulus,const BigInteger& mu) const{

	BigInteger a(*this);
	BigInteger b_op(b);

	if(*this > modulus){
		a.ModBarrettInPlace(modulus,mu);
	}

	if(b>modulus){
		b_op.ModBarrettInPlace(modulus,mu);
	}

	if(a >= b_op){
		a.MinusEq(b_op);
		a.ModBarrettInPlace(modulus,mu);
	}
	else{
		a.PlusEq(modulus);
		a.MinusEq(b_op);
	}

	return a;
}


template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModBarrettSub(const BigInteger& b, const BigInteger& modulus,const BigInteger mu_arr[BARRETT_LEVELS]) const{

	BigInteger a(*this);
	BigInteger b_op(b);

	if(*this > modulus){
		a.ModBarrettInPlace(modulus,mu_arr);
	}

	if(b>modulus){
		b_op.ModBarrettInPlace(modulus,mu_arr);
	}

	if(a >= b_op){
		a.MinusEq(b_op);
		a.ModBarrettInPlace(modulus,mu_arr);
	}
	else{
		a.PlusEq(modulus);
		a.MinusEq(b_op);
	}

	return a;
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModMul(const BigInteger& b, const BigInteger& modulus) const{
	BigInteger a(*this);
	BigInteger bb(b);

	//if a is greater than q reduce a to its mod value
	if(a >= modulus){
		a.ModEq(modulus);
	}

	//if b is greater than q reduce b to its mod value
	if(b >= modulus){
		bb.ModEq(modulus);
	}

	a.TimesEq(bb);
	return a.ModEq(modulus);
}

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModMulFast(const BigInteger& b, const BigInteger& modulus) const{
	BigInteger a(*this);

	a.TimesEq(b);
	return a.ModEq(modulus);
}

template<typename uint_type,usint BITLENGTH>
const BigInteger<uint_type,BITLENGTH>& BigInteger<uint_type,BITLENGTH>::ModMulEq(const BigInteger& b, const BigInteger& modulus) {
	BigInteger bb(b);

	//if a is greater than q reduce a to its mod value
	if(*this >= modulus){
		this->ModEq(modulus);
	}

	//if b is greater than q reduce b to its mod value
	if(b >= modulus){
		bb.ModEq(modulus);
	}

	this->TimesEq(bb);
	this->ModEq(modulus);

	return *this;
}

/*
Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
@article{knezevicspeeding,
  title={Speeding Up Barrett and Montgomery Modular Multiplications},
  author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
}
We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally 
proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail 
in the PhD thesis of the author published at
http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n + 3).
Generally speaking, the value of \alpha should be \ge \gamma + 1, where \gamma + n is the number of digits in the dividend.
We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3).

Multiplication and modulo reduction are NOT INTERLEAVED.

Potential improvements:
Our implementation makes the modulo operation essentially equivalent to two multiplications. If sparse moduli are selected, it can be replaced
with a single multiplication. The interleaved version of modular multiplication for this case is listed in Algorithm 6 of the source. 
This algorithm would most like give the biggest improvement but it sets constraints on moduli.

*/

template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModBarrettMul(const BigInteger& b, const BigInteger& modulus,const BigInteger& mu) const{

	BigInteger a(*this);
	BigInteger bb(b);

	//if a is greater than q reduce a to its mod value
	if(*this >= modulus)
		a.ModBarrettInPlace(modulus,mu);

	//if b is greater than q reduce b to its mod value
	if(b >= modulus)
		bb.ModBarrettInPlace(modulus,mu);

	a.TimesEq(bb);
	return a.ModBarrett(modulus,mu);

}


/*
In-place version of ModBarrettMul
Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
@article{knezevicspeeding,
title={Speeding Up Barrett and Montgomery Modular Multiplications},
author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
}
We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally
proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail
in the PhD thesis of the author published at
http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n + 3).
Generally speaking, the value of \alpha should be \ge \gamma + 1, where \gamma + n is the number of digits in the dividend.
We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3).

Multiplication and modulo reduction are NOT INTERLEAVED.

Potential improvements:
Our implementation makes the modulo operation essentially equivalent to two multiplications. If sparse moduli are selected, it can be replaced
with a single multiplication. The interleaved version of modular multiplication for this case is listed in Algorithm 6 of the source.
This algorithm would most like give the biggest improvement but it sets constraints on moduli.

*/

template<typename uint_type, usint BITLENGTH>
void BigInteger<uint_type, BITLENGTH>::ModBarrettMulInPlace(const BigInteger& b, const BigInteger& modulus, const BigInteger& mu) {

	BigInteger bb(b);

	//if a is greater than q reduce a to its mod value
	if (*this >= modulus)
		this->ModBarrettInPlace(modulus, mu);


	//if b is greater than q reduce b to its mod value
	if (b >= modulus)
		bb.ModBarrettInPlace(modulus, mu);

	this->TimesEq(bb);
	this->ModBarrettInPlace(modulus, mu);

	return;

}


template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModBarrettMul(const BigInteger& b, const BigInteger& modulus,const BigInteger mu_arr[BARRETT_LEVELS]) const{
	BigInteger a(*this);
	BigInteger bb(b);

	//if a is greater than q reduce a to its mod value
	if(*this >= modulus)
		a.ModBarrettInPlace(modulus,mu_arr);

	//if b is greater than q reduce b to its mod value
	if(b >= modulus)
		bb.ModBarrettInPlace(modulus,mu_arr);

	a.TimesEq(bb);
	return a.ModBarrett(modulus,mu_arr);
}

//Modular Multiplication using Square and Multiply Algorithm
//reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::ModExp(const BigInteger& b, const BigInteger& modulus) const{

	//mid is intermidiate value that calculates mid^2%q
	BigInteger mid = this->Mod(modulus);	

	//product calculates the running product of mod values
	BigInteger product(1);

	//Exp is used for spliting b to bit values/ bit extraction
	BigInteger Exp(b);

	//Precompute the Barrett mu parameter
	BigInteger temp(1);
	temp <<= 2 * modulus.GetMSB() + 3;
	BigInteger mu = temp.DividedBy(modulus);

	while(true){
		
		//product is multiplied only if bitvalue is 1
		if(Exp.m_value[m_nSize-1]%2==1){
			product = product*mid;
		}

		//running product is calculated
		if(product>modulus){
			product.ModBarrettInPlace(modulus,mu);
		}

		//divide by 2 and check even to odd to find bit value
		Exp = Exp>>1;
		if(Exp==0)break;

		//mid calculates mid^2%q
		mid = mid*mid;
		
		mid.ModBarrettInPlace(modulus,mu);
	}

	return product;

}

template<typename uint_type,usint BITLENGTH>
const std::string BigInteger<uint_type,BITLENGTH>::ToString() const {

	//this string object will store this BigInteger's value
	std::string bbiString;

	usint counter;

	//print_VALUE array stores the decimal value in the array
	uschar *print_VALUE = new uschar[m_numDigitInPrintval];

	//reset to zero
	for(size_t i=0;i<m_numDigitInPrintval;i++)
		*(print_VALUE+i)=0;

	//starts the conversion from base r to decimal value
	for(size_t i=this->m_MSB;i>0;i--){

		//print_VALUE = print_VALUE*2
		BigInteger<uint_type,BITLENGTH>::double_bitVal(print_VALUE);	

		//adds the bit value to the print_VALUE
		BigInteger<uint_type,BITLENGTH>::add_bitVal(print_VALUE,this->GetBitAtIndex(i));


	}

	//find the first occurrence of non-zero value in print_VALUE
	for(counter=0;counter<m_numDigitInPrintval-1;counter++){
		if((int)print_VALUE[counter]!=0)break;
	}

	//append this BigInteger's digits to this method's returned string object
	for (; counter < m_numDigitInPrintval; counter++) {
		bbiString += std::to_string(print_VALUE[counter]);
	}

	delete [] print_VALUE;

	return bbiString;
}

//Compares the current object with the BigInteger a.
//Uses MSB comparision to output requisite value.
template<typename uint_type,usint BITLENGTH>
int BigInteger<uint_type,BITLENGTH>::Compare(const BigInteger& a) const
{

	if(this->m_MSB<a.m_MSB)
		return -1;
	else if(this->m_MSB>a.m_MSB)
		return 1;
	if(this->m_MSB==a.m_MSB){
		uschar ceilInt = ceilIntByUInt(this->m_MSB); 
		for(usint i=m_nSize-ceilInt;i< m_nSize;i++) {
			auto testChar = int64_t(this->m_value[i]) - int64_t(a.m_value[i]) ;
			if(testChar<0) return -1;
			else if(testChar>0) return 1;
		}
	}

	return 0;
}

template<typename uint_type,usint BITLENGTH>
bool BigInteger<uint_type,BITLENGTH>::CheckIfPowerOfTwo(const BigInteger& m_numToCheck){
	usint m_MSB = m_numToCheck.m_MSB;
	for(int i=m_MSB-1;i>0;i--){
		if((int)m_numToCheck.GetBitAtIndex(i)==1){
			return false;
		}
	}
	return true;
}

template<typename uint_type,usint BITLENGTH>
usint BigInteger<uint_type,BITLENGTH>::GetMSBUint_type(uint_type x){
	return lbcrypto::GetMSB64(x);
}

template<typename uint_type,usint BITLENGTH>
usint BigInteger<uint_type,BITLENGTH>::GetDigitAtIndexForBase(usint index, usint base) const{

	bool dbg_flag = false;
	DEBUG("BigInteger::GetDigitAtIndexForBase:  index = " << index << ", base = " << base);
	usint DigitLen = ceil(log2(base));

	usint digit = 0;
	usint newIndex = 1 + (index - 1)*DigitLen;
	for (usint i = 1; i < base; i = i * 2)
	{
		digit += GetBitAtIndex(newIndex)*i;
		newIndex++;
	}
	DEBUG("digit = " << digit);
	return digit;
}

template<typename uint_type, usint BITLENGTH>
BigInteger<uint_type, BITLENGTH> BigInteger<uint_type, BITLENGTH>::BitStringToBigInteger(const std::string& bitString) {

	BigInteger value;
	usint len = bitString.length();
	usint cntr = ceilIntByUInt(len);
	std::string val;
	Duint_type partial_value = 0;
	for (usint i = 0; i < cntr; i++)
	{
		//if (len >((i + 1)*m_uintBitLength)) // before the fix
		if (len >= ((i + 1)*m_uintBitLength)) // modified -- the fix by ES
			val = bitString.substr((len - (i + 1)*m_uintBitLength), m_uintBitLength);
		else
			val = bitString.substr(0, len%m_uintBitLength);
		for (usint j = 0; j < val.length(); j++) {
			partial_value += std::stoi(val.substr(j, 1));
			partial_value <<= 1;
		}
		partial_value >>= 1;
		value.m_value[m_nSize - 1 - i] = (uint_type)partial_value;
		partial_value = 0;
	}
	/* Fix by ES */
	usint i = m_nSize - cntr;
	while (GetMSBUint_type(value.m_value[i]) == 0 && i<m_nSize - 1)
		i++;
	value.m_MSB = GetMSBUint_type(value.m_value[i]);
	value.m_MSB += (m_uintBitLength*(m_nSize - i - 1));
	/* ES fix ends here */

	/* Original code */
	/*value.m_MSB = (cntr - 1)*m_uintBitLength;
	value.m_MSB += GetMSBUint_type(value.m_value[m_nSize - cntr]);*/
	/* Ends here */

	return value;
}


//Recursive Exponentiation function
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::Exp(usint p) const{
	if (p == 0) return 1;
	BigInteger x(*this);
  	if (p == 1) return x;

	BigInteger tmp = x.Exp(p/2);
	if (p%2 == 0) return tmp * tmp;
	else return tmp * tmp * x;
}

template<typename uint_type, usint BITLENGTH>
BigInteger<uint_type, BITLENGTH> BigInteger<uint_type, BITLENGTH>::MultiplyAndRound(const BigInteger &p, const BigInteger &q) const {
	BigInteger ans(*this);
	ans = ans*p;
	ans = ans.DivideAndRound(q);

	return ans;
}

template<typename uint_type, usint BITLENGTH>
BigInteger<uint_type, BITLENGTH> BigInteger<uint_type, BITLENGTH>::DivideAndRound(const BigInteger &q) const {

	//check for garbage initialization and 0 condition
	if (q == 0)
		throw std::logic_error("DIVISION BY ZERO");

	BigInteger halfQ(q>>1);

	if (*this < q) {
		if (*this <= halfQ)
			return 0;
		else
			return 1;
	}

	BigInteger ans;

	//normalised_dividend = result*quotient
	BigInteger normalised_dividend(*this);
	//Number of array elements in Divisor
	uint_type ncharInDivisor = ceilIntByUInt(q.m_MSB);
	//Number of array elements in Normalised_dividend
	uint_type ncharInNormalised_dividend = ceilIntByUInt(normalised_dividend.m_MSB);
	//variable to store the running dividend
	BigInteger running_dividend;
	//variable to store the running remainder
	BigInteger runningRemainder;
	BigInteger expectedProd;
	BigInteger estimateFinder;

	//Initialize the running dividend
	for (usint i = 0; i<ncharInDivisor; i++) {
		running_dividend.m_value[m_nSize - ncharInDivisor + i] = normalised_dividend.m_value[m_nSize - ncharInNormalised_dividend + i];
	}
	running_dividend.m_MSB = GetMSBUint_type(running_dividend.m_value[m_nSize - ncharInDivisor]) + (ncharInDivisor - 1)*m_uintBitLength;

	uint_type estimate = 0;
	uint_type maskBit = 0;
	uint_type shifts = 0;
	usint ansCtr = m_nSize - ncharInNormalised_dividend + ncharInDivisor - 1;
	//Long Division Computation to determine quotient
	for (usint i = ncharInNormalised_dividend - ncharInDivisor;;) {
		//Get the remainder from the Modulus operation
		runningRemainder = running_dividend.Mod(q);
		//Compute the expected product from the running dividend and remainder
		expectedProd = running_dividend - runningRemainder;
		estimateFinder = expectedProd;
		
		estimate = 0;

		//compute the quotient
		if (expectedProd>q) {
			while (estimateFinder.m_MSB > 0) {
				/*
				if(expectedProd.m_MSB-b.m_MSB==m_uintBitLength){
				maskBit= (uint_type)1<<(m_uintBitLength-1);
				}
				else
				maskBit= (uint_type)1<<(expectedProd.m_MSB-b.m_MSB);
				*/
				shifts = estimateFinder.m_MSB - q.m_MSB;
				if (shifts == m_uintBitLength) {
					maskBit = 1 << (m_uintBitLength - 1);
				}
				else
					maskBit = 1 << (shifts);

				if ((q.MulByUint(maskBit))>estimateFinder) {
					maskBit >>= 1;
					estimateFinder -= q << (shifts - 1);
				}
				else if (shifts == m_uintBitLength)
					estimateFinder -= q << (shifts - 1);
				else
					estimateFinder -= q << shifts;

				estimate |= maskBit;
			}

		}
		else if (expectedProd.m_MSB == 0)
			estimate = 0;
		else
			estimate = 1;
		//assgning the quotient in the result array
		ans.m_value[ansCtr] = estimate;
		ansCtr++;
		if (i == 0)
			break;
		//Get the next uint element from the divisor and proceed with long division
		if (running_dividend.m_MSB == 0) {
			running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
		}
		else
			running_dividend = runningRemainder << m_uintBitLength;

		running_dividend.m_value[m_nSize - 1] = normalised_dividend.m_value[m_nSize - i];
		if (running_dividend.m_MSB == 0)
			running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
		i--;
	}
	ansCtr = m_nSize - ncharInNormalised_dividend + ncharInDivisor - 1;
	//Loop to the MSB position
	while (ans.m_value[ansCtr] == 0) {
		ansCtr++;
	}
	//Computation of MSB value 
	ans.m_MSB = GetMSBUint_type(ans.m_value[ansCtr]) + (m_nSize - 1 - ansCtr)*m_uintBitLength;

	//Rounding operation from running remainder
	if (!(runningRemainder <= halfQ)){
		ans += 1;
	}

	return ans;

}

template<typename uint_type,usint BITLENGTH>
usint BigInteger<uint_type,BITLENGTH>::GetMSBDUint_type(Duint_type x){
	return lbcrypto::GetMSB64(x);
}

//Algoritm used is shift and add
template<typename uint_type,usint BITLENGTH>
 uint_type BigInteger<uint_type,BITLENGTH>::UintInBinaryToDecimal(uschar *a){
	 uint_type Val = 0;
	 uint_type one =1;
	 for(int i=m_uintBitLength-1;i>=0;i--){
		 Val+= one**(a+i);
		 one<<=1;
		 *(a+i)=0;
	 }

	 return Val;
 }

 
 template<typename uint_type,usint BITLENGTH>
 void BigInteger<uint_type,BITLENGTH>::double_bitVal(uschar* a){
	
	uschar ofl=0;
	for(int i=m_numDigitInPrintval-1;i>-1;i--){
		*(a+i)<<=1;
		if(*(a+i)>9){
			*(a+i)=*(a+i)-10+ofl;
			ofl=1;
		}
		else{
			*(a+i)=*(a+i)+ofl;
			ofl = 0;
		}

	}
 }

 template<typename uint_type,usint BITLENGTH>
 void BigInteger<uint_type,BITLENGTH>::add_bitVal(uschar* a,uschar b){
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

template<typename uint_type,usint BITLENGTH>
uschar BigInteger<uint_type,BITLENGTH>::GetBitAtIndex(usint index) const{
	bool dbg_flag = false;

	DEBUG("BigInteger::GetBitAtIndex(" << index << ")");
	if(index<=0){
		return 0;
	}
	else if (index > m_MSB)
		return 0;
	uint_type result;
	int idx = m_nSize - ceilIntByUInt(index);//idx is the index of the character array
	uint_type temp = this->m_value[idx];
	uint_type bmask_counter = index%m_uintBitLength==0? m_uintBitLength:index%m_uintBitLength;//bmask is the bit number in the 8 bit array
	uint_type bmask = 1;
	for(size_t i=1;i<bmask_counter;i++)
		bmask<<=1;//generate the bitmask number
	DEBUG("temp = " << temp << ", bmask_counter = " << bmask_counter
	      << ", bmask = " << bmask);
	result = temp&bmask;//finds the bit in  bit format
	DEBUG("result = " << result);
	result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
	DEBUG("result = " << result);
	return (uschar)result;
}

template<typename uint_type,usint BITLENGTH>
uschar BigInteger<uint_type,BITLENGTH>::Get6BitsAtIndex(usint index) const{
	if(index == 0 || index > m_MSB ) {
		return 0;
	}

	uint_type result;
	int idx = m_nSize - ceilIntByUInt(index);	//idx is the slot holding the first bit
	uint_type temp = this->m_value[idx];

	uint_type bmask_counter = index%m_uintBitLength==0? m_uintBitLength:index%m_uintBitLength;
	uint_type bmask = 0x3f;

	if( bmask_counter >= 6 ) {
		result = temp&(bmask<<(bmask_counter-6));
		result >>= (bmask_counter-6); //shift the answer all the way back over
	} else {
		// some bits are in here, some bits are in the next guy...
		if( index <= bmask_counter ) {
			// i just want the last index bits
			result = this->m_value[idx] & (bmask >> (6-index));
		}
		else {
			result = temp&(bmask>>(6-bmask_counter));
			result <<= (6-bmask_counter);
			// get bits from the next slot
			uint_type otherbits = this->m_value[idx+1];
			uint_type oresult = (otherbits>>(m_uintBitLength-6+bmask_counter)) & bmask;
			result |= oresult;
		}
	}

	return (uschar)result;
}


template<typename uint_type, usint BITLENGTH>
void BigInteger<uint_type, BITLENGTH>::SetIntAtIndex(usint idx, uint_type value){
	if (idx >= m_nSize)
		throw std::logic_error("Index Invalid");
	this->m_value[idx] = value;
}

/*
	This method can be used to convert int to BigInteger
*/
template<typename uint_type,usint BITLENGTH>
BigInteger<uint_type,BITLENGTH> BigInteger<uint_type,BITLENGTH>::intToBigInteger(usint m){

	return BigInteger(m);

}

template class BigInteger<integral_dtype,BigIntegerBitLength>;
} // namespace cpu_int ends
