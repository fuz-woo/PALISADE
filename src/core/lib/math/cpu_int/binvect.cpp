/*
 * @file binvect.cpp This file contains the vector manipulation functionality.
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
	This code provides basic arithmetic functionality.

*/

#include "../../utils/serializable.h"
#include "../cpu_int/binvect.h"
#include "../nbtheory.h"
#include "../../utils/debug.h"


namespace cpu_int {

//CTORS
template<class IntegerType>
BigVectorImpl<IntegerType>::BigVectorImpl(){
	this->m_length = 0;
	//this->m_modulus;
	m_data = NULL;
}

template<class IntegerType>
BigVectorImpl<IntegerType>::BigVectorImpl(usint length){
	this->m_length = length;
	//this->m_modulus;
	this->m_data = new IntegerType[m_length] ();
}

template<class IntegerType>
BigVectorImpl<IntegerType>::BigVectorImpl(usint length, const IntegerType& modulus){
	this->m_length = length;
	this->m_modulus = modulus;
	this->m_data = new IntegerType[m_length] ();
}

template<class IntegerType>
BigVectorImpl<IntegerType>::BigVectorImpl(usint length, const IntegerType& modulus, std::initializer_list<usint> rhs){
	this->m_length = length;
	this->m_modulus = modulus;
	this->m_data = new IntegerType[m_length] ();
	usint len = rhs.size();
	for (usint i=0;i<m_length;i++){ // this loops over each entry
		if(i<len) {
			m_data[i] =  IntegerType(*(rhs.begin()+i));  
		} else {
			m_data[i] = IntegerType::ZERO;
		}
	}

}

template<class IntegerType>
BigVectorImpl<IntegerType>::BigVectorImpl(usint length, const IntegerType& modulus, std::initializer_list<std::string> rhs){
	this->m_length = length;
	this->m_modulus = modulus;
	this->m_data = new IntegerType[m_length] ();
	usint len = rhs.size();
	for(usint i=0;i<m_length;i++){ // this loops over each entry
		if(i<len) {
			m_data[i] =  IntegerType(*(rhs.begin()+i));  
		} else {
			m_data[i] = IntegerType::ZERO;
		}
	}
}

template<class IntegerType>
BigVectorImpl<IntegerType>::BigVectorImpl(const BigVectorImpl &bigVector){

	m_length = bigVector.m_length;
	m_modulus = bigVector.m_modulus;
	m_data = new IntegerType[m_length];
	for(usint i=0;i<m_length;i++){
		m_data[i] = bigVector.m_data[i];
	}

}

template<class IntegerType>
BigVectorImpl<IntegerType>::BigVectorImpl(BigVectorImpl &&bigVector){
	m_data = bigVector.m_data;
	m_length = bigVector.m_length;
	m_modulus = bigVector.m_modulus;
	bigVector.m_data = NULL;
}

//ASSIGNMENT OPERATOR
template<class IntegerType>
const BigVectorImpl<IntegerType>& BigVectorImpl<IntegerType>::operator=(const BigVectorImpl &rhs){
	if(this!=&rhs){
		if(this->m_length==rhs.m_length){
			for (usint i = 0; i < m_length; i++){
				this->m_data[i] = rhs.m_data[i];
			}
		}
		else{
			//throw std::logic_error("Trying to copy vectors of different size");
			delete [] m_data;
			m_length = rhs.m_length;
			m_modulus = rhs.m_modulus;
			m_data = new IntegerType[m_length];
			for (usint i = 0; i < m_length; i++){
				m_data[i] = rhs.m_data[i];
			}
		}
		this->m_modulus = rhs.m_modulus;
	}

	return *this;
}

template<class IntegerType>
const BigVectorImpl<IntegerType>& BigVectorImpl<IntegerType>::operator=(std::initializer_list<sint> rhs){
	usint len = rhs.size();
	for(usint i=0;i<m_length;i++){ // this loops over each tower
		if(i<len) {
			m_data[i] = IntegerType(*(rhs.begin()+i));
		} else {
			m_data[i] = 0;
		}
	}

	return *this;
}

template<class IntegerType>
const BigVectorImpl<IntegerType>& BigVectorImpl<IntegerType>::operator=(std::initializer_list<std::string> rhs){
        bool dbg_flag = false;
	usint len = rhs.size();
	for(usint i=0;i<m_length;i++){ // this loops over each tower
		if(i<len) {
			m_data[i] = IntegerType(*(rhs.begin()+i));
		} else {
			m_data[i] = 0;
		}
		DEBUG("in op= i.l. m_data["<<i<<"] = "<<m_data[i]);
	}

	return *this;
}

template<class IntegerType>
BigVectorImpl<IntegerType>& BigVectorImpl<IntegerType>::operator=(BigVectorImpl &&rhs){

	if(this!=&rhs){

		delete [] m_data;
		m_data = rhs.m_data;
		m_length = rhs.m_length;
		m_modulus = rhs.m_modulus;
		rhs.m_data = NULL;
	}

	return *this;

}

template<class IntegerType>
BigVectorImpl<IntegerType>::~BigVectorImpl(){
	//std::cout<<"destructor called for vector of size: "<<this->m_length<<"  "<<std::endl;
	delete [] m_data;
}

//ACCESSORS
template<class IntegerType_c>
std::ostream& operator<<(std::ostream& os, const BigVectorImpl<IntegerType_c> &ptr_obj){
        auto len = ptr_obj.m_length;
        os<<"[";
	for(usint i=0;i<len;i++){
	  os<< ptr_obj.m_data[i];
	  os << ((i == (len-1))?"]":" ");
	}
	return os;
}

template<class IntegerType>
void BigVectorImpl<IntegerType>::SetModulus(const IntegerType& value){
	this->m_modulus = value;
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
template<class IntegerType>
void BigVectorImpl<IntegerType>::SwitchModulus(const IntegerType& newModulus) {
    bool dbg_flag = false;
    DEBUG("Switch modulus old mod :"<<this->m_modulus);
    DEBUG("Switch modulus old this :"<<*this);
	
	IntegerType oldModulus(this->m_modulus);
	IntegerType n;
	IntegerType oldModulusByTwo(oldModulus>>1);
	IntegerType diff ((oldModulus > newModulus) ? (oldModulus-newModulus) : (newModulus - oldModulus));
	DEBUG("Switch modulus diff :"<<diff);
	for(usint i=0; i< this->m_length; i++) {
		n = this->GetValAtIndex(i);
		DEBUG("i,n "<<i<<" "<< n);
		if(oldModulus < newModulus) {
			if(n > oldModulusByTwo) {
			  DEBUG("s1 "<<n.ModAdd(diff, newModulus));
				this->SetValAtIndex(i, n.ModAdd(diff, newModulus));
			} else {
			  DEBUG("s2 "<<n.Mod(newModulus));
				this->SetValAtIndex(i, n.Mod(newModulus));
			}
		} else {
			if(n > oldModulusByTwo) {
			  DEBUG("s3 "<<n.ModSub(diff, newModulus));				
				this->SetValAtIndex(i, n.ModSub(diff, newModulus));
			} else {
			  DEBUG("s4 "<<n.Mod(newModulus));
				this->SetValAtIndex(i, n.Mod(newModulus));
			}
		}
	}
	DEBUG("Switch modulus this before set :"<<*this);
	this->SetModulus(newModulus);
	DEBUG("Switch modulus new modulus :"<<this->m_modulus);
	DEBUG("Switch modulus new this :"<<*this);

}

template<class IntegerType>
const IntegerType& BigVectorImpl<IntegerType>::GetModulus() const{

	return this->m_modulus;

}


template<class IntegerType>
usint BigVectorImpl<IntegerType>::GetLength() const{
	return this->m_length;
}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::Mod(const IntegerType& modulus) const{

	//BigVectorImpl ans(*this);

	//for(usint i=0;i<this->m_length;i++){
	//	ans.m_data[i] = ans.m_data[i].Mod(modulus);
	//}
	//return ans;

	if (modulus==2)
		return this->ModByTwo();
	else 
	{
		BigVectorImpl ans(this->GetLength(),this->GetModulus());
		IntegerType halfQ(this->GetModulus() >> 1);
		for (usint i = 0; i<ans.GetLength(); i++) {
			if (this->GetValAtIndex(i)>halfQ) {
				ans.SetValAtIndex(i,this->GetValAtIndex(i).ModSub(this->GetModulus(),modulus));
			}
			else {
				ans.SetValAtIndex(i,this->GetValAtIndex(i).Mod(modulus));
			}
		}
		return ans;
	}

}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModAddAtIndex(usint i, const IntegerType &b) const{
	if(i > this->GetLength()-1) {
		std::string errMsg = "binvect::ModAddAtIndex. Index is out of range. i = " + std::to_string(i);
		throw std::runtime_error(errMsg);
	}
	BigVectorImpl ans(*this);
	ans.m_data[i] = ans.m_data[i].ModAdd(b, this->m_modulus);
	return ans;
}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModAdd(const IntegerType &b) const{
	BigVectorImpl ans(*this);
	for(usint i=0;i<this->m_length;i++){
		ans.m_data[i] = ans.m_data[i].ModAdd(b, this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModSub(const IntegerType &b) const{
	BigVectorImpl ans(*this);

	for(usint i=0;i<this->m_length;i++){
		ans.m_data[i] = ans.m_data[i].ModSub(b,this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::MultiplyAndRound(const IntegerType &p, const IntegerType &q) const {

	//BigVectorImpl ans(this->GetLength(), this->GetModulus());
	//IntegerType halfQ(this->GetModulus() >> 1);
	//for (usint i = 0; i<ans.GetLength(); i++) {
	//	if (this->GetValAtIndex(i)>halfQ) {
	//		ans.SetValAtIndex(i, this->GetValAtIndex(i).ModSub(this->GetModulus(), modulus));
	//	}
	//	else {
	//		ans.SetValAtIndex(i, this->GetValAtIndex(i).Mod(modulus));
	//	}
	//}
	//return ans;

	BigVectorImpl ans(*this);
	IntegerType halfQ(this->m_modulus >> 1);
	for(usint i=0;i<this->m_length;i++){
		if (ans.m_data[i] > halfQ) {
			IntegerType temp = this->m_modulus - ans.m_data[i];
			ans.m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
		}
		else
			ans.m_data[i] = ans.m_data[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::DivideAndRound(const IntegerType &q) const {
	BigVectorImpl ans(*this);
	for(usint i=0;i<this->m_length;i++){
		ans.m_data[i] = ans.m_data[i].DivideAndRound(q);
	}
	return ans;
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

Potential improvements:
1. When working with MATHBACKEND = 1, we tried to compute an evenly distributed array of \mu (the number is approximately equal
to the number BARRET_LEVELS) but that did not give any performance improvement. So using one pre-computed value of 
\mu was the most efficient option at the time.
2. We also tried "Interleaved digit-serial modular multiplication with generalized Barrett reduction" Algorithm 3 in the Source but it 
was slower with MATHBACKEND = 1.
3. Our implementation makes the modulo operation essentially equivalent to two multiplications. If sparse moduli are selected, it can be replaced
with a single multiplication. The interleaved version of modular multiplication for this case is listed in Algorithm 6 of the source. 
This algorithm would most like give the biggest improvement but it sets constraints on moduli.

*/
template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModMul(const IntegerType &b) const{
	//std::cout<< "Printing Modulus: "<< m_modulus<< std::endl;

	BigVectorImpl ans(*this);

	//Precompute the Barrett mu parameter
	IntegerType mu = lbcrypto::ComputeMu<IntegerType>(m_modulus);

	for(usint i=0;i<this->m_length;i++){
		//std::cout<< "before data: "<< ans.m_data[i]<< std::endl;
		ans.m_data[i].ModBarrettMulInPlace(b,this->m_modulus,mu);
		//std::cout<< "after data: "<< ans.m_data[i]<< std::endl;
	}

	return ans;
}



template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModExp(const IntegerType &b) const{
	BigVectorImpl ans(*this);
	for(usint i=0;i<this->m_length;i++){
		ans.m_data[i] = ans.m_data[i].ModExp(b,this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModInverse() const{

	BigVectorImpl ans(*this);
	//std::cout << ans << std::endl;
	for(usint i=0;i<this->m_length;i++){
		//std::cout << ans.m_data[i] << std::endl;
		//ans.m_data[i].PrintValueInDec();
		ans.m_data[i] = ans.m_data[i].ModInverse(this->m_modulus);
	}
	return ans;

}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModAdd(const BigVectorImpl &b) const{

	if((this->m_length!=b.m_length) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModAdd called on BigVectorImpl's with different parameters.");
	}

	BigVectorImpl ans(*this);

	for(usint i=0;i<ans.m_length;i++){
		ans.m_data[i] = ans.m_data[i].ModAdd(b.m_data[i],this->m_modulus);
	}
	return ans;

}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModSub(const BigVectorImpl &b) const{

	if((this->m_length!=b.m_length) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModSub called on BigVectorImpl's with different parameters.");
	}

	BigVectorImpl ans(*this);

	for(usint i=0;i<ans.m_length;i++){
		ans.m_data[i] = ans.m_data[i].ModSub(b.m_data[i],this->m_modulus);
	}
	return ans;

}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModByTwo() const {

	BigVectorImpl ans(this->GetLength(),this->GetModulus());
	IntegerType halfQ(this->GetModulus() >> 1);
	for (usint i = 0; i<ans.GetLength(); i++) {
		if (this->GetValAtIndex(i)>halfQ) {
			if (this->GetValAtIndex(i).Mod(2) == 1)
				ans.SetValAtIndex(i, IntegerType(0));
			else
				ans.SetValAtIndex(i, 1);
		}
		else {
			if (this->GetValAtIndex(i).Mod(2) == 1)
				ans.SetValAtIndex(i, 1);
			else
				ans.SetValAtIndex(i, IntegerType(0));
		}

	}
	return ans;
}

template<class IntegerType>
const BigVectorImpl<IntegerType>& BigVectorImpl<IntegerType>::operator+=(const BigVectorImpl &b) {

	if((this->m_length!=b.m_length) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("operator+= called on BigVectorImpl's with different parameters.");
	}

	for(usint i=0;i<this->m_length;i++){
		this->m_data[i] = this->m_data[i].ModAdd(b.m_data[i],this->m_modulus);
	}
	return *this;

}

template<class IntegerType>
const BigVectorImpl<IntegerType>& BigVectorImpl<IntegerType>::operator-=(const BigVectorImpl &b) {

	if((this->m_length!=b.m_length) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("operator-= called on BigVectorImpl's with different parameters.");
	}

	for(usint i=0;i<this->m_length;i++){
		this->m_data[i] = this->m_data[i].ModSub(b.m_data[i],this->m_modulus);
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
We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3).

Potential improvements:
1. When working with MATHBACKEND = 1, we tried to compute an evenly distributed array of \mu (the number is approximately equal
to the number BARRET_LEVELS) but that did not give any performance improvement. So using one pre-computed value of 
\mu was the most efficient option at the time.
2. We also tried "Interleaved digit-serial modular multiplication with generalized Barrett reduction" Algorithm 3 in the Source but it 
was slower with MATHBACKEND = 1.
3. Our implementation makes the modulo operation essentially equivalent to two multiplications. If sparse moduli are selected, it can be replaced
with a single multiplication. The interleaved version of modular multiplication for this case is listed in Algorithm 6 of the source. 
This algorithm would most like give the biggest improvement but it sets constraints on moduli.

*/
template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::ModMul(const BigVectorImpl &b) const{

	if((this->m_length!=b.m_length) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModMul called on BigVectorImpl's with different parameters.");
	}

	BigVectorImpl ans(*this);

	//Precompute the Barrett mu parameter
	IntegerType mu = lbcrypto::ComputeMu<IntegerType>(this->GetModulus());

	for(usint i=0;i<ans.m_length;i++){
		//ans.m_data[i] = ans.m_data[i].ModMul(b.m_data[i],this->m_modulus);
		ans.m_data[i].ModBarrettMulInPlace(b.m_data[i],this->m_modulus,mu);
	}
	return ans;
}

template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::MultWithOutMod(const BigVectorImpl &b) const {

	if ((this->m_length != b.m_length) || this->m_modulus != b.m_modulus) {
        throw std::logic_error("ModMul called on BigVectorImpl's with different parameters.");
	}

	BigVectorImpl ans(*this);

	for (usint i = 0; i<ans.m_length; i++) {
		ans.m_data[i] = ans.m_data[i] * b.m_data[i];
	}
	return ans;
}

//Gets the ind
template<class IntegerType>
BigVectorImpl<IntegerType> BigVectorImpl<IntegerType>::GetDigitAtIndexForBase(usint index, usint base) const{
	BigVectorImpl ans(*this);
	for(usint i=0;i<this->m_length;i++){
		ans.m_data[i] = IntegerType(ans.m_data[i].GetDigitAtIndexForBase(index,base));
	}

	return ans;
}

// Serialize Operation
template<class IntegerType>
bool BigVectorImpl<IntegerType>::Serialize(lbcrypto::Serialized* serObj) const {

	if( !serObj->IsObject() )
		return false;

	lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);

	bbvMap.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator());
	bbvMap.AddMember("IntegerType", IntegerType::IntegerTypeName(), serObj->GetAllocator());

	usint pkVectorLength = this->GetLength();
	bbvMap.AddMember("Length", std::to_string(pkVectorLength), serObj->GetAllocator());

	if( pkVectorLength > 0 ) {
		std::string pkBufferString = "";
		for (size_t i = 0; i < pkVectorLength; i++) {
			pkBufferString += GetValAtIndex(i).Serialize(this->GetModulus());
		}
		bbvMap.AddMember("VectorValues", pkBufferString, serObj->GetAllocator());
	}

	serObj->AddMember("BigVectorImpl", bbvMap, serObj->GetAllocator());

	return true;
}

// Deserialize Operation
template<class IntegerType>
bool BigVectorImpl<IntegerType>::Deserialize(const lbcrypto::Serialized& serObj) {

	lbcrypto::Serialized::ConstMemberIterator mIter = serObj.FindMember("BigVectorImpl");
	if( mIter == serObj.MemberEnd() )
		return false;

	lbcrypto::SerialItem::ConstMemberIterator vIt;

	if( (vIt = mIter->value.FindMember("IntegerType")) == mIter->value.MemberEnd() )
		return false;
	if( IntegerType::IntegerTypeName() != vIt->value.GetString() )
		return false;

	if( (vIt = mIter->value.FindMember("Modulus")) == mIter->value.MemberEnd() )
		return false;
	IntegerType bbiModulus(vIt->value.GetString());

	if( (vIt = mIter->value.FindMember("Length")) == mIter->value.MemberEnd() )
		return false;
	usint vectorLength = std::stoi(vIt->value.GetString());

	if( (vIt = mIter->value.FindMember("VectorValues")) == mIter->value.MemberEnd() )
		return false;

	BigVectorImpl<IntegerType> newVec(vectorLength, bbiModulus);

	IntegerType vectorElem;
	const char *vp = vIt->value.GetString();
	for( usint ePos = 0; ePos < vectorLength; ePos++ ) {
		if( *vp == '\0' ) {
			return false; // premature end of vector
		}
		vp = vectorElem.Deserialize(vp, bbiModulus);
		newVec[ePos] = vectorElem;
	}

	*this = std::move(newVec);

	return true;
}

} // namespace lbcrypto ends
