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
	This code provides basic arithmetic functionality for vectors of native integers.

*/

#include "../backend.h"
#include "../../utils/serializable.h"
#include "../native_int/binvect.h"
#include "../nbtheory.h"
#include "../../utils/debug.h"
#include "../../utils/serializablehelper.h"


namespace native_int {

//CTORS
template<class IntegerType>
NativeVector<IntegerType>::NativeVector(){
}

template<class IntegerType>
NativeVector<IntegerType>::NativeVector(usint length){
	this->m_data.resize(length);
}

template<class IntegerType>
NativeVector<IntegerType>::NativeVector(usint length, const IntegerType& modulus){
	this->m_modulus = modulus;
	this->m_data.resize(length);
}

template<class IntegerType>
NativeVector<IntegerType>::NativeVector(usint length, const IntegerType& modulus, std::initializer_list<uint64_t> rhs){
	this->m_modulus = modulus;
	this->m_data.resize(length);
	usint len = rhs.size();
	for (usint i=0;i<m_data.size();i++){ // this loops over each entry
		if(i<len) {
			m_data[i] =  IntegerType(*(rhs.begin()+i))%m_modulus;  
		} else {
			m_data[i] = IntegerType(0);
		}
	}

}

template<class IntegerType>
NativeVector<IntegerType>::NativeVector(usint length, const IntegerType& modulus, std::initializer_list<std::string> rhs){
	this->m_modulus = modulus;
	this->m_data.resize(length);
	usint len = rhs.size();
	for(usint i=0;i<m_data.size();i++){ // this loops over each entry
		if(i<len) {
			m_data[i] =  IntegerType(*(rhs.begin()+i))%m_modulus;  
		} else {
			m_data[i] = IntegerType(0);
		}
	}
}

template<class IntegerType>
NativeVector<IntegerType>::NativeVector(const NativeVector &bigVector){
	m_modulus = bigVector.m_modulus;
	m_data = bigVector.m_data;
}

template<class IntegerType>
NativeVector<IntegerType>::NativeVector(NativeVector &&bigVector){
	m_data = std::move(bigVector.m_data);
	m_modulus = bigVector.m_modulus;
}

//ASSIGNMENT OPERATOR
template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::operator=(const NativeVector &rhs){
	if(this!=&rhs){
		if(this->m_data.size()==rhs.m_data.size()){
			for (usint i = 0; i < m_data.size(); i++){
				this->m_data[i] = rhs.m_data[i];
			}
		}
		else{
			m_data = rhs.m_data;
		}
		m_modulus = rhs.m_modulus;
	}

	return *this;
}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::operator=(std::initializer_list<uint64_t> rhs){
	usint len = rhs.size();
	for(usint i=0;i<m_data.size();i++){ // this loops over each tower
		if(i<len) {
		  if (m_modulus!=0)
			m_data[i] = IntegerType(*(rhs.begin()+i))%m_modulus;
		  else
			m_data[i] = IntegerType(*(rhs.begin()+i));
		} else {
			m_data[i] = 0;
		}
	}

	return *this;
}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::operator=(std::initializer_list<std::string> rhs){
        bool dbg_flag = false;
	usint len = rhs.size();
	for(usint i=0;i<m_data.size();i++){ // this loops over each tower
		if(i<len) {
		  if (m_modulus!=0)
			m_data[i] = IntegerType(*(rhs.begin()+i))%m_modulus;
		  else
			m_data[i] = IntegerType(*(rhs.begin()+i));
		} else {
			m_data[i] = 0;
		}
		DEBUG("in op= i.l. m_data["<<i<<"] = "<<m_data[i]);
	}

	return *this;
}

template<class IntegerType>
NativeVector<IntegerType>& NativeVector<IntegerType>::operator=(NativeVector &&rhs){

	if(this!=&rhs){
		m_data = std::move(rhs.m_data);
		m_modulus = rhs.m_modulus;
	}

	return *this;

}

template<class IntegerType>
NativeVector<IntegerType>::~NativeVector(){}

//ACCESSORS

template<class IntegerType>
void NativeVector<IntegerType>::SetModulus(const IntegerType& value){
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
void NativeVector<IntegerType>::SwitchModulus(const IntegerType& newModulus) {
    bool dbg_flag = false;
    DEBUG("Switch modulus old mod :"<<this->m_modulus);
    DEBUG("Switch modulus old this :"<<*this);
	
	IntegerType oldModulus(this->m_modulus);
	IntegerType oldModulusByTwo(oldModulus>>1);
	IntegerType diff ((oldModulus > newModulus) ? (oldModulus-newModulus) : (newModulus - oldModulus));
	DEBUG("Switch modulus diff :"<<diff);
	for(usint i=0; i< this->m_data.size(); i++) {
		IntegerType n = this->m_data[i];
		DEBUG("i,n "<<i<<" "<< n);
		if(oldModulus < newModulus) {
			if(n > oldModulusByTwo) {
			  DEBUG("s1 "<<n.ModAdd(diff, newModulus));
				this->m_data[i] = n.ModAdd(diff, newModulus);
			} else {
			  DEBUG("s2 "<<n.Mod(newModulus));
				this->m_data[i] = n.Mod(newModulus);
			}
		} else {
			if(n > oldModulusByTwo) {
			  DEBUG("s3 "<<n.ModSub(diff, newModulus));				
				this->m_data[i] = n.ModSub(diff, newModulus);
			} else {
			  DEBUG("s4 "<<n.Mod(newModulus));
				this->m_data[i] = n.Mod(newModulus);
			}
		}
	}
	DEBUG("Switch modulus this before set :"<<*this);
	this->SetModulus(newModulus);
	DEBUG("Switch modulus new modulus :"<<this->m_modulus);
	DEBUG("Switch modulus new this :"<<*this);

}

template<class IntegerType>
const IntegerType& NativeVector<IntegerType>::GetModulus() const{

	return this->m_modulus;

}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::Mod(const IntegerType& modulus) const{

	if (modulus==2)
		return this->ModByTwo();
	else 
	{
		NativeVector ans(this->GetLength(),this->GetModulus());
		IntegerType halfQ(this->GetModulus() >> 1);
		for (size_t i = 0; i<ans.GetLength(); i++) {
			if (this->operator[](i)>halfQ) {
				ans[i] = this->operator[](i).ModSub(this->GetModulus(),modulus);
			}
			else {
				ans[i] = this->operator[](i).Mod(modulus);
			}
		}
		return ans;
	}
}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::ModEq(const IntegerType& modulus) {

	if (modulus==2)
		return this->ModByTwoEq();
	else
	{
		IntegerType halfQ(this->GetModulus() >> 1);
		for (size_t i = 0; i<this->GetLength(); i++) {
			if (this->operator[](i)>halfQ) {
				this->operator[](i).ModSubEq(this->GetModulus(),modulus);
			}
			else {
				this->operator[](i).ModEq(modulus);
			}
		}
		return *this;
	}
}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModAddAtIndex(usint i, const IntegerType &b) const{
	if(i > this->GetLength()-1) {
		std::string errMsg = "binvect::ModAddAtIndex. Index is out of range. i = " + std::to_string(i);
		throw std::runtime_error(errMsg);
	}
	NativeVector ans(*this);
	ans.m_data[i].ModAddEq(b, this->m_modulus);
	return ans;
}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModAdd(const IntegerType &b) const{

	IntegerType modulus = this->m_modulus;
	IntegerType bLocal = b;

	NativeVector ans(*this);
	if (this->m_modulus.GetMSB() < NTL_SP_NBITS + 1)
	{
		if (bLocal > m_modulus)
			bLocal.ModEq(modulus);
		for(usint i=0;i<this->m_data.size();i++){
			ans.m_data[i].ModAddFastOptimizedEq(bLocal, modulus);
		}
	}
	else
		for(usint i=0;i<this->m_data.size();i++){
			ans.m_data[i].ModAddFastEq(bLocal, modulus);
		}
	return ans;

}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::ModAddEq(const IntegerType &b) {

	IntegerType modulus = this->m_modulus;
	IntegerType bLocal = b;

	if (this->m_modulus.GetMSB() < NTL_SP_NBITS + 1)
	{
		if (bLocal > m_modulus)
			bLocal.ModEq(modulus);
		for(usint i=0;i<this->m_data.size();i++){
			this->m_data[i].ModAddFastOptimizedEq(bLocal, modulus);
		}
	}
	else
	{
		for(usint i=0;i<this->m_data.size();i++){
			this->m_data[i].ModAddEq(bLocal, m_modulus);
		}
	}
	return *this;

}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModSub(const IntegerType &b) const{

	NativeVector ans(*this);
	for(usint i=0;i<this->m_data.size();i++){
		ans.m_data[i].ModSubEq(b,this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::ModSubEq(const IntegerType &b) {

	for(usint i=0;i<this->m_data.size();i++){
		this->m_data[i].ModSubEq(b,this->m_modulus);
	}
	return *this;
}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::MultiplyAndRound(const IntegerType &p, const IntegerType &q) const {

	NativeVector ans(*this);
	IntegerType halfQ(this->m_modulus >> 1);
	for(usint i=0;i<this->m_data.size();i++){
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
NativeVector<IntegerType> NativeVector<IntegerType>::DivideAndRound(const IntegerType &q) const {
	NativeVector ans(*this);
	IntegerType halfQ(this->m_modulus >> 1);
	for(usint i=0;i<this->m_data.size();i++){
		if (ans.m_data[i] > halfQ) {
			IntegerType temp = this->m_modulus - ans.m_data[i];
			ans.m_data[i] = this->m_modulus - temp.DivideAndRound(q);
		}
		else
			ans.m_data[i] = ans.m_data[i].DivideAndRound(q);
	}
	return ans;
}


template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModMul(const IntegerType &b) const{

	NativeVector ans(*this);

	IntegerType modulus = this->m_modulus;
	IntegerType bLocal = b;

	if (modulus.GetMSB() < NTL_SP_NBITS + 1)
	{
		if (bLocal > modulus)
			bLocal.ModEq(modulus);
		for(usint i=0;i<this->m_data.size();i++)
			 ans.m_data[i].ModMulFastEqOptimized(bLocal,modulus);
	}
	else{
		for(usint i=0;i<this->m_data.size();i++)
			ans.m_data[i].ModMulFastEq(bLocal,modulus);
	}

	return ans;
}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::ModMulEq(const IntegerType &b) {

	IntegerType modulus = this->m_modulus;
	IntegerType bLocal = b;

	if (modulus.GetMSB() < NTL_SP_NBITS + 1)
	{
		if (bLocal > modulus)
			bLocal.ModEq(modulus);
		for(usint i=0;i<this->m_data.size();i++){
			this->m_data[i].ModMulFastEqOptimized(bLocal,modulus);
		}
	}
	else
	{
		for(usint i=0;i<this->m_data.size();i++){
			this->m_data[i].ModMulFastEq(bLocal,modulus);
		}
	}

	return *this;
}



template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModExp(const IntegerType &b) const{
	NativeVector ans(*this);
	for(usint i=0;i<this->m_data.size();i++){
		ans.m_data[i] = ans.m_data[i].ModExp(b,this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModInverse() const{

	NativeVector ans(*this);
	for(usint i=0;i<this->m_data.size();i++){
		ans.m_data[i] = ans.m_data[i].ModInverse(this->m_modulus);
	}
	return ans;

}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModAdd(const NativeVector &b) const{

	if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModAdd called on NativeVector's with different parameters.");
	}

	NativeVector ans(*this);

	IntegerType modulus = this->m_modulus;

	if (modulus.GetMSB() < NTL_SP_NBITS + 1)
	{
		for(usint i=0;i<ans.m_data.size();i++)
			ans.m_data[i].ModAddFastOptimizedEq(b[i],modulus);
	}
	else
	{
		for(usint i=0;i<ans.m_data.size();i++)
			ans.m_data[i].ModAddFastEq(b[i],modulus);
	}

	return ans;

}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::ModAddEq(const NativeVector &b) {

	if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModAddEq called on NativeVector's with different parameters.");
	}

	IntegerType modulus = this->m_modulus;

	if (modulus.GetMSB() < NTL_SP_NBITS + 1)
	{
		for(usint i=0;i<this->m_data.size();i++)
			this->m_data[i].ModAddFastOptimizedEq(b[i],modulus);
	}
	else
	{
		for(usint i=0;i<this->m_data.size();i++)
			this->m_data[i].ModAddFastEq(b[i],modulus);
	}

	return *this;

}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModSub(const NativeVector &b) const{

	if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModSub called on NativeVector's with different parameters.");
	}

	NativeVector ans(*this);

	for(usint i=0;i<ans.m_data.size();i++){
		ans.m_data[i].ModSubFastEq(b.m_data[i],this->m_modulus);
	}
	return ans;

}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::ModSubEq(const NativeVector &b) {

	if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModSubEq called on NativeVector's with different parameters.");
	}

	for(usint i=0;i<this->m_data.size();i++){
		this->m_data[i].ModSubFastEq(b.m_data[i],this->m_modulus);
	}
	return *this;

}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModByTwo() const {

	NativeVector ans(*this);
	ans.ModByTwoEq();
	return ans;
}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::ModByTwoEq() {

	IntegerType halfQ(this->GetModulus() >> 1);
	for (size_t i = 0; i<this->GetLength(); i++) {
		if (this->operator[](i)>halfQ) {
			if (this->operator[](i).Mod(2) == 1)
				this->operator[](i) = IntegerType(0);
			else
				this->operator[](i) = 1;
		}
		else {
			if (this->operator[](i).Mod(2) == 1)
				this->operator[](i) = 1;
			else
				this->operator[](i) = IntegerType(0);
		}

	}
	return *this;
}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModMul(const NativeVector &b) const{

	if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModMul called on NativeVector's with different parameters.");
	}

	NativeVector ans(*this);
	IntegerType modulus = this->m_modulus;

	if (modulus.GetMSB() < NTL_SP_NBITS + 1)
	{
		for(usint i=0;i<this->m_data.size();i++)
			ans.m_data[i].ModMulFastEqOptimized(b[i],modulus);
	}
	else
	{
		for(usint i=0;i<this->m_data.size();i++)
			ans.m_data[i].ModMulFastEq(b[i],modulus);
	}

	return ans;

}

template<class IntegerType>
const NativeVector<IntegerType>& NativeVector<IntegerType>::ModMulEq(const NativeVector &b) {

	if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
        throw std::logic_error("ModMul called on NativeVector's with different parameters.");
	}

	IntegerType modulus = this->m_modulus;

	if (modulus.GetMSB() < NTL_SP_NBITS + 1)
	{
		for(usint i=0;i<this->m_data.size();i++)
			this->m_data[i].ModMulFastEqOptimized(b[i],modulus);
	}
	else
	{
		for(usint i=0;i<this->m_data.size();i++)
			this->m_data[i].ModMulFastEq(b[i],modulus);
	}

	return *this;
}

template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::MultWithOutMod(const NativeVector &b) const {

	if ((this->m_data.size() != b.m_data.size()) || this->m_modulus != b.m_modulus) {
        throw std::logic_error("ModMul called on NativeVector's with different parameters.");
	}

	NativeVector ans(*this);

	for (usint i = 0; i<ans.m_data.size(); i++) {
		ans.m_data[i] *= b.m_data[i];
	}
	return ans;
}

//Gets the ind
template<class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::GetDigitAtIndexForBase(usint index, usint base) const{
	bool dbg_flag = false;
	DEBUG("NativeVector::GetDigitAtIndexForBase:  index = " << index << ", base = " << base);
	NativeVector ans(*this);
	for(usint i=0;i<this->m_data.size();i++){
		ans.m_data[i] = IntegerType(ans.m_data[i].GetDigitAtIndexForBase(index,base));
		DEBUG("ans.m_data[" << i << "] = " << ans.m_data[i]);
	}

	return ans;
}

// Serialize Operation
template<class IntegerType>
bool NativeVector<IntegerType>::Serialize(lbcrypto::Serialized* serObj) const {

        if( !serObj->IsObject() ){
	  serObj->SetObject();
	}


	lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);

	bbvMap.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator());
	bbvMap.AddMember("IntegerType", IntegerType::IntegerTypeName(), serObj->GetAllocator());

	size_t pkVectorLength = this->GetLength();

	if( pkVectorLength > 0 ) {
		std::string pkBufferString = "";
		for (size_t i = 0; i < pkVectorLength; i++) {
			pkBufferString += at(i).SerializeToString(this->GetModulus());
		}
		bbvMap.AddMember("VectorValues", pkBufferString, serObj->GetAllocator());
	}

	serObj->AddMember("BigVectorImpl", bbvMap, serObj->GetAllocator());

	return true;
}
  
// Deserialize Operation
template<class IntegerType>
bool NativeVector<IntegerType>::Deserialize(const lbcrypto::Serialized& serObj) {

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

	if( (vIt = mIter->value.FindMember("VectorValues")) == mIter->value.MemberEnd() )
		return false;

 	NativeVector<IntegerType> newVec;
 	newVec.SetModulus(bbiModulus);

	IntegerType vectorElem;
	const char *vp = vIt->value.GetString();
	while( *vp != '\0' ) {
		vp = vectorElem.DeserializeFromString(vp, bbiModulus);
		newVec.m_data.push_back(vectorElem);
	}

	*this = std::move(newVec);

	return true;

}


template class NativeVector<NativeInteger<uint64_t>>;
 
} // namespace lbcrypto ends
