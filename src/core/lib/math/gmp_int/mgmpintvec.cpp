/*
 * @file mgmpintvec.cpp This file contains mgmpintvec, a <vector> of gmpint, with associated
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
 *
 * This file contains the cpp implementation of  mgmpintvec, a <vector> of gmpint, with associated math operators.
 *
 */
#define FASTNLOOSE
#define FORCE_NORMALIZATION

#include "../../utils/serializable.h"

#include "../backend.h"

#include "mgmpintvec.h"

#include "time.h"
#include <chrono>

#include "../../utils/debug.h"

namespace NTL {

// constructors without moduli
//&&&
//copy ctor with vector inputs
//creation ctors without moduli are marked GARBAGE
template<class myT>
myVecP<myT>::myVecP(const myVecP<myT> &a) : Vec<myT>(INIT_SIZE, a.length())
//note use .length() here to return long which Vec expects
{
	bool dbg_flag = false;
	DEBUG("in myVecP(myVecP&) length "<<a.length());
	DEBUG("input vector "<<a);
	DEBUG("input modulus "<<a.GetModulus());
	int rv = this->CopyModulus(a);
	if (rv==-1) {
#ifdef WARN_BAD_MODULUS
		std::cerr<<"in myVecP(myVecP) Bad CopyModulus"<<std::endl;
#endif
	}
	*this=a;

	DEBUG("output vector "<<*this);
	DEBUG("output modulus "<<this->GetModulus());

}

//movecopy ctor
template<class myT>
myVecP<myT>::myVecP(myVecP<myT> &&a) : Vec<myT>(INIT_SIZE, a.length())
//note use .length() here to return long which Vec expects
{
	bool dbg_flag = false;
	DEBUG("in myVecP copymove, myvecP<myT> alength "<<a.length());
	int rv = this->CopyModulus(a);
	if (rv==-1) {
#ifdef WARN_BAD_MODULUS
		std::cerr<<"in myVecP(myVecP &&) Bad CopyModulus"<<std::endl;
#endif
	}
	this->move(a);
}

//constructors with moduli
//ctor myT moduli
template<class myT>
myVecP<myT>::myVecP(const long n, const myT &q): Vec<myT>(INIT_SIZE,n)
{
	bool dbg_flag = false;
	DEBUG("myVecP(n,ZZ) n:"<<n);
	DEBUG("q:"<<q);
	this->SetModulus(q);
	DEBUG("get modulus "<<GetModulus());
}

//constructors with moduli and initializer list
//ctor myT moduli
template<class myT>
myVecP<myT>::myVecP(const long n, const myT &q, std::initializer_list<uint64_t> rhs): Vec<myT>(INIT_SIZE,n)
{
	bool dbg_flag = false;
	DEBUG("myVecP(n,ZZ) n:"<<n);
	DEBUG("q:"<<q);
	this->SetModulus(q);
	DEBUG("get modulus "<<GetModulus());
	usint len = rhs.size();
	for (size_t i=0;i<size_t(n);i++){ // this loops over each entry
		if(i<len) {
			(*this)[i] =  myT(*(rhs.begin()+i))%m_modulus;
		} else {
			(*this)[i] = myT(0);
		}
	}
}

template<class myT>
myVecP<myT>::myVecP(const long n, const myT &q, std::initializer_list<std::string> rhs): Vec<myT>(INIT_SIZE,n)
{
	bool dbg_flag = false;
	DEBUG("myVecP(n,ZZ) n:"<<n);
	DEBUG("q:"<<q);
	this->SetModulus(q);
	DEBUG("get modulus "<<GetModulus());
	usint len = rhs.size();
	for (size_t i=0;i<size_t(n);i++){ // this loops over each entry
		if(i<len) {
			(*this)[i] =  myT(*(rhs.begin()+i))%m_modulus;
		} else {
			(*this)[i] = myT(0);
		}
	}
}


template<class myT>
myVecP<myT>::myVecP(const myVecP<myT> &a, const myT &q): Vec<myT>(a)
{
	this->SetModulus(q);
	(*this) %= q;
}

//ctor with string moduli
template<class myT>
myVecP<myT>::myVecP(size_t n, const std::string &sq):Vec<myT>(INIT_SIZE, n)
{
	this->SetModulus(myT(sq));
}

//copy with char * moduli
template<class myT>
myVecP<myT>::myVecP(const myVecP<myT> &a, const std::string &sq):Vec<myT>(a)
{
	this->SetModulus(myT(sq));
}

//ctor with uint64_t moduli
template<class myT>
myVecP<myT>::myVecP(size_t n, uint64_t q):Vec<myT>(INIT_SIZE, n)
{
	this->SetModulus(q);
}

//copy with unsigned int moduli
template<class myT>
myVecP<myT>::myVecP(const myVecP<myT> &a, const uint64_t q):Vec<myT>(a)
{
	this->SetModulus(q);
	for (size_t i = 0; i < this->GetLength(); i++){
		(*this)[i] %=myT(q);
	}
}

// constructor specifying the myvec as a vector of strings
template<class myT>
myVecP<myT>::myVecP(std::vector<std::string> &s){
	usint len = s.size();
	this->resize(len);
	for (size_t i = 0; i < len; i++){
		(*this)[i] = myT(s[i]);
	}
	this->m_modulus_state = GARBAGE;
}

// constructor specifying the myvec as a vector of strings with modulus
template<class myT>
myVecP<myT>::myVecP(std::vector<std::string> &s, const myT &q){
	usint len = s.size();
	this->resize(len);
	this->SetModulus(q);
	for (size_t i = 0; i < len; i++){
		(*this)[i] = myT(s[i])%q;
	}
}

// constructor specifying the myvec as a vector of strings with modulus
template<class myT>
myVecP<myT>::myVecP(std::vector<std::string> &s, const char *sq){
	usint len = s.size();
	this->resize(len);
	myT zzq(sq);
	this->SetModulus(zzq);
	for (size_t i = 0; i < len; i++){
		(*this)[i] = myT(s[i])%zzq;
	}
}

// constructor specifying the myvec as a vector of strings with modulus
template<class myT>
myVecP<myT>::myVecP(std::vector<std::string> &s, const uint64_t q){
	usint len = s.size();
	this->resize(len);
	myT zzq(q);
	this->SetModulus(zzq);
	for (size_t i = 0; i < len; i++){
		(*this)[i] = myT(s[i])%zzq;
	}
}

//Assignment with initializer list of uint64_ts
//keeps current modulus

template<class myT>
const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<uint64_t> rhs){
	bool dbg_flag = false;
	DEBUG("in op=initializerlist <uint64_t>");

	size_t len = rhs.size();
	if (this->GetLength()< len){
		this->resize(len);
	};

	for(size_t i=0;i<this->GetLength();i++){ // this loops over each entry
		if (i<len) {
#ifdef FORCE_NORMALIZATION
			if (isModulusSet())
				(*this)[i] =  myT(*(rhs.begin()+i))%m_modulus;
			else //must be set directly
#endif
				(*this)[i] =  myT(*(rhs.begin()+i));
		}else{
			(*this)[i] =  myT(0);
		}
	}
	return *this;

	DEBUG("mubintvec assignment copy CTOR uint64_t init list size "<<this->GetLength());
}


//for some dumb reason they coded this., it is dangerous
template<class myT>
const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<int32_t> rhs){
	bool dbg_flag = false;
	DEBUG("in op=initializerlist <uint64_t>");

	size_t len = rhs.size();
	if (this->GetLength()< len){
		this->resize(len);
	};

	for(size_t i=0;i<this->GetLength();i++){ // this loops over each entry
		if (i<len) {
			int tmp = *(rhs.begin()+i);
			if (tmp<0){
				std::cout<<"warning trying to assign negative integer value"<<std::endl;
			}
#ifdef FORCE_NORMALIZATION
			if (isModulusSet())
				(*this)[i] =  myT(tmp)%m_modulus;
			else //must be set directly
#endif
				(*this)[i] =  myT(tmp);
		}else{
			(*this)[i] =  myT(0);
		}
	}
	return *this;

	DEBUG("mubintvec assignment copy CTOR uint64_t init list size "<<this->GetLength());
}

//Assignment with initializer list of strings
//keeps current modulus
template<class myT>
const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<std::string> rhs){
	bool dbg_flag = false;
	DEBUG("in op=initializerlist <string>");
	size_t len = rhs.size();
	if (this->GetLength()< len){
		this->resize(len);
	};

	for(size_t i=0;i<this->GetLength();i++){ // this loops over each entry
		if (i<len) {
#ifdef FORCE_NORMALIZATION
			if (isModulusSet())
				(*this)[i] =  myT(*(rhs.begin()+i))%m_modulus;
			else //must be set directly
#endif
				(*this)[i] =  myT(*(rhs.begin()+i));
		}else{
			(*this)[i] =  myT(0);
		}
	}

	return *this;
	DEBUG("mubintvec assignment copy CTOR string init list size "<<this->GetLength());
}

//keeps current modulus
//note this only assigns to the first element!!
template<class myT>
const myVecP<myT>& myVecP<myT>::operator=(uint64_t val)
{
	bool dbg_flag = false;
	DEBUG("in op=uint64_t");

	(*this)[0] = myT(val);
#ifdef FORCE_NORMALIZATION
	if (isModulusSet())
		(*this)[0] %= m_modulus;
#endif

	for (size_t i = 1; i < GetLength(); ++i) {
		(*this)[i] = myT(0);
	}
	return *this;
}

//do not keep current modulus but copies from rhs.
template<class myT>
const myVecP<myT>& myVecP<myT>::operator=(const myVecP<myT> &rhs)
{
	bool dbg_flag = false;
	DEBUG("in op=const myVecP<myT>&");
	DEBUG("setting size "<<rhs.GetLength());
	this->resize(rhs.GetLength());
	DEBUG("setting length "<<rhs.GetLength());
	int rv = this->CopyModulus(rhs);
	if (rv==-1) {
#ifdef WARN_BAD_MODULUS
		std::cerr<<"in operator=(myVecP) Bad CopyModulus"<<std::endl;
#endif
	}
	for (size_t i = 0; i < rhs.GetLength(); i++){
		(*this)[i] = rhs[i];
	}
	return *this;
}

//move copy do not keep current modulus but copies from rhs.
template<class myT>
const myVecP<myT>& myVecP<myT>::operator=( myVecP<myT> &&rhs)
{
	bool dbg_flag = false;

	if (this != &rhs) {
		DEBUG("in op=const myVecP<myT>&");
		DEBUG("setting size "<<rhs.GetLength());
		this->resize(rhs.GetLength());
		DEBUG("setting size "<<rhs.GetLength());
		int rv = this->CopyModulus(rhs);
		if (rv==-1) {
#ifdef WARN_BAD_MODULUS
			std::cerr<<"in operator=(myVecP) Bad CopyModulus"<<std::endl;
#endif
		}
		this->move(rhs);
	}

	return *this;
}

template<class myT>
void myVecP<myT>::clear(myVecP<myT>& x)
{
	//sets all elements to zero, but does not change size
	bool dbg_flag = false;
	DEBUG("in clear myVec");
	//using NTL_NAMESPACE::clear;
	size_t n = x.GetLength();
	for (size_t i = 0; i < n; i++){
		NTL_NAMESPACE::clear(x[i]);
	}
	NTL_NAMESPACE::clear(x.m_modulus);
}

//not enabled yet

//ACCESSORS

//Switches the integers in the vector to values corresponding to the new modulus
//*  Algorithm: Integer i, Old Modulus om, New Modulus nm, delta = abs(om-nm):
// *  Case 1: om < nm
// *  if i > i > om/2
// *  i' = i + delta
// *  Case 2: om > nm
// *  i > om/2
// *  i' = i-delta
//
template<class myT>
void myVecP<myT>::SwitchModulus(const myT& newModulus)
{

	bool dbg_flag = false;
	DEBUG("Switch modulus old mod :"<<this->m_modulus);
	DEBUG("Switch modulus old this :"<<*this);

	myT oldModulus(this->m_modulus);
	myT n;
	myT oldModulusByTwo(oldModulus>>1);
	myT diff ((oldModulus > newModulus) ? (oldModulus-newModulus) : (newModulus - oldModulus));
	DEBUG("Switch modulus diff :"<<diff);
	for(size_t i=0; i< this->GetLength(); i++) {
		n = this->at(i);
		DEBUG("i,n "<<i<<" "<< n);
		if (oldModulus < newModulus) {
			if (n > oldModulusByTwo) {
				DEBUG("s1 "<<n.ModAdd(diff, newModulus));
				this->at(i)= n.ModAdd(diff, newModulus);
			} else {
				DEBUG("s2 "<<n.Mod(newModulus));
				this->at(i)= n.Mod(newModulus);
			}
		} else {
			if(n > oldModulusByTwo) {
				DEBUG("s3 "<<n.ModSub(diff, newModulus));
				this->at(i)= n.ModSub(diff, newModulus);
			} else {
				DEBUG("s4 "<<n.Mod(newModulus));
				this->at(i) = n.Mod(newModulus);
			}
		}

	}
	DEBUG("Switch modulus this before set :"<<*this);
	this->SetModulus(newModulus);
	DEBUG("Switch modulus new modulus :"<<this->m_modulus);
	DEBUG("Switch modulus new this :"<<*this);

}

/// ARITHMETIC FUNCTIONS

template<class myT>
myVecP<myT> myVecP<myT>::Mod(const myT& modulus) const
{
	bool dbg_flag = false;
	DEBUG("mgmpintvec" <<*this);
	DEBUG("MOD("<<modulus<<")");
	if (modulus == myT(2)) {
		return this->ModByTwo();
	} else {
		myT thisMod(this->GetModulus());
		myVecP ans(this->GetLength(), thisMod); //zeroed out
		myT halfQ(thisMod >> 1);
		DEBUG("halfQ = "<<halfQ);
		for (size_t i = 0; i<this->GetLength(); i++) {
			if ((*this)[i]>halfQ) {
				DEBUG("negative at i="<<i);
				ans[i] = (*this)[i].ModSub(thisMod, modulus);
			} else {
				ans[i] = (*this)[i].Mod(modulus);
			}
		}
		DEBUG("ans.GetModulus() "<<ans.GetModulus());

		for (size_t i = 0; i<ans.GetLength(); i++) {
			DEBUG("ans ["<<i<<"] = "<<ans[i]);
		}
		return ans;
	}
}

template<class myT>
const myVecP<myT>& myVecP<myT>::ModEq(const myT& modulus)
{
	bool dbg_flag = false;
	DEBUG("mgmpintvec" <<*this);
	DEBUG("MOD("<<modulus<<")");
	if (modulus == myT(2)) {
		return this->ModByTwoEq();
	} else {
		myT thisMod(this->GetModulus());

		myT halfQ(thisMod >> 1);
		DEBUG("halfQ = "<<halfQ);
		for (size_t i = 0; i<this->GetLength(); i++) {
			if (this->operator[](i) > halfQ) {
				DEBUG("negative at i="<<i);
				this->operator[](i).ModSubEq(thisMod, modulus);
			} else {
				this->operator[](i).ModEq(modulus);
			}
		}
		DEBUG("ans.GetModulus() "<<this->GetModulus());

		for (size_t i = 0; i<this->GetLength(); i++) {
			DEBUG("ans ["<<i<<"] = "<<this->operator[](i));
		}
		return *this;
	}
}

template<class myT>
myVecP<myT> myVecP<myT>::ModByTwo() const {
	myVecP ans(*this);
	ans.ModByTwoEq();
	return ans;
}

//method to mod by two
template<class myT>
const myVecP<myT>& myVecP<myT>::ModByTwoEq() {

	myT halfQ(this->GetModulus() >> 1);
	for (size_t i = 0; i<this->GetLength(); i++) {
		if (this->operator [](i) > halfQ) {
			if (this->operator [](i).Mod(myT(2)) == myT(1))
				this->operator [](i) = 0;
			else
				this->operator [](i) = 1;
		}
		else {
			if (this->operator [](i).Mod(myT(2)) == myT(1))
				this->operator [](i) = 1;
			else
				this->operator [](i) = 0;
		}

	}
	return *this;
}

// method to add scalar to vector element at index i
template<class myT>
myVecP<myT> myVecP<myT>::ModAddAtIndex(size_t i, const myT &b) const{
	if(i > this->GetLength()-1) {
		std::string errMsg = "myVecP::ModAddAtIndex. Index is out of range. i = " + std::to_string(i);
		PALISADE_THROW(lbcrypto::palisade_error, errMsg);
	}
	myVecP ans(*this); //copy vector
	ModulusCheck("myVecP::ModAddAtIndex");
	ans[i] = ans[i].ModAdd(b, this->m_modulus);
	return ans;
}


//Need to mimic Palisade use of signed modulus for modsub.

//subtraction of scalar
//template<class myT>
//myVecP<myT> myVecP<myT>::operator-(const myT& b) const
//{
//	size_t n = this->GetLength();
//	myVecP<myT> res(n);
//	myT mod(this->GetModulus());
//	res.SetModulus(mod);
//
//	for (size_t i = 0; i < n; i++) {
//		res[i] = (*this)[i].ModSub(b, mod);
//	}
//	return(res);
//}

//subtraction of vector
//why can't I inheret this?

//template<class myT>
//myVecP<myT> myVecP<myT>::operator-(const myVecP<myT> &b) const
//{
//	bool dbg_flag = false;
//	DEBUG("in myVecP::operator-");
//	ArgCheckVector(b, "myVecP::op-");
//	myVecP<myT> res(b.GetLength());
//	myT mod(this->GetModulus());
//	res.SetModulus(mod);
//
//	for (size_t i = 0; i < b.GetLength(); i++) {
//		res[i] = (*this)[i].ModSub(b[i],mod);
//	}
//
//
//	DEBUG("myVecP::operator- returning modulus "<<res.m_modulus);
//	return(res);
//}

//template<class myT>
//myVecP<myT> myVecP<myT>::operator-(void)
//{
//	bool dbg_flag = false;
//	DEBUG("in myVecP::operator-negate");
//	myVecP<myT> tmp (this->GetLength());
//	myVecP<myT>::clear(tmp);
//	int rv = tmp.CopyModulus(*this);
//	if (rv==-1) {
//#ifdef WARN_BAD_MODULUS
//		std::cerr<<"in operator-(void) Bad CopyModulus"<<std::endl;
//#endif
//	}
//	return (tmp - *this);
//
//}

//multiplication vector by scalar
//template<class myT>
//myVecP<myT> myVecP<myT>::operator*(myT const& b) const
//{
//
//	size_t n = this->GetLength();
//	myVecP<myT> res(n);
//	int rv = res.CopyModulus(*this);
//	if (rv==-1) {
//#ifdef WARN_BAD_MODULUS
//		std::cerr<<"in operator*(myT) Bad CopyModulus"<<std::endl;
//#endif
//	}
//	myT bmod = b%m_modulus;
//	for (size_t i = 0; i < n; i++){
//		res[i]=(*this)[i].ModMul(bmod,m_modulus);
//	}
//	return(res);
//}

//multiplication vector vector (element wise)
//why can't I inheret this?
//template<class myT>
//myVecP<myT> myVecP<myT>::operator*(myVecP<myT> const& b) const
//{
//	bool dbg_flag = false;
//	DEBUG("in myVecP::operator*");
//	ArgCheckVector(b, "myVecP::operator*");
//	myVecP<myT> res;
//	int rv = res.CopyModulus(*this);
//	if (rv==-1) {
//#ifdef WARN_BAD_MODULUS
//		std::cerr<<"in operator*(myVecP) Bad CopyModulus"<<std::endl;
//#endif
//	}
//	myVecP<myT>::modmul_p(res, *this, b);
//	//NTL_OPT_RETURN(myVecP<myT>, res);
//	DEBUG("myVecP::operator* returning modulus "<<res.m_modulus);
//	return(res);
//}

template<class myT>
myVecP<myT> myVecP<myT>::ModExp(const myT &b) const
{
	myVecP ans(*this);
	ModulusCheck("myVecP::ModExp");
	for(size_t i=0;i<this->GetLength();i++){
		ans[i] = ans[i].ModExp(b%m_modulus, ans.m_modulus);
	}
	return ans;
}

// method to exponentiate vector by scalar
template<class myT>
myVecP<myT> myVecP<myT>::Exp(const myT &b) const //overload of ModExp()
{
	myVecP ans(*this);
	ModulusCheck("myVecP::ModExp");
	ans = ans.ModExp(b%m_modulus);
	return ans;
}

template<class myT>
myVecP<myT> myVecP<myT>::MultiplyAndRound(const myT &p, const myT &q) const
{
	ModulusCheck("myVecP::MultiplyAndRound");
	myVecP ans(*this);
	myT halfQ(this->m_modulus >> 1);
	for (size_t i = 0; i<this->GetLength(); i++) {
		if (ans[i] > halfQ) {
			myT temp = this->m_modulus - ans[i];
			ans[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
		}
		else
			ans[i] = ans[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
	}
	return ans;
}

template<class myT>
myVecP<myT> myVecP<myT>::DivideAndRound(const myT &q) const {
	ModulusCheck("myVecP::DivideAndRound");
	myVecP ans(*this);
	for (size_t i = 0; i<this->GetLength(); i++) {
		ans[i] = ans[i].DivideAndRound(q);
	}
	return ans;
}

template<class myT>
myVecP<myT> myVecP<myT>::ModInverse(void) const
{
	ModulusCheck("myVecP::ModInverse");
	myVecP ans(*this);
	for(size_t i=0;i<this->GetLength();i++){
		ans[i] = ans[i].ModInverse(this->m_modulus);
	}
	return ans;
}

//not sure what this does..
template<class myT>
myVecP<myT> myVecP<myT>::GetDigitAtIndexForBase(size_t index, usint base) const
{
	bool dbg_flag = false;
	DEBUG("myVecP::GetDigitAtIndexForBase:  index = " << index << ", base = " << base);
	myVecP ans(*this);
	for(size_t i=0; i < this->GetLength(); i++){
		ans[i] = ans[i].GetDigitAtIndexForBase(index,base);
		DEBUG("ans.[" << i << "] = " << ans[i]);
	}

	return ans;
}

// serialize and deserialise operations
template<class myT>
bool myVecP<myT>::Serialize(lbcrypto::Serialized* serObj) const {
	bool dbg_flag = false;
	if( !serObj->IsObject() ){
		std::cerr<<"myVecP::Serialize failed bad object"<<std::endl;
		return false;
	}
	//serialize the modulus or mark as unknown
	std::string modstring ="";
	DEBUG("in vector Serialize");
	if (this->isModulusSet()){
		modstring = this->GetModulus().ToString();
	}else{
		modstring = "undefined";
	}
	DEBUG("modstring "<<modstring);

	//build the map for the serialization
	lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);
	//add modulus
	bbvMap.AddMember("Modulus", modstring, serObj->GetAllocator());
	//add Integer type
	DEBUG("IntegerType "<<myT::IntegerTypeName());
	bbvMap.AddMember("IntegerType", myT::IntegerTypeName(),
			serObj->GetAllocator());

	//determine vector size
	size_t pkVectorLength = this->GetLength();
	DEBUG ("size "<<pkVectorLength);
	bbvMap.AddMember("Length", std::to_string(pkVectorLength),
			serObj->GetAllocator());

	//build a string containing all vector elements concatenated
	if( pkVectorLength > 0 ) {
		std::string pkBufferString = "";
		for (size_t i = 0; i < pkVectorLength; i++) {
			DEBUG("element "<<i<<" "<<(*this)[i]);
			std::string tmp = (*this)[i].SerializeToString(this->GetModulus());
			pkBufferString += tmp;
		}
		DEBUG("add VectorValues");
		bbvMap.AddMember("VectorValues", pkBufferString, serObj->GetAllocator());
	}
	//store the map.
	DEBUG("add BigVectorImpl");
	serObj->AddMember("BigVectorImpl", bbvMap, serObj->GetAllocator());

	DEBUG("serialize done");
	return true;
}

// Deserialize
template<class myT>
bool myVecP<myT>::Deserialize(const lbcrypto::Serialized& serObj) {
	bool dbg_flag = false;
	DEBUG("in deserialize");

	//decode in reverse order from Serialize above
	lbcrypto::Serialized::ConstMemberIterator mIter = serObj.FindMember("BigVectorImpl");
	if( mIter == serObj.MemberEnd() ){
		std::cerr<<"myVecP::Deserialize() failed"
				<<" BigVectorImpl not found"<<std::endl;
		return false;
	}

	lbcrypto::SerialItem::ConstMemberIterator vIt; //iterator over serial items
	//look for IntegerType
	if( (vIt = mIter->value.FindMember("IntegerType"))
			== mIter->value.MemberEnd() ){
		std::cerr<<"myVecP::Deserialize() failed IntegerType not found"
				<<std::endl;
		return false;
	}
	if( myT::IntegerTypeName() != vIt->value.GetString() ){
		std::cerr<<"myVecP::Deserialize() failed IntegerType transltion"
				<<std::endl;
		return false;
	}
	//look for Modulus
	if( (vIt = mIter->value.FindMember("Modulus"))
			== mIter->value.MemberEnd() ){
		std::cerr<<"myVecP::Deserialize() failed Modulus not found"<<std::endl;
		return false;
	}
	//decode modulus
	std::string strval(vIt->value.GetString());
	DEBUG("getting modulus string "<<strval);
	myT bbiModulus;
	if (strval !="undefined"){
		bbiModulus =  myT(strval);
	}
	DEBUG("bbiModulus "<<bbiModulus);

	//find length of vector
	if( (vIt = mIter->value.FindMember("Length"))
			== mIter->value.MemberEnd() ){
		std::cerr<<"myVecP::Deserialize() failed Length not found"<<std::endl;
		return false;
	}
	usint vectorLength = std::stoi(vIt->value.GetString());
	DEBUG("vectorLength "<<vectorLength);

	if( (vIt = mIter->value.FindMember("VectorValues")) ==
			mIter->value.MemberEnd() ){
		std::cerr<<"myVecP::Deserialize() failed VectorValues not found"
				<<std::endl;
		return false;
	}

	myVecP<myT> newVec(vectorLength, bbiModulus); //build new vector
	myT vectorElem; //element to store decode

	const char *vp = vIt->value.GetString(); //concatenated str of coded values
	DEBUG("vp is size "<<strlen(vp));

	for( size_t ePos = 0; ePos < vectorLength; ePos++ ) {
		if( *vp == '\0' ) {
			std::cerr<<"myVecP::Deserialize() premature end of vector"<<std::endl;
			std::cerr<<"at position "<<ePos<<std::endl;
			return false; // premature end of vector
		}
		DEBUG("loop "<<ePos<<" vp before is size "<<strlen(vp));
		vp = vectorElem.DeserializeFromString(vp, bbiModulus); //decode element
		DEBUG("vp after is size "<<strlen(vp));
		newVec[ePos] = vectorElem;//store it
	}
	*this = std::move(newVec);//save the overall vectol
	return true;
}

//procedural addition
template<class myT>
inline  void  myVecP<myT>::modadd_p(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const
{
	bool dbg_flag = false;
	a.ArgCheckVector(b, "myVecP::modadd()");
	size_t n = a.GetLength();
	if (b.GetLength() != n) LogicError("myVecP<>vector add: dimension mismatch");

	x.resize(n);

	DEBUG("myvecp::add a mod "<<a.m_modulus<<" b mod "<<b.m_modulus);
	DEBUG("myvecp::add a length "<<a.GetLength()<<"b "<<b.GetLength());
	DEBUG("this->m_modulus "<<this->m_modulus);
	for (size_t i = 0; i < n; i++){
		DEBUG("myvecp::add i:"<<i<<"a "<<a[i]<<" b "<<b[i]);
#ifndef FASTNLOOSE 
		x[i]=a[i].ModAdd(b[i],m_modulus); // modulo add
#else
		x[i]=a[i].ModAddFast(b[i],m_modulus); // modulo add
#endif
	}
	DEBUG("x "<<x);
	DEBUG("myvecp::done");
	//todo make modulus explicit.
}
//procedural subtraction
template<class myT>
void  myVecP<myT>::modsub_p(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const
{
	bool dbg_flag = false;

	a.ArgCheckVector(b, "myVecP::sub()");
	size_t n = a.GetLength();
	if (b.GetLength() != n) LogicError("myVecP<>vector sub: dimension mismatch");

	x.resize(n);
	DEBUG("myvecp::sub a mod "<<a.m_modulus<<" b mod "<<b.m_modulus);
	DEBUG("myvecp::sub a length "<<a.GetLength()<<"b "<<b.GetLength());
	//DEBUG("myvecp::sub initial otm is: "<<ZZ_p::modulus());
	//ZZ_p::init(a.m_modulus);

	for (size_t i = 0; i < n; i++){
		DEBUG("myvecp::sub i:"<<i<<"a "<<a[i]<<" b "<<b[i]);
#ifndef FASTNLOOSE 
		x[i]=a[i].ModSub(b[i],m_modulus); //inmplicit modulo sub
#else
		x[i]=a[i].ModSubFast(b[i],m_modulus); //inmplicit modulo sub
#endif
	}
	DEBUG("myvecp::done");
	//todo make modulus explicit.
}


template<class myT>
inline void  myVecP<myT>::modmul_p(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const
{
	bool dbg_flag = false;
	a.ArgCheckVector(b, "myVecP::mul()");
	unsigned int n = a.GetLength();
	if (b.GetLength() != n) LogicError("myVecP<>vector sub: dimension mismatch");

	x.resize(n);
	unsigned int i;

	DEBUG("myvecp::mul a mod "<<a.m_modulus<<" b mod "<<b.m_modulus);
	DEBUG("myvecp::mul a size "<<a.GetLength()<<"b "<<b.GetLength());
	//DEBUG("myvecp::sub initial otm is: "<<ZZ_p::modulus());
	//ZZ_p::init(a.m_modulus);


	for (i = 0; i < n; i++){
		DEBUG("myvecp::mul i:"<<i<<"a "<<a[i]<<" b "<<b[i]);
#ifndef FASTNLOOSE 
		x[i]=a[i].ModMul(b[i],m_modulus); //inmplicit modulo mul
#else
		x[i]=a[i].ModMulFast(b[i],m_modulus); //inmplicit modulo mul
#endif
	}
	DEBUG("myvecp::done");
	//todo make modulus explicit.
}

} // namespace NTL ends

template class NTL::myVecP<NTL::myZZ>;
