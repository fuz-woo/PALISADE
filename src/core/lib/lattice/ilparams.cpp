/*
 * @file ildcrtparams.cpp - parameters for generalized parameters for integer lattices.
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

#include "ilparams.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto
{


/**
* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
*
* @param serObj stores this object's serialized attribute name value pairs.
* @return map updated with the attribute name value pairs required to serialize this object.
*/
template<typename IntType>
bool ILParamsImpl<IntType>::Serialize(Serialized* serObj) const
{
  
        if( !serObj->IsObject() ){
	  serObj->SetObject();
	}

	SerialItem ser(rapidjson::kObjectType);
	ser.AddMember("Order", std::to_string(this->cyclotomicOrder), serObj->GetAllocator());
	ser.AddMember("RingDim", std::to_string(this->ringDimension), serObj->GetAllocator());
	ser.AddMember("CtModulus", this->ciphertextModulus.ToString(), serObj->GetAllocator());
	ser.AddMember("RootOfUnity", this->rootOfUnity.ToString(), serObj->GetAllocator());
	ser.AddMember("BigCtModulus", this->bigCiphertextModulus.ToString(), serObj->GetAllocator());
	ser.AddMember("BigRootOfUnity", this->bigRootOfUnity.ToString(), serObj->GetAllocator());

	serObj->AddMember("ILParams", ser, serObj->GetAllocator());

	return true;
}

//JSON FACILITY
/**
* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
*
* @param serObj stores this object's serialized attribute name value pairs.
*/
template<typename IntType>
bool ILParamsImpl<IntType>::Deserialize(const Serialized& serObj)
{

	Serialized::ConstMemberIterator mIter = serObj.FindMember("ILParams");
	if( mIter == serObj.MemberEnd() ) {
		return false;
	}

	SerialItem::ConstMemberIterator oIt;

	if( (oIt = mIter->value.FindMember("Order")) == mIter->value.MemberEnd() )
		return false;
	usint order = atoi(oIt->value.GetString());

	if( (oIt = mIter->value.FindMember("RingDim")) == mIter->value.MemberEnd() )
		return false;
	usint ringdim = atoi(oIt->value.GetString());

	if( (oIt = mIter->value.FindMember("CtModulus")) == mIter->value.MemberEnd() )
		return false;
	IntType CtModulus(oIt->value.GetString());

	if( (oIt = mIter->value.FindMember("RootOfUnity")) == mIter->value.MemberEnd() )
		return false;
	IntType RootOfUnity(oIt->value.GetString());

	if( (oIt = mIter->value.FindMember("BigCtModulus")) == mIter->value.MemberEnd() )
		return false;
	IntType BigCtModulus(oIt->value.GetString());

	if( (oIt = mIter->value.FindMember("BigRootOfUnity")) == mIter->value.MemberEnd() )
		return false;
	IntType BigRootOfUnity(oIt->value.GetString());

	this->cyclotomicOrder = order;
	this->ringDimension = ringdim;
	this->isPowerOfTwo = this->ringDimension == this->cyclotomicOrder / 2;
	this->ciphertextModulus = CtModulus;
	this->rootOfUnity = RootOfUnity;
	this->bigCiphertextModulus = BigCtModulus;
	this->bigRootOfUnity = BigRootOfUnity;

	return true;
}


} // namespace lbcrypto ends
