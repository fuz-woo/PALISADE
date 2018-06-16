/*
 * @file elemparams.cpp - element parameters for palisade
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

#include "elemparams.h"

namespace lbcrypto
{

/**
* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
*
* @param serObj stores this object's serialized attribute name value pairs.
* @return map updated with the attribute name value pairs required to serialize this object.
*/
template<typename IntType>
bool ElemParams<IntType>::Serialize(Serialized* serObj) const
{
        if( !serObj->IsObject() ){
	  serObj->SetObject();
	}

	SerialItem ser(rapidjson::kObjectType);
	ser.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator());
	ser.AddMember("Order", std::to_string(this->GetCyclotomicOrder()), serObj->GetAllocator());

	serObj->AddMember("ElemParams", ser, serObj->GetAllocator());

	return true;
}

/**
* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
*
* @param serObj stores this object's serialized attribute name value pairs.
*/
template<typename IntType>
bool ElemParams<IntType>::Deserialize(const Serialized& serObj)
{

	Serialized::ConstMemberIterator mIter = serObj.FindMember("ElemParams");
	if( mIter == serObj.MemberEnd() ) {
		return false;
	}

	SerialItem::ConstMemberIterator oIt;

	if( (oIt = mIter->value.FindMember("Modulus")) == mIter->value.MemberEnd() )
		return false;
	IntType modulus(oIt->value.GetString());

	if( (oIt = mIter->value.FindMember("Order")) == mIter->value.MemberEnd() )
		return false;
	usint order = atoi(oIt->value.GetString());

	cyclotomicOrder = order;
	ringDimension = GetTotient(order);
	isPowerOfTwo = cyclotomicOrder/2 == ringDimension;
	ciphertextModulus = modulus;
	return true;
}


} // namespace lbcrypto ends
