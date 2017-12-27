/**
 * @file encodingparams.cpp Represents and defines parameters for plaintext encoding.
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

#include "encodingparams.h"

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
bool EncodingParamsImpl::Serialize(Serialized* serObj) const
{

	if (!serObj->IsObject())
		return false;

	SerialItem ser(rapidjson::kObjectType);
	ser.AddMember("PlaintextModulus", std::to_string(this->m_plaintextModulus), serObj->GetAllocator());
	ser.AddMember("PlaintextRootOfUnity", this->m_plaintextRootOfUnity.ToString(), serObj->GetAllocator());
	ser.AddMember("PlaintextBigModulus", this->m_plaintextBigModulus.ToString(), serObj->GetAllocator());
	ser.AddMember("PlaintextBigRootOfUnity", this->m_plaintextBigRootOfUnity.ToString(), serObj->GetAllocator());
	ser.AddMember("PlaintextGenerator", std::to_string(this->m_plaintextGenerator), serObj->GetAllocator());
	ser.AddMember("BatchSize", std::to_string(this->m_batchSize), serObj->GetAllocator());

	serObj->AddMember("EncodingParams", ser.Move(), serObj->GetAllocator());

	return true;

}

/**
* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
*
* @param serObj stores this object's serialized attribute name value pairs.
*/
bool EncodingParamsImpl::Deserialize(const Serialized& serObj)
{

	Serialized::ConstMemberIterator mIter = serObj.FindMember("EncodingParams");
	if (mIter == serObj.MemberEnd()) {
		return false;
	}

	SerialItem::ConstMemberIterator oIt;

	if ((oIt = mIter->value.FindMember("PlaintextModulus")) == mIter->value.MemberEnd())
		return false;
	PlaintextModulus plaintextModulus = atoi(oIt->value.GetString());

	if ((oIt = mIter->value.FindMember("PlaintextRootOfUnity")) == mIter->value.MemberEnd())
		return false;
	NativeInteger plaintextRootOfUnity(atoi(oIt->value.GetString()));

	if ((oIt = mIter->value.FindMember("PlaintextBigModulus")) == mIter->value.MemberEnd())
		return false;
	NativeInteger plaintextBigModulus(oIt->value.GetString());

	if ((oIt = mIter->value.FindMember("PlaintextBigRootOfUnity")) == mIter->value.MemberEnd())
		return false;
	NativeInteger plaintextBigRootOfUnity(oIt->value.GetString());

	if ((oIt = mIter->value.FindMember("PlaintextGenerator")) == mIter->value.MemberEnd())
		return false;
	usint plaintextGenerator = atoi(oIt->value.GetString());

	if ((oIt = mIter->value.FindMember("BatchSize")) == mIter->value.MemberEnd())
		return false;
	usint batchSize = atoi(oIt->value.GetString());

	this->m_plaintextModulus = plaintextModulus;
	this->m_plaintextRootOfUnity = plaintextRootOfUnity;
	this->m_plaintextBigModulus = plaintextBigModulus;
	this->m_plaintextBigRootOfUnity = plaintextBigRootOfUnity;
	this->m_plaintextGenerator = plaintextGenerator;
	this->m_batchSize = batchSize;

	return true;

}

} // namespace lbcrypto ends
