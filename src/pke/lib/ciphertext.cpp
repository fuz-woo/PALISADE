/*
* @file ciphertext.cpp - ciphertext class implementation
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

#include "ciphertext.h"

namespace lbcrypto {

template <typename Element>
bool CiphertextImpl<Element>::Serialize(Serialized* serObj) const {
	serObj->SetObject();

	if( !this->SerializeCryptoObject(serObj) )
		return false;

	serObj->AddMember("Object", "Ciphertext", serObj->GetAllocator());
	serObj->AddMember("Depth", std::to_string(m_depth), serObj->GetAllocator());
	serObj->AddMember("EncodingType", std::to_string(this->encodingType), serObj->GetAllocator());
	SerializeVector("Elements", Element::GetElementName(), this->m_elements, serObj);

	return true;
}

template <typename Element>
bool CiphertextImpl<Element>::Deserialize(const Serialized& serObj) {

	// deserialization must be done in a crypto context; the context must be initialized before deserializing the elements
	if( !this->GetCryptoContext() )
		return false;

	// get the KeyTag
	if( !this->DeserializeCryptoObject(serObj, false) )
		return false;

	Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "Ciphertext" )
		return false;

	mIter = serObj.FindMember("Depth");
	if( mIter == serObj.MemberEnd() )
		return false;
	m_depth = std::stoul(mIter->value.GetString());

	mIter = serObj.FindMember("EncodingType");
	if( mIter == serObj.MemberEnd() )
		return false;
	this->encodingType = (PlaintextEncodings)std::stoi(mIter->value.GetString());

	mIter = serObj.FindMember("Elements");
	if( mIter == serObj.MemberEnd() )
		return false;

	if( !DeserializeVector<Element>("Elements", this->m_elements[0].GetElementName(), mIter, &this->m_elements) )
		return false;

	return true;
}

}
