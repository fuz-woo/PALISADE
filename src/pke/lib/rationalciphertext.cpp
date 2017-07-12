/*
* @file rationalciphertext.cpp - rational ciphertext class implementation
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

#include "rationalciphertext.h"

namespace lbcrypto {

template<class Element>
bool RationalCiphertext<Element>::Serialize(Serialized* serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "RationalCiphertext", serObj->GetAllocator());

	Serialized numSer(rapidjson::kObjectType, &serObj->GetAllocator());
	if( !m_numerator->Serialize(&numSer) )
		return false;

	// note only serialize denominator if it's not an integer
	Serialized denSer(rapidjson::kObjectType, &serObj->GetAllocator());
	if( !m_integerFlag && !m_denominator->Serialize(&denSer) )
		return false;

	serObj->AddMember("isInteger", m_integerFlag ? std::to_string(1) : std::to_string(0), serObj->GetAllocator());
	serObj->AddMember("numerator", numSer.Move(), serObj->GetAllocator());
	if( !m_integerFlag )
		serObj->AddMember("denominator", denSer.Move(), serObj->GetAllocator());

	return true;
}

/**
 * Populate the object from the deserialization of the Serialized
 * @param serObj contains the serialized object
 * @return true on success
 */
template<class Element>
bool RationalCiphertext<Element>::Deserialize(const Serialized& serObj) {
	// deserialization must be done in a crypto context; this object must be initialized before deserializing the elements
	//if( !this->cryptoContext )
	//	return false;

	Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "RationalCiphertext" )
		return false;

	mIter = serObj.FindMember("isInteger");
	if( mIter == serObj.MemberEnd() )
		return false;

	string flagString = mIter->value.GetString();

	m_integerFlag = (flagString == "1") ? true : false;

	mIter = serObj.FindMember("numerator");
	if( mIter == serObj.MemberEnd() )
		return false;

	Serialized oneItem(rapidjson::kObjectType);
	SerialItem val( mIter->value, oneItem.GetAllocator() );
	val.Swap(oneItem);

	if( !m_numerator->Deserialize(oneItem) ) {
		return false;
	}

	if( !m_integerFlag ) {
		mIter = serObj.FindMember("denominator");
		if( mIter == serObj.MemberEnd() )
			return false;

		Serialized oneItem(rapidjson::kObjectType);
		SerialItem val( mIter->value, oneItem.GetAllocator() );
		val.Swap(oneItem);

		if( !m_denominator->Deserialize(oneItem) ) {
			return false;
		}
	}
	else {
		m_denominator.reset();
	}

	return true;
}

}


