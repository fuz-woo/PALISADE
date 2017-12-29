/*
 * @file pubkeylp.cpp - public key implementation
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
 
#include "cryptocontext.h"
#include "pubkeylp.h"

namespace lbcrypto {

template<typename Element>
bool LPPublicKeyImpl<Element>::Serialize(Serialized *serObj) const {
	serObj->SetObject();

	if( !this->SerializeCryptoObject(serObj) )
		return false;

	serObj->AddMember("Object", "PublicKey", serObj->GetAllocator());
	SerializeVector<Element>("Vectors", Element::GetElementName(), this->GetPublicElements(), serObj);

	return true;
}

template<typename Element>
bool LPPublicKeyImpl<Element>::Deserialize(const Serialized &serObj) {

	// deserialization must be done in a crypto context; the context must be initialized before deserializing the elements
	if( !this->GetCryptoContext() )
		return false;

	// get the KeyTag
	if( !this->DeserializeCryptoObject(serObj, false) )
		return false;

	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "PublicKey" )
		return false;

	mIt = serObj.FindMember("Vectors");

	if( mIt == serObj.MemberEnd() ) {
		return false;
	}

	bool ret = DeserializeVector<Element>("Vectors", Element::GetElementName(), mIt, &this->m_h);

	return ret;
}

template<typename Element>
static bool EvalKeyRelinSerializer(const LPEvalKeyRelinImpl<Element> *item, Serialized *serObj, bool doContext) {
	serObj->SetObject();

	if( !item->SerializeCryptoObject(serObj, doContext) )
		return false;

	serObj->AddMember("Object", "EvalKeyRelin", serObj->GetAllocator());
	SerializeVector<Element>("AVector", Element::GetElementName(), item->GetAVector(), serObj);
	SerializeVector<Element>("BVector", Element::GetElementName(), item->GetBVector(), serObj);

	return true;
}

template<typename Element>
bool LPEvalKeyRelinImpl<Element>::Serialize(Serialized *serObj) const {
	return EvalKeyRelinSerializer<Element>(this, serObj, true);
}

template<typename Element>
bool LPEvalKeyRelinImpl<Element>::SerializeWithoutContext(Serialized *serObj) const {
	return EvalKeyRelinSerializer<Element>(this, serObj, false);
}

template<typename Element>
bool LPEvalKeyRelinImpl<Element>::Deserialize(const Serialized &serObj) {

	// deserialization must be done in a crypto context; the context must be initialized before deserializing the elements
	if( !this->GetCryptoContext() )
		return false;

	// get the KeyTag
	if( !this->DeserializeCryptoObject(serObj, false) )
		return false;

	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyRelin" )
		return false;

	mIt = serObj.FindMember("AVector");

	if( mIt == serObj.MemberEnd() ) {
		return false;
	}

	std::vector<Element> deserElem;
	bool ret = DeserializeVector<Element>("AVector", Element::GetElementName(), mIt, &deserElem);
	this->m_rKey.push_back(deserElem);

	if( !ret ) return ret;

	mIt = serObj.FindMember("BVector");

	if( mIt == serObj.MemberEnd() ) {
		return false;
	}

	ret = DeserializeVector<Element>("BVector", Element::GetElementName(), mIt, &deserElem);
	this->m_rKey.push_back(deserElem);

	return ret;
}

template<typename Element>
static bool EvalKeyNTRUSerializer(const LPEvalKeyNTRUImpl<Element> *item, Serialized *serObj, bool doContext) {
	serObj->SetObject();

	if( !item->SerializeCryptoObject(serObj, doContext) )
		return false;

	serObj->AddMember("Object", "EvalKeyNTRU", serObj->GetAllocator());

	const Element& pe = item->GetA();

	if (!pe.Serialize(serObj)) {
		return false;
	}

	return true;
}

template<typename Element>
bool LPEvalKeyNTRUImpl<Element>::Serialize(Serialized *serObj) const {
	return EvalKeyNTRUSerializer<Element>(this, serObj, true);
}

template<typename Element>
bool LPEvalKeyNTRUImpl<Element>::SerializeWithoutContext(Serialized *serObj) const {
	return EvalKeyNTRUSerializer<Element>(this, serObj, false);
}

template<typename Element>
bool LPEvalKeyNTRUImpl<Element>::Deserialize(const Serialized &serObj) {
	// deserialization must be done in a crypto context; the context must be initialized before deserializing the elements
	if( !this->GetCryptoContext() )
		return false;

	// get the KeyTag
	if( !this->DeserializeCryptoObject(serObj, false) )
		return false;

	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyNTRU" )
		return false;

	Element pe;

	if( !pe.Deserialize(serObj) ) {
		return false;
	}

	m_Key = pe;

	return true;
}

template<typename Element>
static bool EvalKeyNTRURelinSerializer(const LPEvalKeyNTRURelinImpl<Element> *item, Serialized *serObj, bool doContext) {
	serObj->SetObject();

	if( !item->SerializeCryptoObject(serObj, doContext) )
		return false;

	serObj->AddMember("Object", "EvalKeyNTRURelin", serObj->GetAllocator());
	SerializeVector<Element>("Vectors", Element::GetElementName(), item->GetAVector(), serObj);

	return true;
}

template<typename Element>
bool LPEvalKeyNTRURelinImpl<Element>::Serialize(Serialized *serObj) const {
	return EvalKeyNTRURelinSerializer<Element>(this, serObj, true);
}

template<typename Element>
bool LPEvalKeyNTRURelinImpl<Element>::SerializeWithoutContext(Serialized *serObj) const {
	return EvalKeyNTRURelinSerializer<Element>(this, serObj, false);
}

template<typename Element>
bool LPEvalKeyNTRURelinImpl<Element>::Deserialize(const Serialized &serObj) {
	// deserialization must be done in a crypto context; the context must be initialized before deserializing the elements
	if( !this->GetCryptoContext() )
		return false;

	// get the KeyTag
	if( !this->DeserializeCryptoObject(serObj, false) )
		return false;

	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyNTRURelin" )
		return false;

	mIt = serObj.FindMember("Vectors");

	if( mIt == serObj.MemberEnd() ) {
		return false;
	}

	std::vector<Element> newElements;
	if( DeserializeVector<Element>("Vectors", Element::GetElementName(), mIt, &newElements) ) {
		this->SetAVector(newElements);
		return true;
	}

	return false;
}

template<typename Element>
bool LPPrivateKeyImpl<Element>::Serialize(Serialized *serObj) const {
	serObj->SetObject();

	if( !this->SerializeCryptoObject(serObj) )
		return false;

	serObj->AddMember("Object", "PrivateKey", serObj->GetAllocator());
	return this->GetPrivateElement().Serialize(serObj);
}

template<typename Element>
bool LPPrivateKeyImpl<Element>::Deserialize(const Serialized &serObj) {
	// deserialization must be done in a crypto context; the context must be initialized before deserializing the elements
	if( !this->GetCryptoContext() )
		return false;

	// get the KeyTag
	if( !this->DeserializeCryptoObject(serObj, false) )
		return false;

	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "PrivateKey" )
		return false;

	Element json_ilElement;
	if (json_ilElement.Deserialize(serObj)) {
		this->SetPrivateElement(json_ilElement);
		return true;
	}
	return false;

}

}
