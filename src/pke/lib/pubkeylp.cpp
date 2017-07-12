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
bool LPPublicKey<Element>::Serialize(Serialized *serObj) const {
	serObj->SetObject();

	if (!this->context->Serialize(serObj)) {
		return false;
	}

	serObj->AddMember("Object", "PublicKey", serObj->GetAllocator());
	SerializeVector<Element>("Vectors", Element::GetElementName(), this->GetPublicElements(), serObj);

	return true;
}

template<typename Element>
bool LPPublicKey<Element>::Deserialize(const Serialized &serObj) {

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
static bool EvalKeyRelinSerializer(const LPEvalKeyRelin<Element> *item, Serialized *serObj, bool doContext) {
	serObj->SetObject();

	if( doContext ) {
		if (!item->GetCryptoContext()->Serialize(serObj)) {
			return false;
		}
	}

	serObj->AddMember("Object", "EvalKeyRelin", serObj->GetAllocator());
	SerializeVector<Element>("AVector", Element::GetElementName(), item->GetAVector(), serObj);
	SerializeVector<Element>("BVector", Element::GetElementName(), item->GetBVector(), serObj);

	return true;
}

template<typename Element>
bool LPEvalKeyRelin<Element>::Serialize(Serialized *serObj) const {
	return EvalKeyRelinSerializer<Element>(this, serObj, true);
}

template<typename Element>
bool LPEvalKeyRelin<Element>::SerializeWithoutContext(Serialized *serObj) const {
	return EvalKeyRelinSerializer<Element>(this, serObj, false);
}

template<typename Element>
bool LPEvalKeyRelin<Element>::Deserialize(const Serialized &serObj) {

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
static bool EvalKeyNTRUSerializer(const LPEvalKeyNTRU<Element> *item, Serialized *serObj, bool doContext) {
	serObj->SetObject();

	if( doContext ) {
		if (!item->GetCryptoContext()->Serialize(serObj)) {
			return false;
		}
	}

	serObj->AddMember("Object", "EvalKeyNTRU", serObj->GetAllocator());

	const Element& pe = item->GetA();

	if (!pe.Serialize(serObj)) {
		return false;
	}

	return true;
}

template<typename Element>
bool LPEvalKeyNTRU<Element>::Serialize(Serialized *serObj) const {
	return EvalKeyNTRUSerializer<Element>(this, serObj, true);
}

template<typename Element>
bool LPEvalKeyNTRU<Element>::SerializeWithoutContext(Serialized *serObj) const {
	return EvalKeyNTRUSerializer<Element>(this, serObj, false);
}

template<typename Element>
bool LPEvalKeyNTRU<Element>::Deserialize(const Serialized &serObj) {
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
static bool EvalKeyNTRURelinSerializer(const LPEvalKeyNTRURelin<Element> *item, Serialized *serObj, bool doContext) {
	serObj->SetObject();

	if( doContext ) {
		if (!item->GetCryptoContext()->Serialize(serObj)) {
			return false;
		}
	}

	serObj->AddMember("Object", "EvalKeyNTRURelin", serObj->GetAllocator());
	SerializeVector<Element>("Vectors", Element::GetElementName(), item->GetAVector(), serObj);

	return true;
}

template<typename Element>
bool LPEvalKeyNTRURelin<Element>::Serialize(Serialized *serObj) const {
	return EvalKeyNTRURelinSerializer<Element>(this, serObj, true);
}

template<typename Element>
bool LPEvalKeyNTRURelin<Element>::SerializeWithoutContext(Serialized *serObj) const {
	return EvalKeyNTRURelinSerializer<Element>(this, serObj, false);
}

template<typename Element>
bool LPEvalKeyNTRURelin<Element>::Deserialize(const Serialized &serObj) {
	Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
	if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyNTRURelin" )
		return false;

	SerialItem::ConstMemberIterator it = serObj.FindMember("Vectors");

	if( it == serObj.MemberEnd() ) {
		return false;
	}

	std::vector<Element> newElements;
	if( DeserializeVector<Element>("Vectors", Element::GetElementName(), it, &newElements) ) {
		this->SetAVector(newElements);
		return true;
	}

	return false;
}


}
