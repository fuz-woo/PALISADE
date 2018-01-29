/*
 * @file ildcrtparams.cpp - parameters for generalized double-crt parameters.
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
#include "ildcrtparams.h"
#include "../utils/serializablehelper.h"


namespace lbcrypto
{

template<typename IntType>
ILDCRTParams<IntType>::ILDCRTParams(usint order, usint depth, usint bits) : ElemParams<IntType>(order, 0, 0, 0, 0)
{
	if( order == 0 )
		return;
	if( depth == 0 )
		throw std::logic_error("Invalid depth for ILDCRTParams");
	if( bits == 0 || bits > 64 )
		throw std::logic_error("Invalid bits for ILDCRTParams");

	m_parms.resize(depth);
	this->ciphertextModulus = IntType(0);

	NativeInteger q = FirstPrime<NativeInteger>(bits, order);

	for(size_t j = 0; ;) {
		NativeInteger root = RootOfUnity<NativeInteger>(order, q);
		std::shared_ptr<ILNativeParams> p( new ILNativeParams(order, q, root) );
		m_parms[j] = p;

		if( ++j >= depth )
			break;

		q = NextPrime<NativeInteger>(q, order);
	}

	RecalculateModulus();
}

template<typename IntType>
bool
ILDCRTParams<IntType>::Serialize(Serialized* serObj) const
{
	if( !serObj->IsObject() )
		return false;

	Serialized ser(rapidjson::kObjectType, &serObj->GetAllocator());

	SerializeVectorOfPointers<ILNativeParams>("Params", "ILParams", m_parms, &ser);

	serObj->AddMember("ILDCRTParams", ser, serObj->GetAllocator());

	return true;
}

template<typename IntType>
bool
ILDCRTParams<IntType>::Deserialize(const Serialized& serObj)
{
	Serialized::ConstMemberIterator rIt = serObj.FindMember("ILDCRTParams");
	if( rIt == serObj.MemberEnd() ) return false;

	const SerialItem& arr = rIt->value;

	Serialized::ConstMemberIterator it = arr.FindMember("Params");

	if( it == arr.MemberEnd() ) {
		return false;
	}

	if( DeserializeVectorOfPointers<ILNativeParams>("Params", "ILParams", it, &this->m_parms) == false )
		return false;

	this->cyclotomicOrder = this->m_parms[0]->GetCyclotomicOrder();
	this->ringDimension = this->m_parms[0]->GetRingDimension();
	this->isPowerOfTwo = this->ringDimension == this->cyclotomicOrder / 2;

	RecalculateModulus();
	return true;
}


}
