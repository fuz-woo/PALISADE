/*
* @file bfvrns.cpp - implementation of the BFVrns scheme.
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
Description:	

This code implements a RNS variant of the Brakerski-Fan-Vercauteren (BFV) homomorphic encryption scheme.  This scheme is also referred to as the FV scheme.

The BFV scheme is introduced in the following papers:
   - Zvika Brakerski (2012). Fully Homomorphic Encryption without Modulus Switching from Classical GapSVP. Cryptology ePrint Archive, Report 2012/078. (https://eprint.iacr.org/2012/078)
   - Junfeng Fan and Frederik Vercauteren (2012). Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)

 Our implementation builds from the designs here:
   - Halevi S. and Polyakov Y. (in preparation, 2018) A Simpler, Faster RNS Variant of the BFV Homomorphic Encryption Scheme.
   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
   - Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent Zucca (2016). A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes. Cryptology ePrint Archive, Report 2016/510. (https://eprint.iacr.org/2016/510)

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef LBCRYPTO_CRYPTO_BFVRNS_C
#define LBCRYPTO_CRYPTO_BFVRNS_C

#include "bfvrns.h"
#include <iostream>
#include <fstream>

namespace lbcrypto {

template <class Element>
LPCryptoParametersBFVrns<Element>::LPCryptoParametersBFVrns() : LPCryptoParametersRLWE<Element>() {}

template <class Element>
LPCryptoParametersBFVrns<Element>::LPCryptoParametersBFVrns(const LPCryptoParametersBFVrns &rhs) : LPCryptoParametersRLWE<Element>(rhs) {}

template <class Element>
LPCryptoParametersBFVrns<Element>::LPCryptoParametersBFVrns(shared_ptr<typename Element::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth)
			: LPCryptoParametersRLWE<Element>(params,
				EncodingParams( new EncodingParamsImpl(plaintextModulus) ),
				distributionParameter,
				assuranceMeasure,
				securityLevel,
				relinWindow,
				depth,
				maxDepth,
				mode) {
	}

template <class Element>
LPCryptoParametersBFVrns<Element>::LPCryptoParametersBFVrns(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth)
		: LPCryptoParametersRLWE<Element>(params,
			encodingParams,
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth,
			maxDepth,
			mode) {
	}

template <class Element>
bool LPCryptoParametersBFVrns<Element>::Serialize(Serialized* serObj) const {
	if (!serObj->IsObject())
		return false;

	SerialItem cryptoParamsMap(rapidjson::kObjectType);
	if (this->SerializeRLWE(serObj, cryptoParamsMap) == false)
		return false;

	serObj->AddMember("LPCryptoParametersBFVrns", cryptoParamsMap.Move(), serObj->GetAllocator());
	serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersBFVrns", serObj->GetAllocator());

	return true;
}

template <class Element>
bool LPCryptoParametersBFVrns<Element>::Deserialize(const Serialized& serObj) {
	Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersBFVrns");
	if (mIter == serObj.MemberEnd()) return false;

	if (this->DeserializeRLWE(mIter) == false)
		return false;

	SerialItem::ConstMemberIterator pIt;

	return PrecomputeCRTTables();
}

// Enable for LPPublicKeyEncryptionSchemeBFV
template <class Element>
void LPPublicKeyEncryptionSchemeBFVrns<Element>::Enable(PKESchemeFeature feature) {
	switch (feature)
	{
	case ENCRYPTION:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBFVrns<Element>();
		break;
	case SHE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBFVrns<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEBFVrns<Element>();
		break;
	case PRE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBFVrns<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEBFVrns<Element>();
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPREBFVrns<Element>();
		break; 
	case MULTIPARTY:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBFVrns<Element>();
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPREBFVrns<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEBFVrns<Element>();
		if (this->m_algorithmMultiparty == NULL)
			this->m_algorithmMultiparty = new LPAlgorithmMultipartyBFVrns<Element>();
		break; 
	case FHE:
		throw std::logic_error("FHE feature not supported for BFVrns scheme");
	case LEVELEDSHE:
		throw std::logic_error("LEVELEDSHE feature not supported for BFVrns scheme");
	}
}

template <class Element>
LPPublicKeyEncryptionSchemeBFVrns<Element>::LPPublicKeyEncryptionSchemeBFVrns() : LPPublicKeyEncryptionScheme<Element>() {
			this->m_algorithmParamsGen = new LPAlgorithmParamsGenBFVrns<Element>();
		}


}  // namespace lbcrypto ends

#endif
