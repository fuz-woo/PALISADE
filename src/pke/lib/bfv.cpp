/*
* @file bfv.cpp - implementation of the BFV scheme.
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

 This code implements the Fan-Vercauteren (BFV) homomorphic encryption scheme.
 The BFV scheme is introduced in https://eprint.iacr.org/2012/144.pdf and originally implemented in https://eprint.iacr.org/2014/062.pdf 
 (this paper has optimized correctness constraints, which are used here as well). 

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef LBCRYPTO_CRYPTO_BFV_C
#define LBCRYPTO_CRYPTO_BFV_C

#include "bfv.h"
#include <iostream>
#include <fstream>

namespace lbcrypto {

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV() : LPCryptoParametersRLWE<Element>() {
	m_delta = typename Element::Integer(0);
	m_bigModulus = typename Element::Integer(0);
	m_bigRootOfUnity = typename Element::Integer(0);
	m_bigModulusArb = typename Element::Integer(0);
	m_bigRootOfUnityArb = typename Element::Integer(0);
}

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV(const LPCryptoParametersBFV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {
	m_delta = rhs.m_delta;
	m_bigModulus = rhs.m_bigModulus;
	m_bigRootOfUnity = rhs.m_bigRootOfUnity;
	m_bigModulusArb = rhs.m_bigModulusArb;
	m_bigRootOfUnityArb = rhs.m_bigRootOfUnityArb;
}

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV(shared_ptr<typename Element::Params> params,
	const PlaintextModulus &plaintextModulus,
	float distributionParameter,
	float assuranceMeasure,
	float securityLevel,
	usint relinWindow,
	const typename Element::Integer &delta,
	MODE mode,
	const typename Element::Integer &bigModulus ,
	const typename Element::Integer &bigRootOfUnity,
	const typename Element::Integer &bigModulusArb,
	const typename Element::Integer &bigRootOfUnityArb,
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
			m_delta = delta;
			m_bigModulus = bigModulus;
			m_bigRootOfUnity = bigRootOfUnity;
			m_bigModulusArb = bigModulusArb;
			m_bigRootOfUnityArb = bigRootOfUnityArb;
		}

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV(shared_ptr<typename Element::Params> params,
	EncodingParams encodingParams,
	float distributionParameter,
	float assuranceMeasure,
	float securityLevel,
	usint relinWindow,
	const typename Element::Integer &delta,
	MODE mode,
	const typename Element::Integer &bigModulus ,
	const typename Element::Integer &bigRootOfUnity,
	const typename Element::Integer &bigModulusArb,
	const typename Element::Integer &bigRootOfUnityArb,
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
	m_delta = delta;
	m_bigModulus = bigModulus;
	m_bigRootOfUnity = bigRootOfUnity;
	m_bigModulusArb = bigModulusArb;
	m_bigRootOfUnityArb = bigRootOfUnityArb;
}

template <class Element>
bool LPCryptoParametersBFV<Element>::Serialize(Serialized* serObj) const {
	if (!serObj->IsObject())
		return false;

	SerialItem cryptoParamsMap(rapidjson::kObjectType);
	if (this->SerializeRLWE(serObj, cryptoParamsMap) == false)
		return false;

	cryptoParamsMap.AddMember("delta", m_delta.ToString(), serObj->GetAllocator());
	cryptoParamsMap.AddMember("bigmodulus", m_bigModulus.ToString(), serObj->GetAllocator());
	cryptoParamsMap.AddMember("bigrootofunity", m_bigRootOfUnity.ToString(), serObj->GetAllocator());
	cryptoParamsMap.AddMember("bigmodulusarb", m_bigModulusArb.ToString(), serObj->GetAllocator());
	cryptoParamsMap.AddMember("bigrootofunityarb", m_bigRootOfUnityArb.ToString(), serObj->GetAllocator());

	serObj->AddMember("LPCryptoParametersBFV", cryptoParamsMap.Move(), serObj->GetAllocator());
	serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersBFV", serObj->GetAllocator());

	return true;
}

template <class Element>
bool LPCryptoParametersBFV<Element>::Deserialize(const Serialized& serObj) {
	Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersBFV");
	if (mIter == serObj.MemberEnd()) return false;

	if (this->DeserializeRLWE(mIter) == false)
		return false;

	SerialItem::ConstMemberIterator pIt;
	if ((pIt = mIter->value.FindMember("delta")) == mIter->value.MemberEnd())
		return false;
	typename Element::Integer delta(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("bigmodulus")) == mIter->value.MemberEnd())
		return false;
	typename Element::Integer bigmodulus(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("bigrootofunity")) == mIter->value.MemberEnd())
		return false;
	typename Element::Integer bigrootofunity(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("bigmodulusarb")) == mIter->value.MemberEnd())
		return false;
	typename Element::Integer bigmodulusarb(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("bigrootofunityarb")) == mIter->value.MemberEnd())
		return false;
	typename Element::Integer bigrootofunityarb(pIt->value.GetString());

	this->SetBigModulus(bigmodulus);
	this->SetBigRootOfUnity(bigrootofunity);
	this->SetBigModulusArb(bigmodulusarb);
	this->SetBigRootOfUnityArb(bigrootofunityarb);
	this->SetDelta(delta);

	return true;
}

template <class Element>
bool LPAlgorithmParamsGenBFV<Element>::ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount) const
{

	if (!cryptoParams)
		return false;

	const shared_ptr<LPCryptoParametersBFV<Element>> cryptoParamsBFV = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(cryptoParams);

	double sigma = cryptoParamsBFV->GetDistributionParameter();
	double alpha = cryptoParamsBFV->GetAssuranceMeasure();
	double hermiteFactor = cryptoParamsBFV->GetSecurityLevel();
	double p = cryptoParamsBFV->GetPlaintextModulus();
	uint32_t r = cryptoParamsBFV->GetRelinWindow();

	//Bound of the Gaussian error polynomial
	double Berr = sigma*sqrt(alpha);

	//Bound of the key polynomial
	double Bkey;
	
	//supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParamsBFV->GetMode() == RLWE)
		Bkey = sigma*sqrt(alpha);
	else
		Bkey = 1;

	//expansion factor delta
	auto delta = [](uint32_t n) -> double { return sqrt(n); };

	//norm of fresh ciphertext polynomial
	auto Vnorm = [&](uint32_t n) -> double { return Berr*(1+2*delta(n)*Bkey);  };

	//RLWE security constraint
	auto nRLWE = [&](double q) -> double { return log2(q / sigma) / (4 * log2(hermiteFactor));  };

	//initial values
	uint32_t n = 512;
	double q = 0;
	
	//only public key encryption and EvalAdd (optional when evalAddCount = 0) operations are supported
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	if ((evalMultCount == 0) && (keySwitchCount == 0)) {

		//Correctness constraint
		auto qBFV = [&](uint32_t n) -> double { return p*(2*((evalAddCount+1)*Vnorm(n) + evalAddCount*p) + p);  };

		//initial value
		q = qBFV(n);

		while (nRLWE(q) > n) {
			n = 2 * n;
			q = qBFV(n);
		}

	} 
	// this case supports re-encryption and automorphism w/o any other operations
	else if ((evalMultCount == 0) && (keySwitchCount > 0) && (evalAddCount == 0)) {

		//base for relinearization
		double w = pow(2, r);

		//Correctness constraint
		auto qBFV = [&](uint32_t n, double qPrev) -> double { return p*(2*(Vnorm(n) + keySwitchCount*delta(n)*(floor(log2(qPrev) / r) + 1)*w*Berr) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qBFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q 
		//changes the requirement for n, which is rare but still theortically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				qPrev = q;
			}

			q = qBFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qBFV(n, qPrev);
			}

		}

	}
	//Only EvalMult operations are used in the correctness constraint
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	else if ((evalAddCount == 0) && (evalMultCount > 0) && (keySwitchCount == 0))
	{

		//base for relinearization
		double w = pow(2, r);

		//function used in the EvalMult constraint
		auto epsilon1 = [&](uint32_t n) -> double { return 4 / (delta(n)*Bkey);  };

		//function used in the EvalMult constraint
		auto C1 = [&](uint32_t n) -> double { return (1 + epsilon1(n))*delta(n)*delta(n)*p*Bkey;  };

		//function used in the EvalMult constraint
		auto C2 = [&](uint32_t n, double qPrev) -> double { return delta(n)*delta(n)*Bkey*(Bkey + p*p) + delta(n)*(floor(log2(qPrev) / r) + 1)*w*Berr;  };

		//main correctness constraint
		auto qBFV = [&](uint32_t n, double qPrev) -> double { return p*(2 * (pow(C1(n), evalMultCount)*Vnorm(n) + evalMultCount*pow(C1(n), evalMultCount - 1)*C2(n, qPrev)) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qBFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q 
		//changes the requirement for n, which is rare but still theortically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				qPrev = q;
			}

			q = qBFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qBFV(n, qPrev);
			}

		}

	}

	if (ceil(log2(q))+1 > 125)
		PALISADE_THROW( lbcrypto::math_error, "BFV cannot autogenerate parameters for this case, please use BFVrns instead.");

	typename Element::Integer qPrime = FirstPrime<typename Element::Integer>(ceil(log2(q))+1, 2*n);
	typename Element::Integer rootOfUnity = RootOfUnity<typename Element::Integer>(2 * n, qPrime);

	//reserves enough digits to avoid wrap-around when evaluating p*(c1*c2+c3*c4)
	typename Element::Integer qPrime2 = FirstPrime<typename Element::Integer>(2*(ceil(log2(q)) + 1) + ceil(log2(p)) + 3, 2 * n);
	typename Element::Integer rootOfUnity2 = RootOfUnity<typename Element::Integer>(2 * n, qPrime2);

	cryptoParamsBFV->SetBigModulus(qPrime2);
	cryptoParamsBFV->SetBigRootOfUnity(rootOfUnity2);

	shared_ptr<typename Element::Params> ilParams( new typename Element::Params(2*n, qPrime, rootOfUnity) );
	cryptoParamsBFV->SetElementParams(ilParams);

	cryptoParamsBFV->SetDelta(qPrime.DividedBy(cryptoParamsBFV->GetPlaintextModulus()));

	return true;
	
}

//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmBFV<Element>::KeyGen(CryptoContext<Element> cc, bool makeSparse)
{

	LPKeyPair<Element>	kp( new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc) );

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(cc->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename Element::DugType dug;
	typename Element::TugType tug;

	//Generate the element "a" of the public key
	Element a(dug, elementParams, Format::EVALUATION);

	//Generate the secret key
	Element s;

	//Done in two steps not to use a random polynomial from a pre-computed pool
	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE) {
		s = Element(dgg, elementParams, Format::COEFFICIENT);
		s.SwitchFormat();
	}
	else {
		s = Element(tug, elementParams, Format::COEFFICIENT);
		s.SwitchFormat();
	}

	kp.secretKey->SetPrivateElement(s);

	//Done in two steps not to use a discrete Gaussian polynomial from a pre-computed pool
	Element e(dgg, elementParams, Format::COEFFICIENT);
	e.SwitchFormat();

	Element b(elementParams, Format::EVALUATION, true);
	b-=e;
	b-=(a*s);

	kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
	kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

	return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmBFV<Element>::Encrypt(const LPPublicKey<Element> publicKey,
		Element ptxt) const
{
	Ciphertext<Element> ciphertext( new CiphertextImpl<Element>(publicKey) );

	const shared_ptr<LPCryptoParametersBFV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(publicKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	ptxt.SwitchFormat();

	const typename Element::Integer &delta = cryptoParams->GetDelta();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename Element::TugType tug;

	const Element &p0 = publicKey->GetPublicElements().at(0);
	const Element &p1 = publicKey->GetPublicElements().at(1);

	Element u;

	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE)
		u = Element(dgg, elementParams, Format::EVALUATION);
	else
		u = Element(tug, elementParams, Format::EVALUATION);

	Element e1(dgg, elementParams, Format::EVALUATION);
	Element e2(dgg, elementParams, Format::EVALUATION);

	Element c0(elementParams);
	Element c1(elementParams);

	c0 = p0*u + e1 + delta*ptxt;

	c1 = p1*u + e2;

	ciphertext->SetElements({ c0, c1 });

	return ciphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmBFV<Element>::Encrypt(const LPPrivateKey<Element> privateKey,
		Element ptxt) const
{
	Ciphertext<Element> ciphertext( new CiphertextImpl<Element>(privateKey) );

	const shared_ptr<LPCryptoParametersBFV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(privateKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	ptxt.SwitchFormat();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename Element::DugType dug;
	const typename Element::Integer &delta = cryptoParams->GetDelta();

	Element a(dug, elementParams, Format::EVALUATION);
	const Element &s = privateKey->GetPrivateElement();
	Element e(dgg, elementParams, Format::EVALUATION);

	Element c0(a*s + e + delta*ptxt);
	Element c1(elementParams, Format::EVALUATION, true);
	c1 -= a;

	ciphertext->SetElements({ c0, c1 });

	return ciphertext;
}

template <class Element>
DecryptResult LPAlgorithmBFV<Element>::Decrypt(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext,
		NativePoly *plaintext) const
{
	const shared_ptr<LPCryptoParametersBFV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(privateKey->GetCryptoParameters());
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();
	Element sPower = s;

	Element b = c[0];
	if(b.GetFormat() == Format::COEFFICIENT)
		b.SwitchFormat();

	Element cTemp;
	for(size_t i=1; i<=ciphertext->GetDepth(); i++){
		cTemp = c[i];
		if(cTemp.GetFormat() == Format::COEFFICIENT)
			cTemp.SwitchFormat();

		b += sPower*cTemp;
		sPower *= s;
	}

	b.SwitchFormat();
	
	const auto p = cryptoParams->GetPlaintextModulus();

	const typename Element::Integer &delta = cryptoParams->GetDelta();
	Element ans = b.DivideAndRound(delta).Mod(p);

	*plaintext = ans.DecryptionCRTInterpolate(p);

	return DecryptResult(plaintext->GetLength());
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalAdd(const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2) const {

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEBFV::EvalAdd crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

	const std::vector<Element> &cipherText1Elements = ciphertext1->GetElements();
	const std::vector<Element> &cipherText2Elements = ciphertext2->GetElements();

	size_t cipherTextRElementsSize;
	size_t cipherTextSmallElementsSize;

	bool isCipherText1Small;
	if(cipherText1Elements.size() > cipherText2Elements.size()){
		isCipherText1Small = false;
		cipherTextRElementsSize = cipherText1Elements.size();
		cipherTextSmallElementsSize = cipherText2Elements.size();
		newCiphertext->SetDepth(ciphertext1->GetDepth());
	}
	else {
		isCipherText1Small = true;
		cipherTextRElementsSize = cipherText2Elements.size();
		cipherTextSmallElementsSize = cipherText1Elements.size();
		newCiphertext->SetDepth(ciphertext2->GetDepth());
	}

	std::vector<Element> c(cipherTextRElementsSize);

	for(size_t i=0; i<cipherTextSmallElementsSize; i++)
		c[i] = cipherText1Elements[i] + cipherText2Elements[i];

	for(size_t i=cipherTextSmallElementsSize; i<cipherTextRElementsSize; i++){
		if(isCipherText1Small == true)
			c[i] = cipherText2Elements[i];
		else
			c[i] = cipherText1Elements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalAdd(const Ciphertext<Element> ciphertext,
	const Plaintext plaintext) const {

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

	plaintext->GetEncodedElement<Element>().SetFormat(EVALUATION);
	const Element& ptElement = plaintext->GetEncodedElement<Element>();

	std::vector<Element> c(cipherTextElements.size());

    auto bfvParams = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(ciphertext->GetCryptoParameters());
    auto &delta = bfvParams->GetDelta();

	c[0] = cipherTextElements[0] + delta*ptElement;

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalSub(const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2) const {

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEBFV::EvalSub crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

	const std::vector<Element> &cipherText1Elements = ciphertext1->GetElements();
	const std::vector<Element> &cipherText2Elements = ciphertext2->GetElements();

	size_t cipherTextRElementsSize;
	size_t cipherTextSmallElementsSize;

	bool isCipherText1Small;
	if(cipherText1Elements.size() > cipherText2Elements.size()){
		isCipherText1Small = false;
		cipherTextRElementsSize = cipherText1Elements.size();
		cipherTextSmallElementsSize = cipherText2Elements.size();
		newCiphertext->SetDepth(ciphertext1->GetDepth());
	}
	else {
		isCipherText1Small = true;
		cipherTextRElementsSize = cipherText2Elements.size();
		cipherTextSmallElementsSize = cipherText1Elements.size();
		newCiphertext->SetDepth(ciphertext2->GetDepth());
	}

	std::vector<Element> c(cipherTextRElementsSize);

	for(size_t i=0; i<cipherTextSmallElementsSize; i++)
		c[i] = cipherText1Elements[i] - cipherText2Elements[i];

	for(size_t i=cipherTextSmallElementsSize; i<cipherTextRElementsSize; i++){
		if(isCipherText1Small == true)
			c[i] = cipherText2Elements[i];
		else
			c[i] = cipherText1Elements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalSub(const Ciphertext<Element> ciphertext,
	const Plaintext plaintext) const {

//	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
//		std::string errMsg = "LPAlgorithmSHEBFV::EvalSub crypto parameters are not the same";
//		throw std::runtime_error(errMsg);
//	}

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

	plaintext->GetEncodedElement<Element>().SetFormat(EVALUATION);
	const Element& ptElement = plaintext->GetEncodedElement<Element>();

	std::vector<Element> c(cipherTextElements.size());

    auto bfvParams = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(ciphertext->GetCryptoParameters());
    auto &delta = bfvParams->GetDelta();

	c[0] = cipherTextElements[0] - delta*ptElement;

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalNegate(const Ciphertext<Element> ciphertext) const {

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

	Element c0 = cipherTextElements[0].Negate();
	Element c1 = cipherTextElements[1].Negate();

	newCiphertext->SetElements({ c0, c1 });
	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMult(const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2) const {

	bool isCiphertext1FormatCoeff = false;
	bool isCiphertext2FormatCoeff = false;

	if(ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT)
			isCiphertext1FormatCoeff = true;

	if(ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT)
			isCiphertext2FormatCoeff = true;

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEBFV::EvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(ciphertext1->GetCryptoContext()->GetCryptoParameters());
	//Check if the multiplication supports the depth
	if ( (ciphertext1->GetDepth() + ciphertext2->GetDepth()) > cryptoParamsLWE->GetMaxDepth() ) {
			std::string errMsg = "LPAlgorithmSHEBFV::EvalMult multiplicative depth is not supported";
			throw std::runtime_error(errMsg);
	}

	const auto p = cryptoParamsLWE->GetPlaintextModulus();

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const typename Element::Integer &q = elementParams->GetModulus();

	const typename Element::Integer &bigModulus = cryptoParamsLWE->GetBigModulus();
	const typename Element::Integer &bigRootOfUnity = cryptoParamsLWE->GetBigRootOfUnity();
	const typename Element::Integer &bigModulusArb = cryptoParamsLWE->GetBigModulusArb();
	const typename Element::Integer &bigRootOfUnityArb = cryptoParamsLWE->GetBigRootOfUnityArb();
	//Get the ciphertext elements
	std::vector<Element> cipherText1Elements = ciphertext1->GetElements();
	std::vector<Element> cipherText2Elements = ciphertext2->GetElements();

	//converts the ciphertext elements to coefficient format so that the modulus switching can be done
	size_t cipherText1ElementsSize = cipherText1Elements.size();
	size_t cipherText2ElementsSize = cipherText2Elements.size();
	size_t cipherTextRElementsSize = cipherText1ElementsSize + cipherText2ElementsSize - 1;

	std::vector<Element> c(cipherTextRElementsSize);

	if(isCiphertext1FormatCoeff != true)
		for(size_t i=0; i<cipherText1ElementsSize; i++)
			cipherText1Elements[i].SwitchFormat();

	if(isCiphertext2FormatCoeff != true)
		for(size_t i=0; i<cipherText2ElementsSize; i++)
			cipherText2Elements[i].SwitchFormat();

	//switches the modulus to a larger value so that polynomial multiplication w/o mod q can be performed
	for(size_t i=0; i<cipherText1ElementsSize; i++)
		cipherText1Elements[i].SwitchModulus(bigModulus, bigRootOfUnity, bigModulusArb, bigRootOfUnityArb);

	for(size_t i=0; i<cipherText2ElementsSize; i++)
		cipherText2Elements[i].SwitchModulus(bigModulus, bigRootOfUnity, bigModulusArb, bigRootOfUnityArb);

	//converts the ciphertext elements back to evaluation representation
	for(size_t i=0; i<cipherText1ElementsSize; i++)
		cipherText1Elements[i].SwitchFormat();

	for(size_t i=0; i<cipherText2ElementsSize; i++)
		cipherText2Elements[i].SwitchFormat();

	bool *isFirstAdd = new bool[cipherTextRElementsSize];
	std::fill_n(isFirstAdd, cipherTextRElementsSize, true);

	for(size_t i=0; i<cipherText1ElementsSize; i++){
		for(size_t j=0; j<cipherText2ElementsSize; j++){

			if(isFirstAdd[i+j] == true){
				c[i+j] = cipherText1Elements[i] * cipherText2Elements[j];
				isFirstAdd[i+j] = false;
			}
			else{
				c[i+j] += cipherText1Elements[i] * cipherText2Elements[j];
			}
		}
	}

	delete []isFirstAdd;

	//converts to coefficient representation before rounding
	for(size_t i=0; i<cipherTextRElementsSize; i++)
		c[i].SwitchFormat();

	for(size_t i=0; i<cipherTextRElementsSize; i++)
		c[i] = c[i].MultiplyAndRound(p, q);

	//switch the modulus back to the original value
	for(size_t i=0; i<cipherTextRElementsSize; i++)
		c[i].SwitchModulus(q, elementParams->GetRootOfUnity(), elementParams->GetBigModulus(), elementParams->GetBigRootOfUnity());

	newCiphertext->SetElements(c);
	newCiphertext->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

	return newCiphertext;

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMult(const Ciphertext<Element> ciphertext,
	const Plaintext plaintext) const {

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	std::vector<Element> cipherTextElements = ciphertext->GetElements();
	plaintext->GetEncodedElement<Element>().SetFormat(EVALUATION);
	const Element& ptElement = plaintext->GetEncodedElement<Element>();

	if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT || plaintext->GetElement<Element>().GetFormat() == Format::COEFFICIENT) {
		throw std::runtime_error("LPAlgorithmSHEBFV::EvalMult cannot multiply in COEFFICIENT domain.");
	}

	Element c0 = cipherTextElements[0] * ptElement;
	Element c1 = cipherTextElements[1] * ptElement;

	newCiphertext->SetElements({ c0, c1 });

	return newCiphertext;

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMultMany(const vector<Ciphertext<Element>>& cipherTextList,
		const vector<LPEvalKey<Element>> &evalKeys) const {

	vector<Ciphertext<Element>> cipherTextListTemp;
	cipherTextListTemp.resize(cipherTextList.size()*2-1);
	for(size_t i=0; i<cipherTextList.size(); i++){
		cipherTextListTemp.at(i) = cipherTextList.at(i);
	}

	size_t resultIndex = cipherTextList.size();
	for(size_t i=0; i<cipherTextListTemp.size()-1; i=i+2){
		cipherTextListTemp.at(resultIndex) = (this->EvalMultAndRelinearize(cipherTextListTemp.at(i), cipherTextListTemp.at(i+1), evalKeys));
		resultIndex++;
	}

	return cipherTextListTemp.at(cipherTextListTemp.size()-1);

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::KeySwitch(const LPEvalKey<Element> ek,
	const Ciphertext<Element> cipherText) const
{
	
	Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(ek->GetCryptoParameters());
	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	LPEvalKeyRelin<Element> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<Element>>(ek);

	const std::vector<Element> &c = cipherText->GetElements();

	const std::vector<Element> &b = evalKey->GetAVector();
	const std::vector<Element> &a = evalKey->GetBVector();

	std::vector<Element> digitsC2;

	Element ct0(c[0]);

	//in the case of EvalMult, c[0] is initially in coefficient format and needs to be switched to evaluation format
	if (c.size() > 2)
		ct0.SwitchFormat();
	
	Element ct1;

	if (c.size() == 2) //case of PRE or automorphism
	{		
		digitsC2 = c[1].BaseDecompose(relinWindow);
		ct1 = digitsC2[0] * a[0];
	}
	else //case of EvalMult
	{
		digitsC2 = c[2].BaseDecompose(relinWindow);
		ct1 = c[1];
		//Convert ct1 to evaluation representation
		ct1.SwitchFormat();
		ct1 += digitsC2[0] * a[0];
	}

	ct0 += digitsC2[0] * b[0];

	for (usint i = 1; i < digitsC2.size(); ++i)
	{
		ct0 += digitsC2[i] * b[i];
		ct1 += digitsC2[i] * a[i];
	}

	newCiphertext->SetElements({ ct0, ct1 });
	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMult(const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2,
	const LPEvalKey<Element> ek) const {

	Ciphertext<Element> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

	return this->KeySwitch(ek, newCiphertext);

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMultAndRelinearize(const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2,
	const vector<LPEvalKey<Element>> &ek) const {

	// FIXME add a plaintext method for this
//	if(!ciphertext2->GetIsEncrypted()) {
//		return EvalMultPlain(ciphertext1, ciphertext2);
//	}
	//Perform a multiplication
	Ciphertext<Element> cipherText = this->EvalMult(ciphertext1, ciphertext2);

	const shared_ptr<LPCryptoParametersBFV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(ek[0]->GetCryptoParameters());
	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();

	std::vector<Element> c = cipherText->GetElements();

	if(c[0].GetFormat() == Format::COEFFICIENT)
		for(size_t i=0; i<c.size(); i++)
			c[i].SwitchFormat();

	Element ct0(c[0]);
	Element ct1(c[1]);
	// Perform a keyswitching operation to result of the multiplication. It does it until it reaches to 2 elements.
	//TODO: Maybe we can change the number of keyswitching and terminate early. For instance; perform keyswitching until 4 elements left.
	for(size_t j = 0; j<=cipherText->GetDepth()-2; j++){
		size_t index = cipherText->GetDepth()-2-j;
		LPEvalKeyRelin<Element> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<Element>>(ek[index]);

		const std::vector<Element> &b = evalKey->GetAVector();
		const std::vector<Element> &a = evalKey->GetBVector();

		std::vector<Element> digitsC2 = c[index+2].BaseDecompose(relinWindow);

		for (usint i = 0; i < digitsC2.size(); ++i){
			ct0 += digitsC2[i] * b[i];
			ct1 += digitsC2[i] * a[i];
		}
	}

	newCiphertext->SetElements({ ct0, ct1 });

	return newCiphertext;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmSHEBFV<Element>::KeySwitchGen(const LPPrivateKey<Element> originalPrivateKey,
	const LPPrivateKey<Element> newPrivateKey) const {

	LPEvalKeyRelin<Element> ek(new LPEvalKeyRelinImpl<Element>(newPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersBFV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBFV<Element>>(newPrivateKey->GetCryptoParameters());
	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const Element &s = newPrivateKey->GetPrivateElement();

	const typename Element::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	typename Element::DugType dug;

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<Element> evalKeyElements(originalPrivateKey->GetPrivateElement().PowersOfBase(relinWindow));
	std::vector<Element> evalKeyElementsGenerated;

	for (usint i = 0; i < (evalKeyElements.size()); i++)
	{
		// Generate a_i vectors
		Element a(dug, elementParams, Format::EVALUATION);
		evalKeyElementsGenerated.push_back(a);

		// Generate a_i * s + e - PowerOfBase(s^2)
		Element e(dgg, elementParams, Format::EVALUATION);
		evalKeyElements.at(i) -= (a*s + e);
	}

	ek->SetAVector(std::move(evalKeyElements));
	ek->SetBVector(std::move(evalKeyElementsGenerated));

	return ek;

}

template <class Element>
LPEvalKey<Element> LPAlgorithmSHEBFV<Element>::EvalMultKeyGen(
			const LPPrivateKey<Element> originalPrivateKey) const
{
	
	LPPrivateKey<Element> originalPrivateKeySquared = LPPrivateKey<Element>(new LPPrivateKeyImpl<Element>(originalPrivateKey->GetCryptoContext()));

	Element sSquare(originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement());

	originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

	return this->KeySwitchGen(originalPrivateKeySquared, originalPrivateKey);
	
}

template <class Element>
vector<LPEvalKey<Element>> LPAlgorithmSHEBFV<Element>::EvalMultKeysGen(
			const LPPrivateKey<Element> originalPrivateKey) const
{

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(originalPrivateKey->GetCryptoParameters());

	LPPrivateKey<Element> originalPrivateKeyPowered = LPPrivateKey<Element>(new LPPrivateKeyImpl<Element>(originalPrivateKey->GetCryptoContext()));

	vector<LPEvalKey<Element>> evalMultKeys;

	std::vector<Element> sPower(cryptoParamsLWE->GetMaxDepth());
	std::vector<LPEvalKey<Element>> ek(cryptoParamsLWE->GetMaxDepth());
	//Create powers of original key to be used in keyswitching as evaluation keys after they are encrypted.
	sPower[0] = originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement();
	for(size_t i=1; i<cryptoParamsLWE->GetMaxDepth()-1; i++)
		sPower[i] = sPower[i-1] * originalPrivateKey->GetPrivateElement();

	for(size_t i=0; i<cryptoParamsLWE->GetMaxDepth()-1; i++){
		originalPrivateKeyPowered->SetPrivateElement(std::move(sPower[i]));
		ek[i] = this->KeySwitchGen(originalPrivateKeyPowered, originalPrivateKey);
		evalMultKeys.push_back(ek[i]);
	}

	return evalMultKeys;

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalAutomorphism(const Ciphertext<Element> ciphertext, usint i,
	const std::map<usint, LPEvalKey<Element>> &evalKeys) const
{

	Ciphertext<Element> permutedCiphertext(new CiphertextImpl<Element>(*ciphertext));

	const std::vector<Element> &c = ciphertext->GetElements();

	std::vector<Element> cNew;

	cNew.push_back(std::move(c[0].AutomorphismTransform(i)));

	cNew.push_back(std::move(c[1].AutomorphismTransform(i)));

	permutedCiphertext->SetElements(std::move(cNew));

	return this->KeySwitch(evalKeys.find(i)->second, permutedCiphertext);

}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> LPAlgorithmSHEBFV<Element>::EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
	const std::vector<usint> &indexList) const
{

	const Element &privateKeyElement = privateKey->GetPrivateElement();

	usint n = privateKeyElement.GetRingDimension();

	LPPrivateKey<Element> tempPrivateKey(new LPPrivateKeyImpl<Element>(privateKey->GetCryptoContext()));

	shared_ptr<std::map<usint, LPEvalKey<Element>>> evalKeys(new std::map<usint, LPEvalKey<Element>>());

	if (indexList.size() > n - 1)
		throw std::runtime_error("size exceeds the ring dimension");
	else {

		for (usint i = 0; i < indexList.size(); i++)
		{
			Element permutedPrivateKeyElement = privateKeyElement.AutomorphismTransform(indexList[i]);

			tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

			(*evalKeys)[indexList[i]] = this->KeySwitchGen(tempPrivateKey, privateKey);

		}

	}

	return evalKeys;

}

//Currently DISABLED at the scheme level
template <class Element>
LPEvalKey<Element> LPAlgorithmPREBFV<Element>::ReKeyGen(const LPPrivateKey<Element> newSK,
	const LPPrivateKey<Element> origPrivateKey) const
{
	return origPrivateKey->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchGen(origPrivateKey,
		newSK);
}

//Currently DISABLED at the scheme level
//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
template <class Element>
Ciphertext<Element> LPAlgorithmPREBFV<Element>::ReEncrypt(const LPEvalKey<Element> EK,
	const Ciphertext<Element> ciphertext) const
{
	return ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(EK, ciphertext);
}



//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyBFV<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
		const vector<LPPrivateKey<Element>>& secretKeys,
		bool makeSparse)
{


	LPKeyPair<Element>	kp( new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc) );

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(cc->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename Element::DugType dug;
	typename Element::TugType tug;

	//Generate the element "a" of the public key
	Element a(dug, elementParams, Format::EVALUATION);

	//Generate the secret key
	Element s(elementParams, Format::EVALUATION, true);

	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases

	size_t numKeys = secretKeys.size();
	for( size_t i = 0; i < numKeys; i++ ) {
		LPPrivateKey<Element> sk1 = secretKeys[i];
		Element s1 = sk1->GetPrivateElement();
		s += s1;
	}

	kp.secretKey->SetPrivateElement(s);

	//Done in two steps not to use a discrete Gaussian polynomial from a pre-computed pool
	Element e(dgg, elementParams, Format::COEFFICIENT);
	e.SwitchFormat();

	Element b(elementParams, Format::EVALUATION, true);
	b-=e;
	b-=(a*s);

	kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
	kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

	return kp;
}

//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyBFV<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
		const LPPublicKey<Element> pk1, bool makeSparse, bool pre)
{

	LPKeyPair<Element>	kp( new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc) );

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(cc->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename Element::DugType dug;
	typename Element::TugType tug;

	//Generate the element "a" of the public key
	Element a = pk1->GetPublicElements()[1];

	//Generate the secret key
	Element s;

	//Done in two steps not to use a random polynomial from a pre-computed pool
	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE) {
		s = Element(dgg, elementParams, Format::COEFFICIENT);
		s.SwitchFormat();
	}
	else {
		//throw std::logic_error("FusedKeyGen operation has not been enabled for OPTIMIZED cases");
		s = Element(tug, elementParams, Format::COEFFICIENT);
		s.SwitchFormat();
	}

	kp.secretKey->SetPrivateElement(s);

	//Done in two steps not to use a discrete Gaussian polynomial from a pre-computed pool
	Element e(dgg, elementParams, Format::COEFFICIENT);
	e.SwitchFormat();

	Element b(elementParams, Format::EVALUATION, true);
	b-=e;
	b-=(a*s);
	// When PRE is not used, a joint key is computed
	if (!pre)
		b+=pk1->GetPublicElements()[0];

	kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
	kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

	return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyBFV<Element>::MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext) const
{
	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();

	Element b = s*c[1];
	b.SwitchFormat();		

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetElements({ b });

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyBFV<Element>::MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext) const
{
	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();

	Element b = c[0] + s*c[1];
	b.SwitchFormat();		

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetElements({ b });

	return newCiphertext;
}

template <class Element>
DecryptResult LPAlgorithmMultipartyBFV<Element>::MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
		NativePoly *plaintext) const
{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const auto p = cryptoParams->GetPlaintextModulus();
	const typename Element::Integer &q = elementParams->GetModulus();

	const std::vector<Element> &cElem = ciphertextVec[0]->GetElements();
	Element b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<Element> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}
	
	Element ans = b.MultiplyAndRound(p, q).Mod(p);
	*plaintext = ans.DecryptionCRTInterpolate(p);

	return DecryptResult(plaintext->GetLength());
}

// Enable for LPPublicKeyEncryptionSchemeBFV
template <class Element>
void LPPublicKeyEncryptionSchemeBFV<Element>::Enable(PKESchemeFeature feature) {
	switch (feature)
	{
	case ENCRYPTION:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBFV<Element>();
		break;
	case SHE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBFV<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEBFV<Element>();
		break;
	case PRE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBFV<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEBFV<Element>();
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPREBFV<Element>();
		break; 
	case MULTIPARTY:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmBFV<Element>();
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPREBFV<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEBFV<Element>();
		if (this->m_algorithmMultiparty == NULL)
			this->m_algorithmMultiparty = new LPAlgorithmMultipartyBFV<Element>();
		break; 
	case FHE:
		throw std::logic_error("FHE feature not supported for BFV scheme");
	case LEVELEDSHE:
		throw std::logic_error("LEVELEDSHE feature not supported for BFV scheme");
	}
}

}  // namespace lbcrypto ends

#endif
