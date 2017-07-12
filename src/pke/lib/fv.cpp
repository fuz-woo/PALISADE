/*
* @file fv.cpp - implementation of the FV scheme.
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

 This code implements the Fan-Vercauteren (FV) homomorphic encryption scheme.
 The FV scheme is introduced in https://eprint.iacr.org/2012/144.pdf and originally implemented in https://eprint.iacr.org/2014/062.pdf 
 (this paper has optimized correctness constraints, which are used here as well). 

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef LBCRYPTO_CRYPTO_FV_C
#define LBCRYPTO_CRYPTO_FV_C

#include "fv.h"
#include <iostream>
#include <fstream>

namespace lbcrypto {

template <class Element>
bool LPCryptoParametersFV<Element>::Serialize(Serialized* serObj) const {
	if (!serObj->IsObject())
		return false;

	SerialItem cryptoParamsMap(rapidjson::kObjectType);
	if (this->SerializeRLWE(serObj, cryptoParamsMap) == false)
		return false;

	cryptoParamsMap.AddMember("delta", m_delta.ToString(), serObj->GetAllocator());
	cryptoParamsMap.AddMember("mode", std::to_string(m_mode), serObj->GetAllocator());
	cryptoParamsMap.AddMember("bigmodulus", m_bigModulus.ToString(), serObj->GetAllocator());
	cryptoParamsMap.AddMember("bigrootofunity", m_bigRootOfUnity.ToString(), serObj->GetAllocator());
	cryptoParamsMap.AddMember("bigmodulusarb", m_bigModulusArb.ToString(), serObj->GetAllocator());
	cryptoParamsMap.AddMember("bigrootofunityarb", m_bigRootOfUnityArb.ToString(), serObj->GetAllocator());

	serObj->AddMember("LPCryptoParametersFV", cryptoParamsMap.Move(), serObj->GetAllocator());
	serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersFV", serObj->GetAllocator());

	return true;
}

template <class Element>
bool LPCryptoParametersFV<Element>::Deserialize(const Serialized& serObj) {
	Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersFV");
	if (mIter == serObj.MemberEnd()) return false;

	if (this->DeserializeRLWE(mIter) == false)
		return false;

	SerialItem::ConstMemberIterator pIt;
	if ((pIt = mIter->value.FindMember("delta")) == mIter->value.MemberEnd())
		return false;
	BigInteger delta(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("mode")) == mIter->value.MemberEnd())
		return false;
	MODE mode = (MODE)atoi(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("bigmodulus")) == mIter->value.MemberEnd())
		return false;
	BigInteger bigmodulus(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("bigrootofunity")) == mIter->value.MemberEnd())
		return false;
	BigInteger bigrootofunity(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("bigmodulusarb")) == mIter->value.MemberEnd())
		return false;
	BigInteger bigmodulusarb(pIt->value.GetString());

	if ((pIt = mIter->value.FindMember("bigrootofunityarb")) == mIter->value.MemberEnd())
		return false;
	BigInteger bigrootofunityarb(pIt->value.GetString());

	this->SetBigModulus(bigmodulus);
	this->SetBigRootOfUnity(bigrootofunity);
	this->SetBigModulusArb(bigmodulusarb);
	this->SetBigRootOfUnityArb(bigrootofunityarb);
	this->SetMode(mode);
	this->SetDelta(delta);

	return true;
}

template <class Element>
bool LPAlgorithmParamsGenFV<Element>::ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount) const
{

	if (!cryptoParams)
		return false;

	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParamsFV = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(cryptoParams);

	double sigma = cryptoParamsFV->GetDistributionParameter();
	double alpha = cryptoParamsFV->GetAssuranceMeasure();
	double hermiteFactor = cryptoParamsFV->GetSecurityLevel();
	double p = cryptoParamsFV->GetPlaintextModulus().ConvertToDouble();
	uint32_t r = cryptoParamsFV->GetRelinWindow();

	//Bound of the Gaussian error polynomial
	double Berr = sigma*sqrt(alpha);

	//Bound of the key polynomial
	double Bkey;
	
	//supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParamsFV->GetMode() == RLWE)
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
		auto qFV = [&](uint32_t n) -> double { return p*(2*((evalAddCount+1)*Vnorm(n) + evalAddCount*p) + p);  };

		//initial value
		q = qFV(n);

		while (nRLWE(q) > n) {
			n = 2 * n;
			q = qFV(n);
		}

	} 
	// this case supports re-encryption and automorphism w/o any other operations
	else if ((evalMultCount == 0) && (keySwitchCount > 0) && (evalAddCount == 0)) {

		//base for relinearization
		double w = pow(2, r);

		//Correctness constraint
		auto qFV = [&](uint32_t n, double qPrev) -> double { return p*(2*(Vnorm(n) + keySwitchCount*delta(n)*(floor(log2(qPrev) / r) + 1)*w*Berr) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q 
		//changes the requirement for n, which is rare but still theortically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qFV(n, qPrev);
				qPrev = q;
			}

			q = qFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qFV(n, qPrev);
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
		auto qFV = [&](uint32_t n, double qPrev) -> double { return p*(2 * (pow(C1(n), evalMultCount)*Vnorm(n) + evalMultCount*pow(C1(n), evalMultCount - 1)*C2(n, qPrev)) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q 
		//changes the requirement for n, which is rare but still theortically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qFV(n, qPrev);
				qPrev = q;
			}

			q = qFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qFV(n, qPrev);
			}

		}

	}

	BigInteger qPrime = FirstPrime<BigInteger>(ceil(log2(q))+1, 2*n);
	BigInteger rootOfUnity = RootOfUnity<BigInteger>(2 * n, qPrime);

	//reserves enough digits to avoid wrap-around when evaluating p*(c1*c2+c3*c4)
	BigInteger qPrime2 = FirstPrime<BigInteger>(2*(ceil(log2(q)) + 1) + ceil(log2(p)) + 3, 2 * n);
	BigInteger rootOfUnity2 = RootOfUnity<BigInteger>(2 * n, qPrime2);

	cryptoParamsFV->SetBigModulus(qPrime2);
	cryptoParamsFV->SetBigRootOfUnity(rootOfUnity2);

	shared_ptr<typename Element::Params> ilParams( new typename Element::Params(2*n, qPrime, rootOfUnity) );
	cryptoParamsFV->SetElementParams(ilParams);

	cryptoParamsFV->SetDelta(qPrime.DividedBy(cryptoParamsFV->GetPlaintextModulus()));

	return true;
	
}

//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmFV<Element>::KeyGen(CryptoContext<Element>* cc, bool makeSparse)
{

	LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(cc->GetCryptoParameters());

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
shared_ptr<Ciphertext<Element>> LPAlgorithmFV<Element>::Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
		Poly &ptxt, bool doEncryption) const
{
	shared_ptr<Ciphertext<Element>> ciphertext( new Ciphertext<Element>(publicKey->GetCryptoContext()) );

	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(publicKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	Element plaintext(ptxt, elementParams);
	plaintext.SwitchFormat();

	if (doEncryption) {
		const BigInteger &delta = cryptoParams->GetDelta();

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

		c0 = p0*u + e1 + delta*plaintext;

		c1 = p1*u + e2;

		ciphertext->SetElements({ c0, c1 });
		ciphertext->SetIsEncrypted(true);

	}
	else
	{

		Element c0(plaintext);
		Element c1(elementParams, Format::EVALUATION, true);

		ciphertext->SetElements({ c0, c1 });
		ciphertext->SetIsEncrypted(false);

	}

	return ciphertext;
}

template <class Element>
DecryptResult LPAlgorithmFV<Element>::Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		Poly *plaintext) const
{
	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(privateKey->GetCryptoParameters());
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();

	Element b = c[0] + s*c[1];

	b.SwitchFormat();
	
	const BigInteger &p = cryptoParams->GetPlaintextModulus();

	const BigInteger &delta = cryptoParams->GetDelta();
	Element ans = b.DivideAndRound(delta).SignedMod(p);

	*plaintext = ans.CRTInterpolate();

	return DecryptResult(plaintext->GetLength());
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHEFV<Element>::EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2) const {

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEFV::EvalAdd crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

	const std::vector<Element> &cipherText1Elements = ciphertext1->GetElements();
	const std::vector<Element> &cipherText2Elements = ciphertext2->GetElements();

	if(ciphertext2->GetIsEncrypted()){
		Element c0 = cipherText1Elements[0] + cipherText2Elements[0];
		Element c1 = cipherText1Elements[1] + cipherText2Elements[1];

		newCiphertext->SetElements({ c0, c1 });
	} else {
		auto fvParams = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(ciphertext1->GetCryptoParameters());
		auto &delta = fvParams->GetDelta();
		Element c0 = cipherText1Elements[0] + delta*cipherText2Elements[0];
		Element c1 = cipherText1Elements[1];

		newCiphertext->SetElements({ c0, c1 });
	}
	return newCiphertext;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHEFV<Element>::EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2) const {

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEFV::EvalSub crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

	const std::vector<Element> &cipherText1Elements = ciphertext1->GetElements();
	const std::vector<Element> &cipherText2Elements = ciphertext2->GetElements();

	if(ciphertext2->GetIsEncrypted()){
		Element c0 = cipherText1Elements[0] - cipherText2Elements[0];
		Element c1 = cipherText1Elements[1] - cipherText2Elements[1];

		newCiphertext->SetElements({ c0, c1 });
	} else {
		auto fvParams = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(ciphertext1->GetCryptoParameters());
		auto &delta = fvParams->GetDelta();
		Element c0 = cipherText1Elements[0] - delta*cipherText2Elements[0];
		Element c1 = cipherText1Elements[1];

		newCiphertext->SetElements({ c0, c1 });
	}
	return newCiphertext;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHEFV<Element>::EvalNegate(const shared_ptr<Ciphertext<Element>> ciphertext) const {

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

	const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

	Element c0 = cipherTextElements[0].Negate();
	Element c1 = cipherTextElements[1].Negate();

	newCiphertext->SetElements({ c0, c1 });
	return newCiphertext;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHEFV<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2) const {

	if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
		throw std::runtime_error("LPAlgorithmSHEFV::EvalMult cannot multiply in COEFFICIENT domain.");
	}

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEFV::EvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(ciphertext1->GetCryptoContext()->GetCryptoParameters());
	const BigInteger &p = cryptoParamsLWE->GetPlaintextModulus();

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const BigInteger &q = elementParams->GetModulus();

	const BigInteger &bigModulus = cryptoParamsLWE->GetBigModulus();
	const BigInteger &bigRootOfUnity = cryptoParamsLWE->GetBigRootOfUnity();
	const BigInteger &bigModulusArb = cryptoParamsLWE->GetBigModulusArb();
	const BigInteger &bigRootOfUnityArb = cryptoParamsLWE->GetBigRootOfUnityArb();

	std::vector<Element> cipherText1Elements = ciphertext1->GetElements();
	std::vector<Element> cipherText2Elements = ciphertext2->GetElements();

	//converts the ciphertext elements to coefficient format so that the modulus switching can be done
	cipherText1Elements[0].SwitchFormat();
	cipherText1Elements[1].SwitchFormat();
	cipherText2Elements[0].SwitchFormat();
	cipherText2Elements[1].SwitchFormat();

	//switches the modulus to a larger value so that polynomial multiplication w/o mod q can be performed
	cipherText1Elements[0].SwitchModulus(bigModulus, bigRootOfUnity, bigModulusArb, bigRootOfUnityArb);
	cipherText1Elements[1].SwitchModulus(bigModulus, bigRootOfUnity, bigModulusArb, bigRootOfUnityArb);
	cipherText2Elements[0].SwitchModulus(bigModulus, bigRootOfUnity, bigModulusArb, bigRootOfUnityArb);
	cipherText2Elements[1].SwitchModulus(bigModulus, bigRootOfUnity, bigModulusArb, bigRootOfUnityArb);

	//converts the ciphertext elements back to evaluation representation
	cipherText1Elements[0].SwitchFormat();
	cipherText1Elements[1].SwitchFormat();
	cipherText2Elements[0].SwitchFormat();
	cipherText2Elements[1].SwitchFormat();

	Element c0 = cipherText1Elements[0] * cipherText2Elements[0];
	Element c1 = cipherText1Elements[0] * cipherText2Elements[1] + cipherText1Elements[1] * cipherText2Elements[0];
	Element c2 = cipherText1Elements[1] * cipherText2Elements[1];

	//converts to coefficient representation before rounding
	c0.SwitchFormat();
	c1.SwitchFormat();
	c2.SwitchFormat();

	c0 = c0.MultiplyAndRound(p, q);
	c1 = c1.MultiplyAndRound(p, q);
	c2 = c2.MultiplyAndRound(p, q);

	//switch the modulus back to the original value
	c0.SwitchModulus(q, elementParams->GetRootOfUnity(), elementParams->GetBigModulus(), elementParams->GetBigRootOfUnity());
	c1.SwitchModulus(q, elementParams->GetRootOfUnity(), elementParams->GetBigModulus(), elementParams->GetBigRootOfUnity());
	c2.SwitchModulus(q, elementParams->GetRootOfUnity(), elementParams->GetBigModulus(), elementParams->GetBigRootOfUnity());

	newCiphertext->SetElements({ c0, c1, c2 });

	return newCiphertext;

}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHEFV<Element>::EvalMultPlain(const shared_ptr<Ciphertext<Element>> ciphertext,
	const shared_ptr<Ciphertext<Element>> plaintext) const {

	if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT || plaintext->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
		throw std::runtime_error("LPAlgorithmSHEFV::EvalMult cannot multiply in COEFFICIENT domain.");
	}

	if (!(ciphertext->GetCryptoParameters() == plaintext->GetCryptoParameters())) {
		throw std::runtime_error("LPAlgorithmSHEFV::EvalMult crypto parameters are not the same");
	}

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

	std::vector<Element> cipherText1Elements = ciphertext->GetElements();
	std::vector<Element> cipherText2Elements = plaintext->GetElements();

	Element c0 = cipherText1Elements[0] * cipherText2Elements[0];
	Element c1 = cipherText1Elements[1] * cipherText2Elements[0];

	newCiphertext->SetElements({ c0, c1});

	return newCiphertext;

}


template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHEFV<Element>::KeySwitch(const shared_ptr<LPEvalKey<Element>> ek,
	const shared_ptr<Ciphertext<Element>> cipherText) const
{
	
	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(cipherText->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(ek->GetCryptoParameters());
	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	shared_ptr<LPEvalKeyRelin<Element>> evalKey = std::static_pointer_cast<LPEvalKeyRelin<Element>>(ek);

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
shared_ptr<Ciphertext<Element>> LPAlgorithmSHEFV<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
	const shared_ptr<Ciphertext<Element>> ciphertext2,
	const shared_ptr<LPEvalKey<Element>> ek) const {

	if(!ciphertext2->GetIsEncrypted()) {
		return EvalMultPlain(ciphertext1, ciphertext2);
	}

	shared_ptr<Ciphertext<Element>> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

	return this->KeySwitch(ek, newCiphertext);

}

template <class Element>
shared_ptr<LPEvalKey<Element>> LPAlgorithmSHEFV<Element>::KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey,
	const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {

	shared_ptr<LPEvalKeyRelin<Element>> ek(new LPEvalKeyRelin<Element>(newPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(newPrivateKey->GetCryptoParameters());
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
shared_ptr<LPEvalKey<Element>> LPAlgorithmSHEFV<Element>::EvalMultKeyGen(
			const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const
{
	
	shared_ptr<LPPrivateKey<Element>> originalPrivateKeySquared = std::shared_ptr<LPPrivateKey<Element>>(new LPPrivateKey<Element>(originalPrivateKey->GetCryptoContext()));

	Element sSquare(originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement());

	originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

	return this->KeySwitchGen(originalPrivateKeySquared, originalPrivateKey);
	
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmSHEFV<Element>::EvalAutomorphism(const shared_ptr<Ciphertext<Element>> ciphertext, usint i,
	const std::map<usint, shared_ptr<LPEvalKey<Element>>> &evalKeys) const
{

	shared_ptr<Ciphertext<Element>> permutedCiphertext(new Ciphertext<Element>(*ciphertext));

	const std::vector<Element> &c = ciphertext->GetElements();

	std::vector<Element> cNew;

	cNew.push_back(std::move(c[0].AutomorphismTransform(i)));

	cNew.push_back(std::move(c[1].AutomorphismTransform(i)));

	permutedCiphertext->SetElements(std::move(cNew));

	return this->KeySwitch(evalKeys.find(i)->second, permutedCiphertext);

}

template <class Element>
shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> LPAlgorithmSHEFV<Element>::EvalAutomorphismKeyGen(const shared_ptr<LPPrivateKey<Element>> privateKey,
	const std::vector<usint> &indexList) const
{

	const Element &privateKeyElement = privateKey->GetPrivateElement();

	usint n = privateKeyElement.GetRingDimension();

	shared_ptr<LPPrivateKey<Element>> tempPrivateKey(new LPPrivateKey<Element>(privateKey->GetCryptoContext()));

	shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> evalKeys(new std::map<usint, shared_ptr<LPEvalKey<Element>>>());

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
shared_ptr<LPEvalKey<Element>> LPAlgorithmPREFV<Element>::ReKeyGen(const shared_ptr<LPPrivateKey<Element>> newSK,
	const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
{
	return origPrivateKey->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchGen(origPrivateKey,
		newSK);
}

//Currently DISABLED at the scheme level
//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmPREFV<Element>::ReEncrypt(const shared_ptr<LPEvalKey<Element>> EK,
	const shared_ptr<Ciphertext<Element>> ciphertext) const
{
	return ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(EK, ciphertext);
}



//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyFV<Element>::MultipartyKeyGen(CryptoContext<Element>* cc,
		const vector<shared_ptr<LPPrivateKey<Element>>>& secretKeys,
		bool makeSparse)
{


	LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(cc->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename Element::DugType dug;
	typename Element::TugType tug;

	//Generate the element "a" of the public key
	Element a(dug, elementParams, Format::EVALUATION);

	//Generate the secret key
	Element s(elementParams, Format::EVALUATION, true);

	//Done in two steps not to use a random polynomial from a pre-computed pool
	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases

	size_t numKeys = secretKeys.size();
	for( size_t i = 0; i < numKeys; i++ ) {
		shared_ptr<LPPrivateKey<Element>> sk1 = secretKeys[i];
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
LPKeyPair<Element> LPAlgorithmMultipartyFV<Element>::MultipartyKeyGen(CryptoContext<Element>* cc,
		const shared_ptr<LPPublicKey<Element>> pk1, bool makeSparse)
{

	LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

	const shared_ptr<LPCryptoParametersFV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersFV<Element>>(cc->GetCryptoParameters());

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

	kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
	kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

	return kp;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmMultipartyFV<Element>::MultipartyDecryptMain(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
{
	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();

	Element b = s*c[1];
	b.SwitchFormat();		

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));
	newCiphertext->SetElements({ b });

	return newCiphertext;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmMultipartyFV<Element>::MultipartyDecryptLead(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
{
	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();

	Element b = c[0] + s*c[1];
	b.SwitchFormat();		

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));
	newCiphertext->SetElements({ b });

	return newCiphertext;
}

template <class Element>
DecryptResult LPAlgorithmMultipartyFV<Element>::MultipartyDecryptFusion(const vector<shared_ptr<Ciphertext<Element>>>& ciphertextVec,
		Poly *plaintext) const
{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const BigInteger &p = cryptoParams->GetPlaintextModulus();
	const BigInteger &q = elementParams->GetModulus();

	const std::vector<Element> &cElem = ciphertextVec[0]->GetElements();
	Element b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<Element> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}
	
	Element ans = b.MultiplyAndRound(p, q).SignedMod(p);
	*plaintext = ans.CRTInterpolate();

	return DecryptResult(plaintext->GetLength());
}

// Enable for LPPublicKeyEncryptionSchemeFV
template <class Element>
void LPPublicKeyEncryptionSchemeFV<Element>::Enable(PKESchemeFeature feature) {
	switch (feature)
	{
	case ENCRYPTION:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmFV<Element>();
		break;
	case SHE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmFV<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEFV<Element>();
		break;
	case PRE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmFV<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEFV<Element>();
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPREFV<Element>();
		break; 
	case MULTIPARTY:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmFV<Element>();
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPREFV<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHEFV<Element>();
		if (this->m_algorithmMultiparty == NULL)
			this->m_algorithmMultiparty = new LPAlgorithmMultipartyFV<Element>();
		break; 
	case FHE:
		throw std::logic_error("FHE feature not supported for FV scheme");
	case LEVELEDSHE:
		throw std::logic_error("LEVELEDSHE feature not supported for FV scheme");
	}
}

}  // namespace lbcrypto ends

#endif
