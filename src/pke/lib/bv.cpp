/*
* @file bv.cpp - BV scheme implementation.
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
This code implements the Brakerski-Vaikuntanathan (BV) homomorphic encryption scheme.
The scheme is described at http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf (or alternative Internet source:
http://dx.doi.org/10.1007/978-3-642-22792-9_29).
The levelled Homomorphic scheme is described in
"Fully Homomorphic Encryption without Bootstrapping", Internet Source: https://eprint.iacr.org/2011/277.pdf .
Implementation details are provided in
"Homomorphic Evaluation of the AES Circuit" Internet source: https://eprint.iacr.org/2012/099.pdf .

{the link to the ACM TISSEC manuscript to be added}.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef LBCRYPTO_CRYPTO_BV_C
#define LBCRYPTO_CRYPTO_BV_C

#include "bv.h"

namespace lbcrypto {

	template <class Element>
	bool LPCryptoParametersBV<Element>::Serialize(Serialized* serObj) const {
		if (!serObj->IsObject())
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);
		if (this->SerializeRLWE(serObj, cryptoParamsMap) == false)
			return false;
		cryptoParamsMap.AddMember("mode", std::to_string(m_mode), serObj->GetAllocator());

		serObj->AddMember("LPCryptoParametersBV", cryptoParamsMap.Move(), serObj->GetAllocator());
		serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersBV", serObj->GetAllocator());

		return true;
	}


	template <class Element>
	bool LPCryptoParametersBV<Element>::Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersBV");
		if (mIter == serObj.MemberEnd()) return false;

		if (this->DeserializeRLWE(mIter) == false) {
			return false;
		}

		SerialItem::ConstMemberIterator pIt;

		if ((pIt = mIter->value.FindMember("mode")) == serObj.MemberEnd()) {
			return false;
		}
		MODE mode = (MODE)atoi(pIt->value.GetString());

		this->SetMode(mode);

		return true;
	}

	//makeSparse is not used by this scheme
	template <class Element>
	LPKeyPair<Element> LPAlgorithmBV<Element>::KeyGen(CryptoContext<Element>* cc, bool makeSparse)
	{

		LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBV<Element>>(cc->GetCryptoParameters());

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		const typename Element::Integer &p = cryptoParams->GetPlaintextModulus();

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
		}
		else {
			s = Element(tug, elementParams, Format::COEFFICIENT);
		}
		s.SwitchFormat();

		//public key is generated and set
		//privateKey->MakePublicKey(a, publicKey);
		Element e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();

		Element b = a*s + p*e;

		kp.secretKey->SetPrivateElement(std::move(s));

		kp.publicKey->SetPublicElementAtIndex(0, std::move(a));

		kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

		return kp;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmBV<Element>::Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
		Poly &ptxt, bool doEncryption) const
	{

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(publicKey->GetCryptoParameters());

		shared_ptr<Ciphertext<Element>> ciphertext(new Ciphertext<Element>(publicKey->GetCryptoContext()));

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		const typename Element::Integer &p = cryptoParams->GetPlaintextModulus();
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		typename Element::TugType tug;

		Element plaintext(ptxt, elementParams);

		plaintext.SwitchFormat();

		std::vector<Element> cVector;

		if (doEncryption) {

			const Element &a = publicKey->GetPublicElements().at(0);
			const Element &b = publicKey->GetPublicElements().at(1);

			Element v;

			//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
			if (cryptoParams->GetMode() == RLWE)
				v = Element(dgg, elementParams, Format::EVALUATION);
			else
				v = Element(tug, elementParams, Format::EVALUATION);

			Element e0(dgg, elementParams, Format::EVALUATION);
			Element e1(dgg, elementParams, Format::EVALUATION);

			Element c0(b*v + p*e0 + plaintext);

			Element c1(a*v + p*e1);

			cVector.push_back(std::move(c0));

			cVector.push_back(std::move(c1));

			ciphertext->SetElements(std::move(cVector));

		}
		else
		{

			Element c0(plaintext);

			Element c1(elementParams,Format::EVALUATION,true);

			cVector.push_back(std::move(c0));

			cVector.push_back(std::move(c1));

			ciphertext->SetElements(std::move(cVector));

		}

		return ciphertext;
	}

	template <class Element>
	DecryptResult LPAlgorithmBV<Element>::Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		Poly *plaintext) const
	{
		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
		const typename Element::Integer &p = cryptoParams->GetPlaintextModulus();
		const std::vector<Element> &c = ciphertext->GetElements();
		const Element &s = privateKey->GetPrivateElement();

		Element b = c[0] - s*c[1];

		b.SwitchFormat();

		// Interpolation is needed in the case of Double-CRT interpolation, for example, DCRTPoly
		// CRTInterpolate does nothing when dealing with single-CRT ring elements, such as Poly
		Poly interpolatedElement = b.CRTInterpolate();
		*plaintext = interpolatedElement.SignedMod(p);

		return DecryptResult(plaintext->GetLength());
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalAdd(
		const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const
	{
		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] + c2[0]));

		cNew.push_back(std::move(c1[1] + c2[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const {

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] - c2[0]));

		cNew.push_back(std::move(c1[1] - c2[1]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalMult(
		const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const
	{

		if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
			throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
		}

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] * c2[0]));

		cNew.push_back(std::move(c1[0] * c2[1] + c1[1] * c2[0]));

		cNew.push_back(std::move((c1[1] * c2[1]).Negate()));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalMultPlain(
		const shared_ptr<Ciphertext<Element>> ciphertext,
		const shared_ptr<Ciphertext<Element>> plaintext) const
	{

		if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT || plaintext->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
			throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
		}

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

		const std::vector<Element> &c1 = ciphertext->GetElements();

		const std::vector<Element> &c2 = plaintext->GetElements();

		std::vector<Element> cNew;

		cNew.push_back(std::move(c1[0] * c2[0]));

		cNew.push_back(std::move(c1[1] * c2[0]));

		newCiphertext->SetElements(std::move(cNew));

		return newCiphertext;

	}


	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const {

		shared_ptr<Ciphertext<Element>> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

		return this->KeySwitch(ek, newCiphertext);

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalNegate(const shared_ptr<Ciphertext<Element>> ciphertext) const {

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

		const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

		Element c0 = cipherTextElements[0].Negate();
		Element c1 = cipherTextElements[1].Negate();

		newCiphertext->SetElements({ c0, c1 });
		return newCiphertext;
	}


	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmSHEBV<Element>::KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey, const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(originalPrivateKey->GetCryptoParameters());

		const shared_ptr<typename Element::Params> originalKeyParams = cryptoParams->GetElementParams();

		const BigInteger &p = cryptoParams->GetPlaintextModulus();

		shared_ptr<LPEvalKey<Element>> keySwitchHintRelin(new LPEvalKeyRelin<Element>(originalPrivateKey->GetCryptoContext()));

		//Getting a reference to the polynomials of new private key.
		const Element &sNew = newPrivateKey->GetPrivateElement();

		//Getting a reference to the polynomials of original private key.
		const Element &s = originalPrivateKey->GetPrivateElement();

		//Getting a refernce to discrete gaussian distribution generator.
		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		//Getting a reference to discrete uniform generator.
		typename Element::DugType dug;

		//Relinearization window is used to calculate the base exponent.
		usint relinWindow = cryptoParams->GetRelinWindow();

		//Pushes the powers of base exponent of original key polynomial onto evalKeyElements.
		std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));

		//evalKeyElementsGenerated hold the generated noise distribution.
		std::vector<Element> evalKeyElementsGenerated;

		for (usint i = 0; i < (evalKeyElements.size()); i++)
		{
			// Generate a_i vectors
			Element a(dug, originalKeyParams, Format::EVALUATION);

			evalKeyElementsGenerated.push_back(a); //alpha's of i

												   // Generate a_i * newSK + p * e - PowerOfBase(oldSK)
			Element e(dgg, originalKeyParams, Format::EVALUATION);

			evalKeyElements.at(i) = (a*sNew + p*e) - evalKeyElements.at(i);

		}

		keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

		keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

		return keySwitchHintRelin;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::KeySwitch(const shared_ptr<LPEvalKey<Element>> keySwitchHint, const shared_ptr<Ciphertext<Element>> cipherText) const {

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(*cipherText));

		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(keySwitchHint->GetCryptoParameters());

		const shared_ptr<LPEvalKeyRelin<Element>> evalKey = std::static_pointer_cast<LPEvalKeyRelin<Element>>(keySwitchHint);

		const std::vector<Element> &a = evalKey->GetAVector();
		const std::vector<Element> &b = evalKey->GetBVector();

		usint relinWindow = cryptoParamsLWE->GetRelinWindow();

		const std::vector<Element> &c = cipherText->GetElements();

		std::vector<Element> digitsC1;
		Element ct1;

		if (c.size() == 2) //case of PRE or automorphism
		{
			digitsC1 = c[1].BaseDecompose(relinWindow);
			ct1 = digitsC1[0] * a[0];
		}
		else //case of EvalMult
		{
			digitsC1 = c[2].BaseDecompose(relinWindow);
			ct1 = c[1] + digitsC1[0] * a[0];
		}

		Element ct0(c[0] + digitsC1[0] * b[0]);

		//Relinearization Step.
		for (usint i = 1; i < digitsC1.size(); ++i)
		{
			ct0 += digitsC1[i] * b[i];
			ct1 += digitsC1[i] * a[i];
		}

		std::vector<Element> ctVector;

		ctVector.push_back(std::move(ct0));

		ctVector.push_back(std::move(ct1));

		newCiphertext->SetElements(std::move(ctVector));

		return newCiphertext;

	}

	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmSHEBV<Element>::EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const
	{

		shared_ptr<LPPrivateKey<Element>> originalPrivateKeySquared = std::shared_ptr<LPPrivateKey<Element>>(new LPPrivateKey<Element>(originalPrivateKey->GetCryptoContext()));

		Element sSquare(originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement());

		originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

		return this->KeySwitchGen(originalPrivateKeySquared, originalPrivateKey);

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHEBV<Element>::EvalAutomorphism(const shared_ptr<Ciphertext<Element>> ciphertext, usint i,
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
	shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> LPAlgorithmSHEBV<Element>::EvalAutomorphismKeyGen(const shared_ptr<LPPrivateKey<Element>> privateKey,
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

	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmPREBV<Element>::ReKeyGen(const shared_ptr<LPPrivateKey<Element>> newSK,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
	{
		return origPrivateKey->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchGen(origPrivateKey,
			newSK);
	}

	//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmPREBV<Element>::ReEncrypt(const shared_ptr<LPEvalKey<Element>> EK,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
	{
		return ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(EK, ciphertext);

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmBV<Element>::ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const {

		shared_ptr<Ciphertext<Element>> newcipherText(new Ciphertext<Element>(*cipherText));

		std::vector<Element> cipherTextElements(cipherText->GetElements());

		BigInteger plaintextModulus(cipherText->GetCryptoParameters()->GetPlaintextModulus());

		for (auto &cipherTextElement : cipherTextElements) {
			cipherTextElement.ModReduce(plaintextModulus); // this is being done at the lattice layer. The ciphertext is mod reduced.
		}

		newcipherText->SetElements(cipherTextElements);

		return newcipherText;
	}


	//makeSparse is not used by this scheme
	template <class Element>
	LPKeyPair<Element> LPAlgorithmMultipartyBV<Element>::MultipartyKeyGen(CryptoContext<Element>* cc,
		const vector<shared_ptr<LPPrivateKey<Element>>>& secretKeys,
		bool makeSparse)
	{

		LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));
		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBV<Element>>(cc->GetCryptoParameters());
		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		const typename Element::Integer &p = cryptoParams->GetPlaintextModulus();
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
			shared_ptr<LPPrivateKey<Element>> sk1 = secretKeys[i];
			Element s1 = sk1->GetPrivateElement();
			s += s1;
		}
//		s.SwitchFormat();

		//public key is generated and set
		//privateKey->MakePublicKey(a, publicKey);
		Element e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();

		Element b = a*s + p*e;

		kp.secretKey->SetPrivateElement(std::move(s));
		kp.publicKey->SetPublicElementAtIndex(0, std::move(a));
		kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

		return kp;
	}

//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyBV<Element>::MultipartyKeyGen(CryptoContext<Element>* cc,
		const shared_ptr<LPPublicKey<Element>> pk1, bool makeSparse)
	{


		LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));
		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBV<Element>>(cc->GetCryptoParameters());
		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		const typename Element::Integer &p = cryptoParams->GetPlaintextModulus();
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
		}
		else {
			s = Element(tug, elementParams, Format::COEFFICIENT);
		}
		s.SwitchFormat();

		//public key is generated and set
		//privateKey->MakePublicKey(a, publicKey);
		Element e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();
		//a.SwitchFormat();

		Element b = a*s + p*e;

		kp.secretKey->SetPrivateElement(std::move(s));
		kp.publicKey->SetPublicElementAtIndex(0, std::move(a));
		kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

		return kp;
	}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmMultipartyBV<Element>::MultipartyDecryptLead(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
{

		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
		const std::vector<Element> &c = ciphertext->GetElements();
		const Element &s = privateKey->GetPrivateElement();

		Element b = c[0] - s*c[1];

		shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));
		newCiphertext->SetElements({ b });

		return newCiphertext;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmMultipartyBV<Element>::MultipartyDecryptMain(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
{
	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const std::vector<Element> &c = ciphertext->GetElements();

	const Element &s = privateKey->GetPrivateElement();

	Element b = s*c[1];

	shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));
	newCiphertext->SetElements({ b });

	return newCiphertext;
}


template <class Element>
DecryptResult LPAlgorithmMultipartyBV<Element>::MultipartyDecryptFusion(const vector<shared_ptr<Ciphertext<Element>>>& ciphertextVec,
		Poly *plaintext) const
{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
	const BigInteger &p = cryptoParams->GetPlaintextModulus();

	const std::vector<Element> &cElem = ciphertextVec[0]->GetElements();
	Element b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<Element> &c2 = ciphertextVec[i]->GetElements();
		b -= c2[0];
	}

	b.SwitchFormat();	

	// Interpolation is needed in the case of Double-CRT interpolation, for example, DCRTPoly
	// CRTInterpolate does nothing when dealing with single-CRT ring elements, such as Poly
	Poly interpolatedElement = b.CRTInterpolate();
	*plaintext = interpolatedElement.SignedMod(p);

	return DecryptResult(plaintext->GetLength());

}

	// Enable for LPPublicKeyEncryptionSchemeLTV
	template <class Element>
	void LPPublicKeyEncryptionSchemeBV<Element>::Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPAlgorithmBV<Element>();
			break;
		case PRE:
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE = new LPAlgorithmPREBV<Element>();
			break;
		case SHE:
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE = new LPAlgorithmSHEBV<Element>();
			break;
		case LEVELEDSHE:
			if (this->m_algorithmLeveledSHE == NULL)
				this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmBV<Element>();
			break;
		case MULTIPARTY:
			if (this->m_algorithmMultiparty == NULL)
				this->m_algorithmMultiparty = new LPAlgorithmMultipartyBV<Element>();
			break;
		case FHE:
			throw std::logic_error("FHE feature not supported for BV scheme");
		}
	}

}  // namespace lbcrypto ends

#endif
