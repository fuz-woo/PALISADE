/*
* @file ltv.cpp - LTV scheme implementation.
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
 * This code provides support for the LTV cryptoscheme.
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our design is informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
 *
 * Note that weaknesses have been discovered in this scheme and it should be used carefully.  Weaknesses come from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
*/

#ifndef LBCRYPTO_CRYPTO_LTV_C
#define LBCRYPTO_CRYPTO_LTV_C

#include "ltv.h"

namespace lbcrypto {

template <class Element>
LPKeyPair<Element> LPAlgorithmLTV<Element>::KeyGen(CryptoContext<Element> cc, bool makeSparse)
{
	LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<Element>>(cc->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const auto p = cryptoParams->GetPlaintextModulus();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	Element f(elementParams, Format::COEFFICIENT);
	do {
		f = Element(dgg, elementParams, Format::COEFFICIENT);
		f = p*f;

		f = f + 1;

		if( makeSparse )
			f.MakeSparse(2);

		f.SwitchFormat();
	} while (!f.InverseExists());

	kp.secretKey->SetPrivateElement(f);

	Element g(dgg, elementParams, Format::COEFFICIENT);

	g.SwitchFormat();

	//public key is generated
	kp.publicKey->SetPublicElementAtIndex(0, std::move(p*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse()));

	return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmLTV<Element>::Encrypt(const LPPublicKey<Element> publicKey,
	Element ptxt) const
{
	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(publicKey->GetCryptoParameters());

	Ciphertext<Element> ciphertext(new CiphertextImpl<Element>(publicKey));

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const auto p = cryptoParams->GetPlaintextModulus();

	ptxt.SwitchFormat();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	const Element &h = publicKey->GetPublicElements().at(0);

	Element s(dgg, elementParams);

	Element e(dgg, elementParams);

	Element c(elementParams);

	c = h*s + p*e + ptxt;

	ciphertext->SetElement(c);

	return ciphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmLTV<Element>::Encrypt(const LPPrivateKey<Element> privateKey,
	Element ptxt) const
{
	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(privateKey->GetCryptoParameters());

	Ciphertext<Element> ciphertext(new CiphertextImpl<Element>(privateKey));

	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
	const auto p = cryptoParams->GetPlaintextModulus();

	ptxt.SwitchFormat();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	// Placeholder implementation that is mostly correct
	Element g(dgg, elementParams, Format::COEFFICIENT);
	g.SwitchFormat();
	const Element h = p*g*privateKey->GetPrivateElement().MultiplicativeInverse();

	Element s(dgg, elementParams);

	Element e(dgg, elementParams);

	Element c(elementParams);

	c = h*s + p*e + ptxt;

	ciphertext->SetElement(c);

	return ciphertext;
}

template <class Element>
DecryptResult LPAlgorithmLTV<Element>::Decrypt(const LPPrivateKey<Element> privateKey,
	const Ciphertext<Element> ciphertext,
	NativePoly *plaintext) const
{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const auto p = cryptoParams->GetPlaintextModulus();

	const Element& c = ciphertext->GetElement();

	const Element& f = privateKey->GetPrivateElement();

	Element b = f*c;

	b.SwitchFormat();

	*plaintext = b.DecryptionCRTInterpolate(p);

	return DecryptResult(plaintext->GetLength());

}

template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalAdd(
	const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2) const
{
	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "EvalAdd crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

	Element cResult = ciphertext1->GetElement() + ciphertext2->GetElement();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalAdd(
	const Ciphertext<Element> ciphertext,
	const Plaintext plaintext) const
{
//	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
//		std::string errMsg = "EvalAdd crypto parameters are not the same";
//		throw std::runtime_error(errMsg);
//	}

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	plaintext->GetEncodedElement<Element>().SetFormat(EVALUATION);

	Element cResult = ciphertext->GetElement() + plaintext->GetEncodedElement<Element>();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalSub(
	const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2) const
{
	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "EvalSub crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

	Element cResult = ciphertext1->GetElement() - ciphertext2->GetElement();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalSub(
	const Ciphertext<Element> ciphertext,
	const Plaintext plaintext) const
{
//	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
//		std::string errMsg = "EvalSub crypto parameters are not the same";
//		throw std::runtime_error(errMsg);
//	}

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	plaintext->GetEncodedElement<Element>().SetFormat(EVALUATION);

	Element cResult = ciphertext->GetElement() - plaintext->GetEncodedElement<Element>();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

// Homomorphic multiplication of ciphertexts without key switching
template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalMult(
	const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2) const
{

	if (ciphertext1->GetElement().GetFormat() == Format::COEFFICIENT || ciphertext2->GetElement().GetFormat() == Format::COEFFICIENT) {
		throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
	}

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "EvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

	Element cResult = ciphertext1->GetElement() * ciphertext2->GetElement();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

// Homomorphic multiplication of ciphertexts with key switching
template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalMult(const Ciphertext<Element> ciphertext1,
	const Ciphertext<Element> ciphertext2, const LPEvalKey<Element> ek) const {

	Ciphertext<Element> newCiphertext = EvalMult(ciphertext1, ciphertext2);

	newCiphertext = KeySwitch(ek, newCiphertext);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalMult(
	const Ciphertext<Element> ciphertext,
	const Plaintext plaintext) const
{
	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	plaintext->GetEncodedElement<Element>().SetFormat(EVALUATION);

	if (ciphertext->GetElement().GetFormat() == Format::COEFFICIENT || plaintext->GetEncodedElement<Element>().GetFormat() == Format::COEFFICIENT ) {
		throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
	}

	Element cResult = ciphertext->GetElement() * plaintext->GetEncodedElement<Element>();

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalNegate(const Ciphertext<Element> ciphertext) const {

	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	const Element& c1 = ciphertext->GetElement();

	newCiphertext->SetElement(c1.Negate());

	return newCiphertext;
}

/**
* Method for KeySwitching based on a KeySwitchHint
*
* This function Calculates a  KeySwitchHint. The hint is used to convert a ciphertext encrypted with
* private key A to a ciphertext that is decryptable by the public key of B.
* The algorithm can be found from this paper.
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
*
* KeySwitchHint
*/
template<class Element>
LPEvalKey<Element> LPAlgorithmSHELTV<Element>::KeySwitchGen(
	const LPPrivateKey<Element> originalPrivateKey,
	const LPPrivateKey<Element> newPrivateKey) const {

	LPEvalKey<Element> keySwitchHint(new LPEvalKeyNTRUImpl<Element>(originalPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersLTV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<Element>>(originalPrivateKey->GetCryptoParameters());

	const Element& f1 = originalPrivateKey->GetPrivateElement();
	const Element& f2 = newPrivateKey->GetPrivateElement();
	const auto p = cryptoParams->GetPlaintextModulus();

	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	Element e(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);

	e.SwitchFormat();

	Element m(p*e);

	m.AddILElementOne();

	Element newKeyInverse = f2.MultiplicativeInverse();

	Element keySwitchHintElement(m * f1 * newKeyInverse);

	keySwitchHint->SetA(std::move(keySwitchHintElement));
	return keySwitchHint;
}

/*
* Method for KeySwitching based on a KeySwitchHint
*
* This function performs KeySwitch based on a KeySwitchHint.
* The algorithm can be found from this paper:
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
*
* KeySwitch takes in a KeySwitchHint and a cipher text. Based on the two, it calculates and returns a new ciphertext.
* if the KeySwitchHint constructed for Private Key A is converted to Private Key B, then the new ciphertext, originally encrypted with
* private key A, is now decryptable by private key B (and not A).
*/
template<class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::KeySwitch(
	const LPEvalKey<Element> keySwitchHint,
	const Ciphertext<Element> cipherText) const {

	//Get the EvalKeyNTRU to perform key swich, also verfies if proper EvalKey is instantiated.
	const LPEvalKeyNTRU<Element> keyHint = std::dynamic_pointer_cast<LPEvalKeyNTRUImpl<Element>>(keySwitchHint);

	Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();

	Element newCipherTextElement = cipherText->GetElement() * keyHint->GetA();

	newCiphertext->SetElement(newCipherTextElement);

	return newCiphertext;
}


//Function to generate an evaluation key for homomorphic evaluation (for depth 2)
template <class Element>
LPEvalKey<Element> LPAlgorithmSHELTV<Element>::EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const
{

	const Element& f = originalPrivateKey->GetPrivateElement();

	LPPrivateKey<Element> quadraticPrivateKey(new LPPrivateKeyImpl<Element>(originalPrivateKey->GetCryptoContext()));
	quadraticPrivateKey->SetPrivateElement(std::move(f*f));

	return KeySwitchGen(quadraticPrivateKey,originalPrivateKey);

}

//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
LPEvalKey<Element> LPAlgorithmSHELTV<Element>::KeySwitchRelinGen(const LPPublicKey<Element> newPublicKey,
	const LPPrivateKey<Element> origPrivateKey) const
{

	// create a new EvalKey of the proper type, in this context
	LPEvalKeyNTRURelin<Element> ek(new LPEvalKeyNTRURelinImpl<Element>(newPublicKey->GetCryptoContext()));

	// the wrapper checked to make sure that the input keys were created in the proper context

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(newPublicKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const auto p = cryptoParamsLWE->GetPlaintextModulus();
	const Element &f = origPrivateKey->GetPrivateElement();

	const Element &hn = newPublicKey->GetPublicElements().at(0);

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<Element> evalKeyElements(f.PowersOfBase(relinWindow));

	const typename Element::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();

	for (usint i = 0; i < evalKeyElements.size(); ++i)
	{
		Element s(dgg, elementParams, Format::EVALUATION);
		Element e(dgg, elementParams, Format::EVALUATION);

		evalKeyElements.at(i) += hn*s + p*e;
	}

	ek->SetAVector(std::move(evalKeyElements));

	return ek;
}

//Function for re-encypting ciphertext using the array generated by KeySwitchRelinGen
template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::KeySwitchRelin(const LPEvalKey<Element>evalKey,
	const Ciphertext<Element> ciphertext) const
{
	Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

	const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParamsLWE =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(evalKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsLWE->GetElementParams();

	const std::vector<Element> &proxy = evalKey->GetAVector();

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	const Element& c = ciphertext->GetElement();

	std::vector<Element> digits(c.BaseDecompose(relinWindow));

	Element ct(digits[0] * proxy[0]);

	for (usint i = 1; i < digits.size(); ++i)
		ct += digits[i] * proxy[i];

	newCiphertext->SetElement(std::move(ct));

	return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHELTV<Element>::EvalAutomorphism(const Ciphertext<Element> ciphertext, usint i,
	const std::map<usint, LPEvalKey<Element>> &evalKeys) const
{

	Ciphertext<Element> permutedCiphertext(new CiphertextImpl<Element>(*ciphertext));

	permutedCiphertext->SetElement(ciphertext->GetElement().AutomorphismTransform(i));

	return ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchRelin(evalKeys.find(i)->second, permutedCiphertext);

}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> LPAlgorithmSHELTV<Element>::EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
	const LPPrivateKey<Element> origPrivateKey, const::std::vector<usint> &indexList) const
{
	const Element &privateKeyElement = origPrivateKey->GetPrivateElement();

	usint n = privateKeyElement.GetRingDimension();

	LPPrivateKey<Element> tempPrivateKey(new LPPrivateKeyImpl<Element>(origPrivateKey->GetCryptoContext()));

	shared_ptr<std::map<usint, LPEvalKey<Element>>> evalKeys(new std::map<usint, LPEvalKey<Element>>());

	if (indexList.size() > n - 1)
		throw std::logic_error("size exceeds the ring dimension");
	else {

		for (usint i = 0; i < indexList.size(); i++)
		{
			Element permutedPrivateKeyElement = privateKeyElement.AutomorphismTransform(indexList[i]);

			tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

			(*evalKeys)[indexList[i]] = publicKey->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchRelinGen(publicKey, tempPrivateKey);

		}

	}

	return evalKeys;
}

//Function to generate 1..log(q) encryptions for each bit of the original private key
template <class Element>
LPEvalKey<Element> LPAlgorithmPRELTV<Element>::ReKeyGen(const LPPublicKey<Element> newPK,
	const LPPrivateKey<Element> origPrivateKey) const
{
	return origPrivateKey->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchRelinGen(newPK, origPrivateKey);
}

//Function for re-encypting ciphertext using the array generated by ReKeyGen
template <class Element>
Ciphertext<Element> LPAlgorithmPRELTV<Element>::ReEncrypt(const LPEvalKey<Element> evalKey,
	const Ciphertext<Element> ciphertext) const
{
	return ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchRelin(evalKey, ciphertext);
}


/**
* This function performs ModReduce on ciphertext element and private key element. The algorithm can be found from this paper:
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
*
* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus q/qi. The qi is generally the largest. In the code below,
* ModReduce is written for DCRTPoly and it drops the last tower while updating the necessary parameters.
*/
template<class Element> inline
Ciphertext<Element> LPLeveledSHEAlgorithmLTV<Element>::ModReduce(Ciphertext<Element> cipherText) const {

	Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();

	Element cipherTextElement(cipherText->GetElement());

	const auto plaintextModulus = cipherText->GetCryptoParameters()->GetPlaintextModulus();

	cipherTextElement.ModReduce(plaintextModulus); // this is being done at the lattice layer. The ciphertext is mod reduced.

	newCiphertext->SetElement(cipherTextElement);

	return newCiphertext;

}

/**
* This function performs RingReduce on ciphertext element and private key element. The algorithm can be found from this paper:
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
* The paper quoted above has an algorithm for generic RingReduce, the code here only reduces the ring by a factor of 2. By the ring, we mean the ring dimension.
* @Input params are cipherText and privateKey, output cipherText element is ring reduced by a factor of 2
*
*/
template<class Element>
Ciphertext<Element>
LPLeveledSHEAlgorithmLTV<Element>::RingReduce(Ciphertext<Element> cipherText, const LPEvalKey<Element> keySwitchHint) const {

	//KeySwitching to a cipherText that can be decrypted by a sparse key.
	Ciphertext<Element> newcipherText = cipherText->GetCryptoContext()->KeySwitch(keySwitchHint, cipherText);

	//Once the keyswitching of the ciphertext has been done, based on the algorithm in the referenced paper, the ciphertext needs to be decomposed.
	Element keySwitchedCipherTextElement(newcipherText->GetElement());

	//changing from EVALUATION to COEFFICIENT domain before performing Decompose operation. Decompose is done in coeffiecient domain.
	keySwitchedCipherTextElement.SwitchFormat();

	/*Based on the algorithm their needs to be a decompose done on the ciphertext. The W factor in this function is 2. The decompose is done
	on the elements of keySwitchedCipherTextElement*/
	keySwitchedCipherTextElement.Decompose();

	//Converting back to EVALUATION representation.
	keySwitchedCipherTextElement.SwitchFormat();

	//setting the decomposed element into ciphertext.
	newcipherText->SetElement(keySwitchedCipherTextElement);

	return newcipherText;
}

template<class Element>
Ciphertext<Element> LPLeveledSHEAlgorithmLTV<Element>::ComposedEvalMult(
	const Ciphertext<Element> cipherText1,
	const Ciphertext<Element> cipherText2,
	const LPEvalKey<Element> ek) const {

	Ciphertext<Element> prod = cipherText1->GetCryptoContext()->GetEncryptionAlgorithm()->EvalMult(cipherText1, cipherText2, ek);

	return this->ModReduce(prod);
}

template<class Element>
Ciphertext<Element> LPLeveledSHEAlgorithmLTV<Element>::LevelReduce(const Ciphertext<Element> cipherText1,
	const LPEvalKey<Element> linearKeySwitchHint) const {

	Ciphertext<Element> cipherTextResult = cipherText1->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(linearKeySwitchHint, cipherText1);

	return this->ModReduce(cipherTextResult);
}

template<class Element>
bool LPLeveledSHEAlgorithmLTV<Element>::CanRingReduce(usint ringDimension, const std::vector<BigInteger> &moduli, const double rootHermiteFactor) const
{
	if (ringDimension == 1) return false;
	ringDimension = ringDimension / 2;
	double multipliedModuli = 1;

	for (usint i = 0; i < moduli.size(); i++) {
		multipliedModuli = multipliedModuli*  moduli.at(i).ConvertToDouble();
	}
	double powerValue = log2(multipliedModuli) / (4 * ringDimension);
	double powerOfTwo = pow(2, powerValue);

	return rootHermiteFactor >= powerOfTwo;
}

// Enable for LPPublicKeyEncryptionSchemeLTV
template <class Element>
void LPPublicKeyEncryptionSchemeLTV<Element>::Enable(PKESchemeFeature feature) {
	switch (feature)
	{
	case ENCRYPTION:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmLTV<Element>();
		break;
	case PRE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmLTV<Element>();
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>();
		break;
	case SHE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmLTV<Element>();
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
		break;
	case LEVELEDSHE:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmLTV<Element>();
		if (this->m_algorithmLeveledSHE == NULL)
			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>();
		break;
	case FHE:
		throw std::logic_error("FHE feature not supported for LTV scheme");
	case MULTIPARTY:
		throw std::logic_error("MULTIPARTY feature not supported for LTV scheme");
	}
}




}  // namespace lbcrypto ends

#endif
