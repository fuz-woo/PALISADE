/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers:
*		K.Doruk Gur <kg365@njit.edu>
* @version 00_01
*
* @section LICENSE
*
* Copyright (c) 2016, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONT0RIBUTORS "AS IS" AND
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
* @section DESCRIPTION
*
* This code provides the utility for GPV Ring-LWE signature scheme with trapdoors. The scheme implemented can be found in the paper https://eprint.iacr.org/2013/297.pdf. Construction 1 of the section 3.2 is used in this implementation. 
*/
#ifndef _SRC_LIB_CRYPTO_SIGNATURE_LWESIGN_CPP
#define _SRC_LIB_CRYPTO_SIGNATURE_LWESIGN_CPP

#include "gpv.h"

namespace lbcrypto {
	
	//Method for generating signing and verification keys
	template <class Element>
	void GPVSignatureScheme<Element>::KeyGen(shared_ptr<LPSignatureParameters<Element>> sparams,LPSignKey<Element>* sk, LPVerificationKey<Element>* vk) {
		GPVSignKey<Element>* signKey = dynamic_cast<GPVSignKey<Element>*>(sk);
		GPVVerificationKey<Element>* verificationKey = dynamic_cast<GPVVerificationKey<Element>*>(vk);
		shared_ptr<GPVSignatureParameters<Element>> m_params = std::dynamic_pointer_cast<GPVSignatureParameters<Element>>(sparams);
		//Get parameters from keys
		shared_ptr<typename Element::Params> params = m_params->GetILParams();
		auto stddev = m_params->GetDiscreteGaussianGenerator().GetStd();
		usint base = m_params->GetBase();

		//Generate trapdoor based using parameters and 
		std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keyPair = RLWETrapdoorUtility<Element>::TrapdoorGen(params, stddev, base);
		//Format of vectors are changed to prevent complications in calculations 
		keyPair.second.m_e.SetFormat(EVALUATION);
		keyPair.second.m_r.SetFormat(EVALUATION);
		keyPair.first.SetFormat(EVALUATION);

		//Verification key will be set to the uniformly sampled matrix used in trapdoor
		verificationKey->SetVerificationKey(std::make_shared<Matrix<Element>>(keyPair.first));

		//Signing key will contain public key matrix of the trapdoor and the trapdoor matrices
		signKey->SetSignKey(std::make_shared<RLWETrapdoorPair<Element>>(keyPair.second));
		size_t n = params->GetRingDimension();
		if (n > 32) {
			for (size_t i = 0;i < n - 32;i = i + 4) {
				int rand = (PseudoRandomNumberGenerator::GetPRNG())();
				seed.push_back((rand >> 24) & 0xFF);
				seed.push_back((rand >> 16) & 0xFF);
				seed.push_back((rand >> 8) & 0xFF);
				seed.push_back((rand) & 0xFF);
			}
		}
	}

	//Method for signing given object
	template <class Element>
	void GPVSignatureScheme<Element>::Sign(shared_ptr<LPSignatureParameters<Element>> sparams,const LPSignKey<Element> & sk,const LPVerificationKey<Element> &vk, const LPSignPlaintext<Element> & pt, LPSignature<Element>* sign) {
		
		shared_ptr<GPVSignatureParameters<Element>> m_params = std::dynamic_pointer_cast<GPVSignatureParameters<Element>>(sparams);
		const GPVSignKey<Element> & signKey = dynamic_cast<const GPVSignKey<Element> &>(sk);
		const GPVVerificationKey<Element> & verificationKey = dynamic_cast<const GPVVerificationKey<Element> &>(vk);
		const GPVPlaintext<Element> & plainText = dynamic_cast<const GPVPlaintext<Element> &>(pt);
		GPVSignature<Element>* signatureText = dynamic_cast<GPVSignature<Element>*>(sign);

		//Getting parameters for calculations
		size_t n = m_params->GetILParams()->GetRingDimension();
		size_t k = m_params->GetK();
		size_t base = m_params->GetBase();

		EncodingParams ep( new EncodingParamsImpl(PlaintextModulus(512)) );

		//Encode the text into a vector so it can be used in signing process. TODO: Adding some kind of digestion algorithm
		vector<int64_t> digest;
		HashUtil::Hash(plainText.GetPlaintext(), SHA_256, digest);
		if( plainText.GetPlaintext().size() <= n ) {
			for(size_t i = 0;i < n - 32;i = i + 4)
				digest.push_back(seed[i]);
		}
		Plaintext hashedText( new CoefPackedEncoding(m_params->GetILParams(), ep, digest) );
		hashedText->Encode();

		Element &u = hashedText->GetElement<Element>();
		u.SwitchFormat();

		//Getting the trapdoor, its public matrix, perturbation matrix and gaussian generator to use in sampling
		const Matrix<Element> & A = verificationKey.GetVerificationKey();
		const RLWETrapdoorPair<Element> & T = signKey.GetSignKey();
		typename Element::DggType & dgg = m_params->GetDiscreteGaussianGenerator();

		typename Element::DggType & dggLargeSigma = m_params->GetDiscreteGaussianGeneratorLargeSigma();
		Matrix<Element> zHat = RLWETrapdoorUtility<Element>::GaussSamp(n,k,A,T,u,dgg,dggLargeSigma,base);
		signatureText->SetSignature(std::make_shared<Matrix<Element>>(zHat));
	}

	//Method for signing given object
	template <class Element>
	shared_ptr<Matrix<Element>> GPVSignatureScheme<Element>::SampleOffline(shared_ptr<GPVSignatureParameters<Element>> m_params,const GPVSignKey<Element> &signKey) {

		//Getting parameters for calculations
		size_t n = m_params->GetILParams()->GetRingDimension();
		size_t k = m_params->GetK();
		size_t base = m_params->GetBase();

		//Getting the trapdoor and gaussian generatorw to use in sampling
		const RLWETrapdoorPair<Element> & T = signKey.GetSignKey();
		typename Element::DggType & dgg = m_params->GetDiscreteGaussianGenerator();
		typename Element::DggType & dggLargeSigma = m_params->GetDiscreteGaussianGeneratorLargeSigma();

		return RLWETrapdoorUtility<Element>::GaussSampOffline(n, k, T, dgg, dggLargeSigma, base);
	}

	//Method for signing given object
	template <class Element>
	void GPVSignatureScheme<Element>::SignOnline(shared_ptr<GPVSignatureParameters<Element>> m_params,const GPVSignKey<Element> &signKey, 
		const GPVVerificationKey<Element> &verificationKey,const shared_ptr<Matrix<Element>> perturbationVector,	const string &plainText,
		GPVSignature<Element> *signatureText) {

		//Getting parameters for calculations
		size_t n = m_params->GetILParams()->GetRingDimension();
		size_t k = m_params->GetK();
		size_t base = m_params->GetBase();

		EncodingParams ep( new EncodingParamsImpl(PlaintextModulus(512)) );

		//Encode the text into a vector so it can be used in signing process. TODO: Adding some kind of digestion algorithm
		vector<int64_t> digest;
		Plaintext hashedText;
		HashUtil::Hash(plainText, SHA_256, digest);

		if( plainText.size() <= n ) {
			for (size_t i = 0;i < n - 32;i = i + 4)
				digest.push_back(seed[i]);
		}

		hashedText.reset( new CoefPackedEncoding(m_params->GetILParams(), ep, digest) );
		hashedText->Encode();

		Element &u = hashedText->GetElement<Element>();
		u.SwitchFormat();


		//Getting the trapdoor, its public matrix, perturbation matrix and gaussian generator to use in sampling
		const Matrix<Element> & A = verificationKey.GetVerificationKey();
		const RLWETrapdoorPair<Element> & T = signKey.GetSignKey();
		typename Element::DggType & dgg = m_params->GetDiscreteGaussianGenerator();

		Matrix<Element> zHat = RLWETrapdoorUtility<Element>::GaussSampOnline(n, k, A, T, u, dgg, perturbationVector, base);
		signatureText->SetSignature(std::make_shared<Matrix<Element>>(zHat));
	}

	
	//Method for verifying given object & signature
	template <class Element>
	bool GPVSignatureScheme<Element>::Verify(shared_ptr<LPSignatureParameters<Element>> sparams,const LPVerificationKey<Element> & vk,const LPSignature<Element> & sign, const LPSignPlaintext<Element> & pt) {
		
		shared_ptr<GPVSignatureParameters<Element>> m_params = std::dynamic_pointer_cast<GPVSignatureParameters<Element>>(sparams);
		const GPVVerificationKey<Element> & verificationKey = dynamic_cast<const GPVVerificationKey<Element> &>(vk);
		const GPVPlaintext<Element> & plainText = dynamic_cast<const GPVPlaintext<Element> &>(pt);
		const GPVSignature<Element> & signatureText = dynamic_cast<const GPVSignature<Element> &>(sign);
		size_t n = m_params->GetILParams()->GetRingDimension();

		EncodingParams ep( new EncodingParamsImpl(PlaintextModulus(512)) );

		//Encode the text into a vector so it can be used in signing process. TODO: Adding some kind of digestion algorithm
		vector<int64_t> digest;
		Plaintext hashedText;
		HashUtil::Hash(plainText.GetPlaintext(), SHA_256, digest);

		if( plainText.GetPlaintext().size() <= n ) {
			for (size_t i = 0;i < n - 32;i = i + 4)
				digest.push_back(seed[i]);
		}

		hashedText.reset( new CoefPackedEncoding(m_params->GetILParams(), ep, digest) );
		hashedText->Encode();

		Element &u = hashedText->GetElement<Element>();
		u.SwitchFormat();

		//Multiply signature with the verification key
		const Matrix<Element> & A = verificationKey.GetVerificationKey();
		const Matrix<Element> & z = signatureText.GetSignature();

		//Check the verified vector is actually the encoding of the object
		 return u == (A*z)(0, 0);
	}

}
#endif
