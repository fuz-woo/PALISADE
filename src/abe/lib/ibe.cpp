/*
* @file ibe.cpp - Implementation file for IBE scheme operations.
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

#include "ibe.h"

namespace lbcrypto{
	//Method for setup phase of an IBE cycle
	template<class Element>
	void IBEScheme<Element>::Setup(shared_ptr<ABECoreParams<Element>> bm_params,ABECoreMasterPublicKey<Element> * bmpk, ABECoreMasterSecretKey<Element> * bmsk){
		shared_ptr<IBEParams<Element>> m_params = dynamic_pointer_cast<IBEParams<Element>>(bm_params);
		IBEMasterPublicKey<Element>* mpk = dynamic_cast<IBEMasterPublicKey<Element>*>(bmpk);
		IBEMasterSecretKey<Element>* msk = dynamic_cast<IBEMasterSecretKey<Element>*>(bmsk);
		std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keypair = RLWETrapdoorUtility<Element>::TrapdoorGen(m_params->GetTrapdoorParams()->GetElemParams(), SIGMA, m_params->GetTrapdoorParams()->GetBase());
		mpk->SetA(std::make_shared<Matrix<Element>>(keypair.first));
		msk->SetTA(std::make_shared<RLWETrapdoorPair<Element>>(keypair.second));
	}
	//Method for key generation phase of an IBE cycle
	template<class Element>
	void IBEScheme<Element>::KeyGen(shared_ptr<ABECoreParams<Element>> bm_params,const ABECoreMasterSecretKey<Element> & bmsk, const ABECoreMasterPublicKey<Element> & bmpk, const ABECoreAccessPolicy<Element> & bid,ABECoreSecretKey<Element>* bsk){
		shared_ptr<IBEParams<Element>> m_params = dynamic_pointer_cast<IBEParams<Element>>(bm_params);
		const IBEMasterPublicKey<Element> & mpk = dynamic_cast<const IBEMasterPublicKey<Element>&>(bmpk);
		const IBEMasterSecretKey<Element>& msk = dynamic_cast<const IBEMasterSecretKey<Element>&>(bmsk);
		const IBEUserIdentifier<Element> & id = dynamic_cast<const IBEUserIdentifier<Element> &>(bid);
		IBESecretKey<Element>* sk = dynamic_cast<IBESecretKey<Element>*>(bsk);
		Matrix<Element> key = RLWETrapdoorUtility<Element>::GaussSamp(m_params->GetTrapdoorParams()->GetN(), m_params->GetTrapdoorParams()->GetK(), mpk.GetA(),msk.GetTA(),id.GetID(), m_params->GetTrapdoorParams()->GetDGGLargeSigma(), m_params->GetTrapdoorParams()->GetDGG(), m_params->GetTrapdoorParams()->GetBase());
		sk->SetSK(std::make_shared<Matrix<Element>>(key));
	}
	//Method for offline sampling for key generation phase of an IBE cycle
	template<class Element>
	PerturbationVector<Element> KeyGenOffline(shared_ptr<IBEParams<Element>> m_params,const IBEMasterSecretKey<Element> & msk){
		shared_ptr<Matrix<Element>> pertubationVector =  RLWETrapdoorUtility<Element>::GaussSampOffline(m_params->GetTrapdoorParams()->GetN(), m_params()->GetTrapdoorParams()->GetK(), msk.GetTA(), m_params->GetTrapdoorParams()->GetDGG(), m_params->GetTrapdoorParams()->GetDGGLargeSigma(), m_params->GetTrapdoorParams()->GetBase());
		PerturbationVector<Element> pvector(pertubationVector);
		return pvector;
	}
	//Method for online phase for key generation phase of an IBE cycle without sampling
	template<class Element>
	void KeyGenOnline(
				shared_ptr<IBEParams<Element>> m_params,
                const IBEMasterSecretKey<Element> & msk,
                const IBEMasterPublicKey<Element> & mpk, 
                const IBEUserIdentifier<Element> & id,
                const PerturbationVector<Element> & pvector,
                IBESecretKey<Element>* sk){
			
		sk->SetSK(RLWETrapdoorUtility<Element>::GaussSampOnline(m_params->GetTrapdoorParams()->GetN(), m_params->GetTrapdoorParams()->GetK(), mpk.GetA(), msk.GetTA(), id.GetID(), m_params->GetTrapdoorParams()->GetDGG(), pvector.GetVector(), m_params->GetTrapdoorParams()->GetBase()));
	}
	//Method for encryption phase of an IBE cycle
	template<class Element>
	void IBEScheme<Element>::Encrypt(shared_ptr<ABECoreParams<Element>> bm_params,const ABECoreMasterPublicKey<Element> & bmpk,  const ABECoreAccessPolicy<Element> & bid, Element pt, ABECoreCiphertext<Element> * bctext){
		shared_ptr<IBEParams<Element>> m_params = dynamic_pointer_cast<IBEParams<Element>>(bm_params);
		const IBEMasterPublicKey<Element> & mpk = dynamic_cast<const IBEMasterPublicKey<Element>&>(bmpk);
		const IBEUserIdentifier<Element> & id = dynamic_cast<const IBEUserIdentifier<Element> &>(bid);
		IBECiphertext<Element>* ctext = dynamic_cast<IBECiphertext<Element>*>(bctext);
		usint m_m = m_params->GetTrapdoorParams()->GetK()+2;

		Matrix<Element> err(Element::MakeDiscreteGaussianCoefficientAllocator(m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT, SIGMA),m_m+1, 1);
		
		Matrix<Element> ctC0(Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(), EVALUATION), 1, m_m);
		Element ctC1(m_params->GetDUG(), m_params->GetTrapdoorParams()->GetElemParams(), EVALUATION); 
		const Matrix<Element> & pubA = mpk.GetA();
		
		for(usint i=0; i < m_m+1;i++){
				err(i,0).SwitchFormat();
		}

		Element s(m_params->GetDUG(), m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT);
		s.SwitchFormat();

		for(usint j=0; j<m_m; j++)
			(ctC0)(0, j) = pubA(0, j)*s + err(j, 0);

		// compute c1
		Element qHalf(m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT, true);
		qHalf += (m_params->GetTrapdoorParams()->GetElemParams()->GetModulus()>> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		Element  uid = id.GetID();
		
		if(uid.GetFormat() != EVALUATION)
			uid.SwitchFormat();
		if(pt.GetFormat() != EVALUATION)
			pt.SwitchFormat();


		ctC1 = s*(uid) + (pt)*qHalf  + err(m_m, 0);

		ctext->SetC0(std::make_shared<Matrix<Element>>(ctC0));
		ctext->SetC1(ctC1);
	}
	//Method for decryption phase of an IBE cycle
	template <class Element>
    void IBEScheme<Element>::Decrypt(shared_ptr<ABECoreParams<Element>> bm_params,const ABECoreAccessPolicy<Element> & bap,const ABECoreAccessPolicy<Element> & bua,const ABECoreSecretKey<Element> & busk,  const ABECoreCiphertext<Element> & bctext, Element* dtext){
		shared_ptr<IBEParams<Element>> m_params = dynamic_pointer_cast<IBEParams<Element>>(bm_params);
		const IBESecretKey<Element> & usk = dynamic_cast<const IBESecretKey<Element>&>(busk);
		const IBECiphertext<Element> & ctext = dynamic_cast<const IBECiphertext<Element> &>(bctext);
		usint m_m = m_params->GetTrapdoorParams()->GetK()+2;

    	const Matrix<Element> & ctC0 = ctext.GetC0();
    	const Element & ctC1 = ctext.GetC1();
    	const Matrix<Element> & sk = usk.GetSK();
    	dtext->SetValuesToZero();
		if(dtext->GetFormat() != EVALUATION)
			dtext->SwitchFormat();

		for(usint j=0; j<m_m; j++)
			*dtext += ctC0(0, j)*sk(j, 0);

		*dtext = ctC1 - *dtext;
		dtext->SwitchFormat();

		typename Element::Integer m_q(m_params->GetTrapdoorParams()->GetElemParams()->GetModulus());
		typename Element::Integer dec, threshold = m_q >> 2, qHalf = m_q >> 1;
		for (usint i = 0; i < m_params->GetTrapdoorParams()->GetN(); i++)
		{
			dec = dtext->at(i);

			if (dec > qHalf)
				dec = m_q - dec;
			if (dec > threshold)
			  dtext->at(i)= typename Element::Integer(1);
			else
			  dtext->at(i)= typename Element::Integer(0);
		}
    }
	// Method for decryption phase of an IBE cycle, assumes that ciphertext was evaluated under the identifier beforehand
	template <class Element>
    void IBEScheme<Element>::Decrypt(shared_ptr<ABECoreParams<Element>> bm_params,const ABECoreSecretKey<Element> & busk,  const ABECoreCiphertext<Element> & bectext, Element* dtext){
		shared_ptr<IBEParams<Element>> m_params = dynamic_pointer_cast<IBEParams<Element>>(bm_params);
		const IBESecretKey<Element> & usk = dynamic_cast<const IBESecretKey<Element>&>(busk);
		const IBECiphertext<Element> & ectext = dynamic_cast<const IBECiphertext<Element> &>(bectext);
		usint m_m = m_params->GetTrapdoorParams()->GetK()+2;

    	
    	const Matrix<Element> & ctC0 = ectext.GetC0();
    	const Element & ctC1 = ectext.GetC1();
    	const Matrix<Element> & sk = usk.GetSK();
    	dtext->SetValuesToZero();
		if(dtext->GetFormat() != EVALUATION)
			dtext->SwitchFormat();

		for(usint j=0; j<m_m; j++)
			*dtext += ctC0(0, j)*sk(j, 0);

		*dtext = ctC1 - *dtext;
		dtext->SwitchFormat();

		typename Element::Integer m_q(m_params->GetTrapdoorParams()->GetElemParams()->GetModulus());
		typename Element::Integer dec, threshold = m_q >> 2, qHalf = m_q >> 1;
		for (usint i = 0; i < m_params->GetTrapdoorParams()->GetN(); i++)
		{
			dec = dtext->at(i);

			if (dec > qHalf)
				dec = m_q - dec;
			if (dec > threshold)
			  dtext->at(i)= typename Element::Integer(1);
			else
			  dtext->at(i)= typename Element::Integer(0);
		}
    }
}