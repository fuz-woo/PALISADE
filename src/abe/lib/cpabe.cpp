
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

#include "cpabe.h"

namespace lbcrypto{
      //Method for setup phase of a CPABE cycle
    template <class Element>
    void CPABEScheme<Element>::Setup(shared_ptr<ABECoreParams<Element>> bm_params,ABECoreMasterPublicKey<Element>* bmpk, ABECoreMasterSecretKey<Element>* bmsk){
		shared_ptr<CPABEParams<Element>> m_params = dynamic_pointer_cast<CPABEParams<Element>>(bm_params);
		CPABEMasterPublicKey<Element>* mpk = dynamic_cast<CPABEMasterPublicKey<Element>*>(bmpk);
		CPABEMasterSecretKey<Element>* msk = dynamic_cast<CPABEMasterSecretKey<Element>*>(bmsk);
		
		typename Element::DugType& dug = m_params->GetDUG();
		usint m_N = m_params->GetTrapdoorParams()->GetN();
		usint m_ell = m_params->GetEll();
		usint m_m = m_params->GetTrapdoorParams()->GetK() + 2;
		auto zero_alloc = Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT);
		
		Matrix<Element> pubElemBPos(zero_alloc, m_ell, m_m);
		Matrix<Element> pubElemBNeg(zero_alloc, m_ell, m_m);
		Element pubElemD(pubElemBPos(0,0));

		if(pubElemD.GetFormat() != COEFFICIENT)
			pubElemD.SwitchFormat();
		pubElemD.SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
		pubElemD.SwitchFormat(); // always kept in EVALUATION format

		for (usint i = 0; i < pubElemBPos.GetRows(); i++)
			for (usint j = 0; j < pubElemBPos.GetCols(); j++) {
				if((pubElemBPos)(i, j).GetFormat() != COEFFICIENT)
					(pubElemBPos)(i,j).SwitchFormat();
				(pubElemBPos)(i, j).SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
				(pubElemBPos)(i, j).SwitchFormat(); // always kept in EVALUATION format
			}

		for (usint i = 0; i < pubElemBNeg.GetRows(); i++)
			for (usint j = 0; j < pubElemBNeg.GetCols(); j++) {
				if((pubElemBNeg)(i, j).GetFormat() != COEFFICIENT)
					(pubElemBNeg)(i,j).SwitchFormat();
				(pubElemBNeg)(i, j).SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
				(pubElemBNeg)(i, j).SwitchFormat(); // always kept in EVALUATION format
			}
		mpk->SetBPos(std::make_shared<Matrix<Element>>(pubElemBPos));
		mpk->SetBNeg(std::make_shared<Matrix<Element>>(pubElemBNeg));
		mpk->SetPubElemD(pubElemD);
		std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keypair = RLWETrapdoorUtility<Element>::TrapdoorGen(m_params->GetTrapdoorParams()->GetElemParams(), SIGMA, m_params->GetTrapdoorParams()->GetBase(),false);
		mpk->SetA(std::make_shared<Matrix<Element>>(keypair.first));
		msk->SetTA(std::make_shared<RLWETrapdoorPair<Element>>(keypair.second));
    }
    //Method for key generation phase of a CPABE cycle
    template <class Element>
    void CPABEScheme<Element>::KeyGen(shared_ptr<ABECoreParams<Element>> bm_params,const ABECoreMasterSecretKey<Element> & bmsk, const ABECoreMasterPublicKey<Element> & bmpk, const ABECoreAccessPolicy<Element> & bid,ABECoreSecretKey<Element>* busk){
    	shared_ptr<CPABEParams<Element>> m_params = dynamic_pointer_cast<CPABEParams<Element>>(bm_params);
		const CPABEMasterSecretKey<Element> & msk = dynamic_cast<const CPABEMasterSecretKey<Element> &>(bmsk);
		const CPABEMasterPublicKey<Element> & mpk = dynamic_cast<const CPABEMasterPublicKey<Element> &>(bmpk);
		const CPABEUserAccess<Element> & id = dynamic_cast<const CPABEUserAccess<Element> &>(bid);
		CPABESecretKey<Element>* usk = dynamic_cast<CPABESecretKey<Element>*>(busk);
		usint m_ell = m_params->GetEll();
    	usint m_k = m_params->GetTrapdoorParams()->GetK();
    	usint m_m = m_k+2;
    	usint m_N = m_params->GetTrapdoorParams()->GetN();
    	usint m_base = m_params->GetTrapdoorParams()->GetBase();
    	double sb = SPECTRAL_BOUND(m_N, m_k,m_base);
		auto ep = m_params->GetTrapdoorParams()->GetElemParams();

			Matrix<Element> skB(Element::MakeDiscreteGaussianCoefficientAllocator(ep, COEFFICIENT, sb), m_m, m_ell);

		//#pragma omp parallel for
			for(usint j=0; j < m_ell;j++){
				for(usint i = 0; i < m_m; i++)
					skB(i,j).SwitchFormat();
			}


			Element y(ep, EVALUATION, true);
			Element z(ep, EVALUATION, true);
			std::vector<Element> z_vectors(m_ell);

			const Matrix<Element> & pubElemBPos = mpk.GetBPos();
			const Matrix<Element> & pubElemBNeg = mpk.GetBNeg();
			const std::vector<usint> s = id.GetS();
			const Element & pubElemD = mpk.GetPubElemD();
		//#pragma omp parallel for firstprivate(z) num_threads(4)
			for(usint i=0; i<m_ell; i++) {
				if(s[i]==1) {
					z = pubElemBPos(i, 0)*skB(0, i);
					for(usint j=1; j<m_m; j++)
						z += pubElemBPos(i, j)*skB(j, i);
				}
				else {
					z = pubElemBNeg(i, 0)*skB(0, i);
					for(usint j=1; j<m_m; j++)
						z += pubElemBNeg(i, j)*skB(j, i);
				}
				z_vectors.at(i) = z;
			}

			for(usint i=0; i < m_ell;i++){
				y += z_vectors.at(i);
			}

			y = pubElemD - y;

			Matrix<Element> skA(Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(), EVALUATION), m_m, 1);

			skA = RLWETrapdoorUtility<Element>::GaussSamp(m_N, m_k, mpk.GetA(), msk.GetTA(), y, m_params->GetTrapdoorParams()->GetDGG(), m_params->GetTrapdoorParams()->GetDGGLargeSigma(), m_base);

			Matrix<Element> sk(Element::Allocator(ep, COEFFICIENT), m_m, m_ell+1);
			for(usint i=0; i<m_m; i++)
				(sk)(i, 0) = skA(i, 0);

		//#pragma omp parallel for num_threads(4)
			for(usint i=0; i<m_ell; i++)
				for(usint j=0; j<m_m; j++)
					(sk)(j, i+1) = skB(j, i);

			usk->SetSK(std::make_shared<Matrix<Element>>(sk));
		}
	//Method for offline sampling for key generation phase of an CPABE cycle
	template <class Element>
	PerturbationVector<Element> KeyGenOffline(shared_ptr<CPABEParams<Element>> m_params,const CPABEMasterSecretKey<Element> & msk){
		shared_ptr<Matrix<Element>> pertubationVector =  RLWETrapdoorUtility<Element>::GaussSampOffline(m_params->GetTrapdoorParams()->GetN(), m_params()->GetTrapdoorParams()->GetK(), msk.GetTA(), m_params->GetTrapdoorParams()->GetDGG(), m_params->GetTrapdoorParams()->GetDGGLargeSigma(), m_params->GetTrapdoorParams()->GetBase());
		PerturbationVector<Element> pvector(pertubationVector);
		return pvector;
	}
	//Method for online phase for key generation phase of an CPABE cycle without sampling
	template <class Element>
	void KeyGenOnline(shared_ptr<CPABEParams<Element>> m_params,const CPABEMasterSecretKey<Element> & msk,const CPABEMasterPublicKey<Element> & mpk, const CPABEUserAccess<Element> & id,const PerturbationVector<Element> & pvector,CPABESecretKey<Element>* usk){
		usint m_ell = m_params->GetEll();
    	usint m_k = m_params->GetTrapdoorParams()->GetK();
    	usint m_m = m_k+2;
    	usint m_N = m_params->GetTrapdoorParams()->GetN();
    	usint m_base = m_params->GetTrapdoorParams()->GetBase();
    	double sb = SPECTRAL_BOUND(m_N, m_k,m_base);
		auto ep = m_params->GetTrapdoorParams()->GetElemParams();

			Matrix<Element> skB(Element::MakeDiscreteGaussianCoefficientAllocator(ep, COEFFICIENT, sb), m_m, m_ell);

		//#pragma omp parallel for
			for(usint j=0; j < m_ell;j++){
				for(usint i = 0; i < m_m; i++)
					skB(i,j).SwitchFormat();
			}


			Element y(ep, EVALUATION, true);
			Element z(ep, EVALUATION, true);
			std::vector<Element> z_vectors(m_ell);

			const Matrix<Element> & pubElemBPos = mpk.GetBPos();
			const Matrix<Element> & pubElemBNeg = mpk.GetBNeg();
			usint *s = id.GetS();
			const Element & pubElemD = mpk.GetPubElemD();
		//#pragma omp parallel for firstprivate(z) num_threads(4)
			for(usint i=0; i<m_ell; i++) {
				if(s[i]==1) {
					z = pubElemBPos(i, 0)*skB(0, i);
					for(usint j=1; j<m_m; j++)
						z += pubElemBPos(i, j)*skB(j, i);
				}
				else {
					z = pubElemBNeg(i, 0)*skB(0, i);
					for(usint j=1; j<m_m; j++)
						z += pubElemBNeg(i, j)*skB(j, i);
				}
				z_vectors.at(i) = z;
			}

			for(usint i=0; i < m_ell;i++){
				y += z_vectors.at(i);
			}

			y = pubElemD - y;

			Matrix<Element> skA(Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(), EVALUATION), m_m, 1);

			skA = RLWETrapdoorUtility<Element>::GaussSampOnline(m_N, m_k, mpk.GetA(), msk.GetTA(), y, m_params->GetTrapdoorParams()->GetDGG(),pvector.GetVector(), m_base);

			Matrix<Element> sk(Element::Allocator(ep, COEFFICIENT), m_m, m_ell+1);
			for(usint i=0; i<m_m; i++)
				(sk)(i, 0) = skA(i, 0);

		//#pragma omp parallel for num_threads(4)
			for(usint i=0; i<m_ell; i++)
				for(usint j=0; j<m_m; j++)
					(sk)(j, i+1) = skB(j, i);

			usk->SetSK(std::make_shared<Matrix<Element>>(sk));
	}
    //Method for encryption phase of a CPABE cycle
    template <class Element>
    void CPABEScheme<Element>::Encrypt(shared_ptr<ABECoreParams<Element>> bm_params,const ABECoreMasterPublicKey<Element> & bmpk, const ABECoreAccessPolicy<Element> & bap, Element ptxt, ABECoreCiphertext<Element>* bctext){
    	shared_ptr<CPABEParams<Element>> m_params = dynamic_pointer_cast<CPABEParams<Element>>(bm_params);
		const CPABEMasterPublicKey<Element> & mpk = dynamic_cast<const CPABEMasterPublicKey<Element> &>(bmpk);
		const CPABEAccessPolicy<Element> & ap = dynamic_cast<const CPABEAccessPolicy<Element> &>(bap);
		CPABECiphertext<Element>* ctext = dynamic_cast<CPABECiphertext<Element>*>(bctext);
		usint lenW = 0;
    	usint m_ell = m_params->GetEll();
    	usint m_N = m_params->GetTrapdoorParams()->GetN();
    	usint m_m = m_params->GetTrapdoorParams()->GetK() + 2;
    	const std::vector<int32_t> & w = ap.GetW();
		auto ep = m_params->GetTrapdoorParams()->GetElemParams();

		for(usint i=0; i<m_ell; i++)
			if(w[i]!=0)
				lenW++;

		Matrix<Element> err(Element::MakeDiscreteGaussianCoefficientAllocator(m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT, SIGMA), m_m, 2*m_ell+2-lenW);

#ifdef OMP
//#pragma omp parallel for num_threads(4)
#endif

		for(usint i=0; i < m_m;i++){
			for(usint j = 0; j < 2*m_ell+2-lenW;j++)
				err(i,j).SwitchFormat();
		}

		typename Element::DugType& dug = m_params->GetDUG();

		Element s(dug, m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT);
		s.SwitchFormat();

		// A part
		usint iNoise = 0;
		const Matrix<Element> & pubTA = mpk.GetA();
		const Matrix<Element> & pubElemBPos = mpk.GetBPos();
		const Matrix<Element> & pubElemBNeg = mpk.GetBNeg();

		Matrix<Element> ctW(Element::Allocator(ep, EVALUATION), lenW+1, m_m);
		Matrix<Element> cPos(Element::Allocator(ep, EVALUATION), m_ell-lenW, m_m);
		Matrix<Element> cNeg(Element::Allocator(ep, EVALUATION), m_ell-lenW, m_m);
//#pragma omp parallel for num_threads(4)
		for(usint j=0; j<m_m; j++)
			(ctW)(0, j) = pubTA(0, j)*s + err(j, iNoise);
		iNoise++;

		// B part
		usint iW = 0;
		usint iAW = 0;
//#pragma omp parallel for num_threads(4)
		for (usint i=0; i<m_ell; i++)
		{
			if(w[i] == 1) {
				for(usint j=0; j<m_m; j++)
					(ctW)(iW+1, j) = pubElemBPos(i, j)*s  + err(j, iNoise);
				iNoise++;
				iW++;
			}
			else if(w[i]==-1) {
				for(usint j=0; j<m_m; j++)
					(ctW)(iW+1, j) = pubElemBNeg(i, j)*s + err(j, iNoise);
				iNoise++;
				iW++;
			}
			else {
				for(usint j=0; j<m_m; j++) {
					(cPos)(iAW, j) = pubElemBPos(i, j)*s  + err(j, iNoise);
					(cNeg)(iAW, j) = pubElemBNeg(i, j)*s + err(j, iNoise+1);

				}
				iNoise+=2;
				iAW++;
			}
		}

		// compute c1
		Element qHalf(m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT, true);
		typename Element::Integer m_q = m_params->GetTrapdoorParams()->GetElemParams()->GetModulus();
		qHalf += (m_q >> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		Element pubElemD = mpk.GetPubElemD();
		Element err1(m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT, true); // error term
		err1.SetValues(m_params->GetTrapdoorParams()->GetDGG().GenerateVector(m_N,m_q), COEFFICIENT);
		err1.SwitchFormat();
		if(ptxt.GetFormat()!=EVALUATION)
			ptxt.SwitchFormat();
		if(pubElemD.GetFormat()!=EVALUATION){
			pubElemD.SwitchFormat();
		}
		Element ctC1(m_params->GetDUG(), m_params->GetTrapdoorParams()->GetElemParams(), EVALUATION);
		ctC1 = s*pubElemD + err1 + ptxt*qHalf;
		
		ctext->SetCW(std::make_shared<Matrix<Element>>(ctW));
		ctext->SetC1(ctC1);
		ctext->SetCPos(std::make_shared<Matrix<Element>>(cPos));
		ctext->SetCNeg(std::make_shared<Matrix<Element>>(cNeg));
    }
    //Method for decryption phase of a CPABE cycle
    template <class Element>
    void CPABEScheme<Element>::Decrypt(shared_ptr<ABECoreParams<Element>> bm_params,const ABECoreAccessPolicy<Element> & bap, const ABECoreAccessPolicy<Element>& bua, const ABECoreSecretKey<Element> & busk, const ABECoreCiphertext<Element> & bctext, Element* dtext){
		shared_ptr<CPABEParams<Element>> m_params = dynamic_pointer_cast<CPABEParams<Element>>(bm_params);
		const CPABESecretKey<Element> & usk = dynamic_cast<const CPABESecretKey<Element> &>(busk);
		const CPABEAccessPolicy<Element> & ap = dynamic_cast<const CPABEAccessPolicy<Element> &>(bap);
		const CPABEUserAccess<Element> & ua = dynamic_cast<const CPABEUserAccess<Element> &>(bua);
		const CPABECiphertext<Element> & ctext = dynamic_cast<const CPABECiphertext<Element>&>(bctext);
		usint m_ell = m_params->GetEll();
		usint m_N = m_params->GetTrapdoorParams()->GetN();
    	
		dtext->SetValuesToZero();
		if(dtext->GetFormat() != EVALUATION)
			dtext->SwitchFormat();
		
		const Matrix<Element> & sk = usk.GetSK();
		const Matrix<Element> & ctW = ctext.GetCW();
		const Matrix<Element> & cPos = ctext.GetCPos();
		const Matrix<Element> & cNeg = ctext.GetCNeg();
		const Element & ctC1 = ctext.GetC1();

		typename Element::Integer m_q = m_params->GetTrapdoorParams()->GetElemParams()->GetModulus();
		usint m_m = m_params->GetTrapdoorParams()->GetK() + 2;
		const std::vector<int32_t> & w = ap.GetW();
		const std::vector<usint> & s = ua.GetS();

		for(usint j=0; j<m_m; j++)
			*dtext += ctW(0, j)*sk(j, 0);

		usint iW=0;
		usint iAW=0;
//#pragma omp parallel for
		for(usint i=0; i<m_ell; i++) {
			if (w[i] == 1  || w[i] == -1) {
				for(usint j=0; j<m_m; j++)
					*dtext += ctW(iW+1, j)*sk(j, i+1);
				iW++;
			}
			else {
				if(s[i]==1)
					for(usint j=0; j<m_m; j++)
						*dtext += cPos(iAW, j)*sk(j, i+1);
				else
					for(usint j=0; j<m_m; j++)
						*dtext += cNeg(iAW, j)*sk(j, i+1);
				iAW++;
			}
		}

		*dtext = ctC1 - *dtext;
		dtext->SwitchFormat();

		typename Element::Integer dec, threshold = m_q >> 2, qHalf = m_q >> 1;
		for (usint i = 0; i < m_N; i++)
		{
			dec = dtext->at(i);

			if (dec > qHalf)
				dec = m_q - dec;
			if (dec > threshold)
			  dtext->at(i)= 1;
			else
			  dtext->at(i)= typename Element::Integer(0);
		}
    }

}
