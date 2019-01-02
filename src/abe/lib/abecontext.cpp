/**
 * @file abecontext.cpp - Implementation file for ABEContext class

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
#include "abecontext.h"

namespace lbcrypto{
    //Method for setting up a CPABE context with specific parameters
    template <class Element>
    void ABEContext<Element>::GenerateCPABEContext(usint ell,usint ringsize,usint base){      
            
            this->ParamsGenCPABE(ringsize,ell,base,m_params);
            shared_ptr<ABECoreScheme<Element>> sch(new CPABEScheme<Element>());
            m_scheme = sch;
            
    }
    //Method for setting up a CPABE context with desired security level and number of attributes only     
    template <class Element>
    void ABEContext<Element>::GenerateCPABEContext(SecurityLevel level,usint ell){
        std::pair<SecurityLevel,usint> key = make_pair(level,ell);
        if(CPABEMinRingSizeMap.count(key)>0){
            std::pair<usint,usint> ringSizeAndBase = CPABEMinRingSizeMap.at(key);
            GenerateCPABEContext(ell,ringSizeAndBase.first,ringSizeAndBase.second);
        }else{
            throw std::logic_error("Unknown minimum ring size and base for given security level and number of attributes");
        }
    }
    //Method for setting up a IBE context with specific parameters
    template <class Element>
    void ABEContext<Element>::GenerateIBEContext(usint ringsize,usint base){
            this->ParamsGenIBE(ringsize,base,m_params);
            shared_ptr<ABECoreScheme<Element>> sch(new IBEScheme<Element>());
            m_scheme = sch;
    }
    //Method for setting shared_ptr<ABECoreParams<Element>> abeparams(new CPABEParams<Element>(std::make_shared<RLWETrapdoorParams<Element>>(tparams),ell,dug)); a IBE context with desired security level only
    template<class Element>
    void ABEContext<Element>::GenerateIBEContext(SecurityLevel level){
        if(IBEMinRingSizeMap.count(level)>0){
            usint ringsize = IBEMinRingSizeMap.at(level).first;
            usint base = IBEMinRingSizeMap.at(level).second;
            GenerateIBEContext(ringsize,base);
        }else{
            throw std::logic_error("Unknown minimun ring size for given security level");
        }
        
    }
    //Method for setup phases in ABE related schemes 
    template <class Element>
        void ABEContext<Element>::Setup(ABECoreMasterPublicKey<Element>* pk,ABECoreMasterSecretKey<Element>* sk){
        m_scheme->Setup(m_params,pk,sk);
    }
    //Method for individual/policy specific key generation for decryption
    template <class Element>
    void ABEContext<Element>::KeyGen(const ABECoreMasterSecretKey<Element> & msk,const ABECoreMasterPublicKey<Element>& mpk, const ABECoreAccessPolicy<Element> & ap,ABECoreSecretKey<Element>* sk){
        m_scheme->KeyGen(m_params,msk,mpk,ap,sk);
    }
    //Method for encryption
    template <class Element>
    void ABEContext<Element>::Encrypt(const ABECoreMasterPublicKey<Element> & mpk,const ABECoreAccessPolicy<Element> & ap,const Plaintext & ptext,ABECoreCiphertext<Element>* ct){
        m_scheme->Encrypt(m_params,mpk,ap,ptext->GetElement<Element>(),ct);
    }
    //Method for decryption with access to identifier/policy 
    template <class Element>
    Plaintext ABEContext<Element>::Decrypt(const ABECoreAccessPolicy<Element> & ap, const ABECoreAccessPolicy<Element> & ua,const ABECoreSecretKey<Element>& sk, const ABECoreCiphertext<Element>& ct){
        Plaintext dtext =PlaintextFactory::MakePlaintext( CoefPacked, this->m_params->GetTrapdoorParams()->GetElemParams(), this->m_params->GetEncodingParams());
        m_scheme->Decrypt(m_params,ap,ua,sk,ct,&(dtext->GetElement<Element>()));
        return dtext;
    }
    //Method for decryption - for the cases without access policy
    template <class Element>
    Plaintext ABEContext<Element>::Decrypt(const ABECoreSecretKey<Element>& sk, const ABECoreCiphertext<Element>& ct){
        Plaintext dtext =PlaintextFactory::MakePlaintext( CoefPacked, this->m_params->GetTrapdoorParams()->GetElemParams(), this->m_params->GetEncodingParams());
        m_scheme->Decrypt(m_params,sk,ct,&(dtext->GetElement<Element>()));
        return dtext;
    }
    //ethod for generating a random ring element with context parameters - demo purposes only 
    template <class Element>
    Element ABEContext<Element>::GenerateRandomElement(){
        Element r(m_params->GetDUG(),m_params->GetTrapdoorParams()->GetElemParams(), EVALUATION);
        return r;
    }
    //ethod for generating a random binary ring element with context parameters - demo purposes only 
    template <class Element>
    Element ABEContext<Element>::GenerateRandomBinaryElement(){
        typename Element::BugType bug = typename Element::BugType();
        Element r(m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT,true);
        r.SetValues(bug.GenerateVector(m_params->GetTrapdoorParams()->GetN(), m_params->GetTrapdoorParams()->GetElemParams()->GetModulus()), COEFFICIENT);
        return r;
    }
    //Method for parameter generation for CPABE 
    template <class Element>
    void ABEContext<Element>::ParamsGenCPABE(usint ringsize,usint ell,usint base,shared_ptr<ABECoreParams<Element>>& m_params){
        //smoothing parameter - also standard deviation for noise Elementnomials
	    double sigma = SIGMA;

	    //Correctness constraint
	    auto qCorrectness = [&](uint32_t n, uint32_t m) -> double { return  256 * sigma * SPECTRAL_BOUND(n,m-2,base) * sqrt( m * n * (ell + 1));  };

	    double qPrev = 1e6;
	    double q = 0;
	    usint k = 0;
	    usint m = 0;

	    //initial value
	    k = floor(log2(qPrev-1.0)+1.0);
	    m = ceil(k / log2(base)) + 2;
	    q = qCorrectness(ringsize, m);

	    //get a more accurate value of q
	    while (std::abs(q - qPrev) > 0.001*q) {
	        qPrev = q;
		    k = floor(log2(qPrev - 1.0) + 1.0);
		    m = ceil(k / log2(base)) + 2;
		    q = qCorrectness(ringsize, m);
		
        }
        usint sm = ringsize * 2;
        typename Element::DggType dgg(sigma);
        typename Element::DugType dug;
        typename Element::Integer smodulus;
        typename Element::Integer srootOfUnity;

        smodulus = FirstPrime<typename Element::Integer>(floor(log2(q - 1.0)) + 1.0, 2 * ringsize);
        srootOfUnity = RootOfUnity(sm, smodulus);
        dug.SetModulus(smodulus);
		ILParamsImpl<typename Element::Integer> ilParams = ILParamsImpl<typename Element::Integer>(sm, smodulus, srootOfUnity);

        ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);
        EncodingParams eparams(new EncodingParamsImpl(2));
        shared_ptr<ILParamsImpl<typename Element::Integer>> silparams = std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);
        RLWETrapdoorParams<Element> tparams(silparams,dgg,sigma,base);
        shared_ptr<ABECoreParams<Element>> abeparams(new CPABEParams<Element>(std::make_shared<RLWETrapdoorParams<Element>>(tparams),ell,dug,eparams));
        m_params = abeparams;
	
    }
    //Method for parameter generation for IBE
    template <class Element>
    void ABEContext<Element>::ParamsGenIBE(usint ringsize,usint base,shared_ptr<ABECoreParams<Element>>& m_params){
        //smoothing parameter - also standard deviation for noise Elementnomials
	    double sigma = SIGMA;

	    //Correctness constraint
	    auto qCorrectness = [&](uint32_t n, uint32_t m) -> double { return  256 * sigma * SPECTRAL_BOUND(n,m-2,base) * sqrt( m * n );  };

	    double qPrev = 1e6;
	    double q = 0;
	    usint k = 0;
	    usint m = 0;

	    //initial value
	    k = floor(log2(qPrev-1.0)+1.0);
	    m = ceil(k / log2(base)) + 2;
	    q = qCorrectness(ringsize, m);

	    //get a more accurate value of q
	    while (std::abs(q - qPrev) > 0.001*q) {
	        qPrev = q;
		    k = floor(log2(qPrev - 1.0) + 1.0);
		    m = ceil(k / log2(base)) + 2;
		    q = qCorrectness(ringsize, m);
		
        }
        usint sm = ringsize * 2;
        typename Element::DggType dgg(sigma);
        typename Element::DugType dug;
        typename Element::Integer smodulus;
        typename Element::Integer srootOfUnity;

        smodulus = FirstPrime<typename Element::Integer>(floor(log2(q - 1.0)) + 1.0, 2 * ringsize);
        srootOfUnity = RootOfUnity(sm, smodulus);
        dug.SetModulus(smodulus);
		ILParamsImpl<typename Element::Integer> ilParams = ILParamsImpl<typename Element::Integer>(sm, smodulus, srootOfUnity);

        ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);

        EncodingParams eparams(new EncodingParamsImpl(2));
        shared_ptr<ILParamsImpl<typename Element::Integer>> silparams = std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);
        RLWETrapdoorParams<Element> tparams(silparams,dgg,sigma,base);
        shared_ptr<ABECoreParams<Element>> ibeparams(new IBEParams<Element>(std::make_shared<RLWETrapdoorParams<Element>>(tparams),dug,eparams));
        m_params = ibeparams;
    }


}