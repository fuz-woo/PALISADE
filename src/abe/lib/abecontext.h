/**
 * @file abecontext.h - Header file for ABEContext class, which is used for ciphertext-policy attribute-based encryption and identity based encryption

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
 #ifndef ABE_ABECONTEXT_H
 #define ABE_ABECONTEXT_H

#include "cpabe.h"
#include "ibe.h"
#include "abeparamset.h"

 namespace lbcrypto{
     /**
      *@brief Context class for ABE schemes, including IBE and CPABE 
      *@tparam Element ring element
      */
    template <class Element>
    class ABEContext{
        public:
            /*
            *@brief Default destructor
            */
            ~ABEContext(){DiscreteFourierTransform::Reset();} 
            /*
            *@brief Default constructor
            */
            ABEContext(){}
            /**
             *@brief Method for setting up a CPABE context with specific parameters
             *@param ell Number of attributes
             *@param ringsize Desired ringsize
             *@param base Base of the gadget matrix
             */
            void GenerateCPABEContext(usint ell,usint ringsize,usint base);
            /**
             *@brief Method for setting up a IBE context with specific parameters
             *@param ell Number of attributes
             *@param ringsize Desired ringsize
             *@param base Base of the gadget matrix
             */
            void GenerateIBEContext(usint ringsize,usint base=2);
             /**
             *@brief Method for setting up a IBE context with desired security level only 
             *@param level Desired security level
             */
            void GenerateIBEContext(SecurityLevel level);
             /**
             *@brief Method for setting up a CPABE context with desired security level and number of attributes only 
             *@param level Desired security level
             *@param ell Number of attributes
             */
            void GenerateCPABEContext(SecurityLevel level,usint ell);
            /**
             *@brief Method for setup phases in ABE related schemes 
             *@param pk Master public key - Output 
             *@param sk Master secret key - Output 
             */
            void Setup(ABECoreMasterPublicKey<Element>* pk,ABECoreMasterSecretKey<Element>* sk);
            /**
             *@brief Method for individual/policy specific key generation for decryption 
             *@param msk Master secret key 
             *@param mpk Master public key 
             *@param ap Access policy/user identifier
             *@param sk Secret key defined for the given policy/identifier - Output 
             */
            void KeyGen(const ABECoreMasterSecretKey<Element> & msk,const ABECoreMasterPublicKey<Element>& mpk, const ABECoreAccessPolicy<Element> & ap,ABECoreSecretKey<Element>* sk);
            /**
             *@brief Method for encryption
             *@param mpk Master public key
             *@param ap Access structure
             *@param ptext Plaintext to be encrypted
             *@param ct Corresponding ciphertext - Output 
             */ 
            void Encrypt(const ABECoreMasterPublicKey<Element> & mpk,const ABECoreAccessPolicy<Element> & ap,const Plaintext & ptext,ABECoreCiphertext<Element>* ct);
            /**
             *@brief Method for decryption with access to identifier/policy 
             *@param ap Access structure 
             *@param ua User's access rights 
             *@param sk User's secret key 
             *@param ct Ciphertext to be decrypted
             *@return Decrypted plaintext
             */
            Plaintext Decrypt(const ABECoreAccessPolicy<Element> & ap, const ABECoreAccessPolicy<Element>& ua,const ABECoreSecretKey<Element>& sk, const ABECoreCiphertext<Element>& ct);
            /**
             *@brief Method for decryption - for the cases without access policy 
             *@param sk Secret key for the user 
             *@param ct Ciphertext to be decrypted 
             *@return Decrypted plaintext 
             */
            Plaintext Decrypt(const ABECoreSecretKey<Element>& sk, const ABECoreCiphertext<Element>& ct);
            /**
             *@brief Method for generating a random ring element with context parameters - demo purposes only 
             *@return Random ring element 
             */
            Element GenerateRandomElement();
            /**
             * @brief Method for generating a random binary ring element with context parameters - demo purposes only 
             * @return Random binary ring element
             */
            Element GenerateRandomBinaryElement();
             /**
	         * MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context
	        * @param value
	        * @return plaintext
	        */
	        Plaintext MakeCoefPackedPlaintext(const vector<int64_t>& value) const {
		        auto p = PlaintextFactory::MakePlaintext( CoefPacked, this->m_params->GetTrapdoorParams()->GetElemParams(), this->m_params->GetEncodingParams(), value );
		        return p;
	        }
        private:
            //Pointer to the scheme used
            shared_ptr<ABECoreScheme<Element>> m_scheme;
            //Pointer to the parameters used for the scheme
            shared_ptr<ABECoreParams<Element>> m_params;
            /**
            *@brief Method for parameter genaration for CPABE 
            *@param ringsize Ring dimension of elements
            *@param ell Number of attributes
            *@param base Base of the gadget matrix
            *@param m_params Modified params
            */
            void ParamsGenCPABE(usint ringsize,usint ell,usint base,shared_ptr<ABECoreParams<Element>>& m_params);
            /**
            *@brief Method for parameter genaration for IBE
            *@param ringsize Ring dimension of elements 
            *@param ell Number of attributes 
            *@param base Base of the gadget matrix 
            *@param m_params Modified params
            */ 
            void ParamsGenIBE(usint ringsize,usint base,shared_ptr<ABECoreParams<Element>>& m_params);

	       
    };
 }

#endif