/**
 * @file signaturecontext.h - Header file for SignatureContext class, which is used for digital signature schemes
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
#ifndef SIGNATURE_SIGNATURECONTEXT_H
#define SIGNATURE_SIGNATURECONTEXT_H

#include "gpv.h"


namespace lbcrypto{
   /**
    *@brief Context class for signature schemes, including GPV
    *@tparam Element ring element 
    */
    template <class Element>
    class SignatureContext{
        public:
            /*
            *@brief Default constructor
            */
            SignatureContext(){}
            /**
             *@brief Method for setting up a GPV context with specific parameters
             *@param ringsize Desired ringsize
             *@param bitwidth Desired modulus bitwidth
             *@param base Base of the gadget matrix
             */
            void GenerateGPVContext(usint ringsize,usint bitwidth,usint base);
            /**
             *@brief Method for setting up a GPV context with desired ring size only 
             *@param ringsize Desired ring size
             */
            void GenerateGPVContext(usint ringsize);
            /**
             *@brief Method for key generation
             *@param sk Signing key for sign operation - Output 
             *@param vk Verification key for verify operation - Output 
             */
            void KeyGen(LPSignKey<Element>* sk, LPVerificationKey<Element>* vk);
            /**
             *@brief Method for signing a given plaintext 
             *@param pt Plaintext to be signed 
             *@param sk Sign key 
             *@param vk Verification key
             *@param sign Signature corresponding to the plaintext - Output 
             */
            void Sign(const LPSignPlaintext<Element> & pt,const LPSignKey<Element> & sk, const LPVerificationKey<Element> & vk,LPSignature<Element>* sign);
            /**
             *@brief Method for verifying the plaintext and signature
             *@param pt Plaintext 
             *@param signature Signature to be verified
             *@param vk Key used for verification
             *@return Verification result 
             */
            bool Verify(const LPSignPlaintext<Element> & pt, const LPSignature<Element> & signature, const LPVerificationKey<Element> & vk);

        private:
            //The signature scheme used
            shared_ptr<LPSignatureScheme<Element>> m_scheme;
            //Parameters related to the scheme
            shared_ptr<LPSignatureParameters<Element>> m_params;
    };
     
}

#endif