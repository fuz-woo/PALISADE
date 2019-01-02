/*
* @file signaturecore.h - Virtual classes for core functionality of signatures.
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

#ifndef SIGNATURE_SIGNATURECORE_H
#define SIGNATURE_SIGNATURECORE_H
/**
 * @brief Virtual templated class for signature
 * @tparam Element ring element
 */
template<class Element>
class LPSignature{
    public:
        /**
         * @brief Destructor
         */
        virtual ~LPSignature(){}
        /**
         *@brief Default constructor 
         */
        LPSignature(){}
        /*
        *@brief Dummy method to force abstract base class
        */
        virtual void forceImplement()=0;
};
/**
 *@brief Virtual templated class for plaintext 
 *@tparam Element ring element 
 */
template<class Element>
class LPSignPlaintext{
    public:
        /**
         *@brief Destructor
         */
        virtual ~LPSignPlaintext(){}
        /**
         *@brief Default constructor
         */
        LPSignPlaintext(){}
        /*
        *@brief Dummy method to force abstract base class
        */
        virtual void forceImplement()=0;
};
/**
 * @brief Virtual templated class for parameters used in signing process
 * @tparam Element ring element
 */
template<class Element>
class LPSignatureParameters{
    public:
        /**
         *@brief Destructor
         */
        virtual ~LPSignatureParameters(){}
        /**
         *@brief Default constructor
         */
        LPSignatureParameters(){}
        /*
        *@brief Dummy method to force abstract base class
        */
        virtual void forceImplement()=0;
};
/**
 *@brief Virtual templated class for private key used in signing 
 *@tparam Element ring element
 */
template<class Element>
class LPSignKey{
    public:
        /**
         * @brief Destructor
         */
        virtual ~LPSignKey(){}
        /**
         * @brief Default constructor
         */
        LPSignKey(){}
        /*
        *@brief Dummy method to force abstract base class
        */
        virtual void forceImplement()=0;
};
/**l
 * @brief Virtual templated class for public key used in verification
 * @tparam Element ring element
 */
template<class Element>
class LPVerificationKey{
    public:
        /**
         *@brief Destructor 
         */
        virtual ~LPVerificationKey(){}
        /**
         *@brief Default constructor 
         */
        LPVerificationKey(){}
        /*
        *@brief Dummy method to force abstract base class
        */
        virtual void forceImplement()=0;
};
/**
 *@brief Virtual templated class for signature schemes
 *@tparam Element ring element 
 */
template<class Element>
class LPSignatureScheme{
 public:
    /**
     * @brief Destructor
     */
    virtual ~LPSignatureScheme(){}
    /**
     * @brief Default constructor
     */
    LPSignatureScheme(){}
    /**
     * @brief Method for key generation
     * @param m_params Parameters used for the scheme
     * @param sk Secret key used for signing - Output
     * @param vk Public key used for verification - Output
     */
    virtual void KeyGen(shared_ptr<LPSignatureParameters<Element>> m_params,LPSignKey<Element>* sk, LPVerificationKey<Element>* vk);
    /**
     * @brief Method for signing
     * @param m_params Parameters used for the scheme
     * @param sk Secret key used for signing
     * @param vk Public key used for verification
     * @param pt Plaintext to be signed
     * @param sign Signature generated - Output
     */
    virtual void Sign(shared_ptr<LPSignatureParameters<Element>> m_params,const LPSignKey<Element> & sk,const LPVerificationKey<Element> &vk, const LPSignPlaintext<Element> & pt, LPSignature<Element>* sign);
    /**
     * @brief Method for verification
     * @param m_params Parameters used for the scheme
     * @param vk Public key used for verification
     * @param sign Signature to be verified
     * @param pt Plaintext to be used for verification
     * @return verification result
     */
    virtual bool Verify(shared_ptr<LPSignatureParameters<Element>> m_params,const LPVerificationKey<Element> & vk,const LPSignature<Element> & sign, const LPSignPlaintext<Element> & pt);
    /*
        *@brief Dummy method to force abstract base class
        */
        virtual void forceImplement()=0;
};
#endif