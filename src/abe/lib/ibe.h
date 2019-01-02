/*
* @file ibe.h - Header file for IBE scheme related classes.
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

#ifndef ABE_IBE_H
#define ABE_IBE_H

#include "abecore.h"

namespace lbcrypto{
       /*
	*@brief Templated class for parameters used in IBE scheme, derived from the main ABE ones
	*@tparam Element ring element
	*/
    template <class Element>
    class IBEParams : public ABECoreParams<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~IBEParams(){}
             /*
            @brief Constructor for ABE core params
            @param tparams Parameters related to trapdoor
            @param dug Discrete Uniform Generator used to generate random numbers
            @param encParams Encoding params used
            @param ell Number of attributes
            */
            IBEParams(shared_ptr<RLWETrapdoorParams<Element>> tparams,typename Element::DugType& dug,const EncodingParams & encParams):ABECoreParams<Element>(tparams,dug,encParams,1){}
        protected:    
        /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
      /*
	*@brief Templated class for master public key that IBE scheme use, derived from the main ABE one
	*@tparam Element ring element
	*/
    template<class Element>
    class IBEMasterPublicKey:public ABECoreMasterPublicKey<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~IBEMasterPublicKey(){}
            /*
        	*@brief Default constructor
        	*/
            IBEMasterPublicKey(){}
            /*
            *@brief Constructor for master public key
            *@param A Matrix of element generated during trapdoor generation
            */
            IBEMasterPublicKey(shared_ptr<Matrix<Element>> A):ABECoreMasterPublicKey<Element>(A){}
        protected:
        /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};    
    };
    /*
	*@brief Templated class for master secret key  that IBE scheme uses, derived from main ABE one
	*@tparam Element ring element
	*/
    template<class Element>
    class IBEMasterSecretKey:public ABECoreMasterSecretKey<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~IBEMasterSecretKey(){}
            /*
        	*@brief Default constructor
        	*/
            IBEMasterSecretKey(){};
            /*
            *@brief Constructor for master secret key
            *@param TA the trapdoor pair
            */
            IBEMasterSecretKey(shared_ptr<RLWETrapdoorPair<Element>> TA): ABECoreMasterSecretKey<Element>(TA){}
        protected:
        /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
    /*
	*@brief Templated class for secret key used by user in IBE scheme, derived from the main one
	*@tparam Element ring element
	*/
    template <class Element>
    class IBESecretKey:public ABECoreSecretKey<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~IBESecretKey(){}
            /*
        	*@brief Default constructor
        	*/
            IBESecretKey(){}
            /*
            *@brief Constructor for the secret key
            *@param sk Matrix of ring elements that acts as the secret key
            */
            IBESecretKey(shared_ptr<Matrix<Element>> sk): ABECoreSecretKey<Element>(sk){}
            protected:
            /**
             *@brief Overloaded dummy method 
             */
                void forceImplement(){};
    };
    /*
	*@brief Templated class for user identifier used for accessibility controls in IBE scheme, derived from ABE one
	*@tparam Element ring element
	*/
    template <class Element>
    class IBEUserIdentifier:public ABECoreAccessPolicy<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~IBEUserIdentifier(){}
            /*
        	*@brief Default constructor
        	*/
            IBEUserIdentifier(){}
            /*
            *@brief Constructor for the identifier
            *@param id Actual user id
            */
            IBEUserIdentifier(const Element & id):m_id(id){}
            /*
            *@brief Accessor function for the user id
            *@return User id
            */
            const Element & GetID() const{return m_id;}
             /*
            *@brief Mutator function for the user id
            *@param id User id
            */
            void SetID(const Element & id){this->m_id = id;}
        protected:
            //User id represented in element form
            Element m_id;
            /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
     /*
	*@brief Templated class for ciphertext in IBE scheme, derived from main ABE one
	*@tparam Element ring element
	*/
    template <class Element>
    class IBECiphertext: public ABECoreCiphertext<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~IBECiphertext(){}
            /*
        	*@brief Default constructor
        	*/
            IBECiphertext(){}
            /*
            *@brief Constructor for ciphertext
            *@param C0 Helper matrix to decrypt the actual ciphertext
            *@param c1 Actual ciphertext in form of a ring element
            */
            IBECiphertext(shared_ptr<Matrix<Element>> C0, const Element & c1):ABECoreCiphertext<Element>(c1){
            	this->m_C0 = C0;
            }
            /*
            *@brief Accessor function for the helper for ciphertext
            *@return Helper for ciphertext
            */
            const Matrix<Element> & GetC0() const {return *m_C0;}
            /*
            *@brief Mutator function for the helper for ciphertext
            *@param C0 Helper for ciphertext
            */
            void SetC0(shared_ptr<Matrix<Element>> C0){this->m_C0 = C0;}
        protected:
            //Helper vector for decryption process
        	shared_ptr<Matrix<Element>> m_C0;
            /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
    /*
    *@brief Templated class for ciphertext in IBE scheme, derived from main ABE one. Assumes it has been evaluated under user identifier beforehand
	*@tparam Element ring element
    */
    template <class Element>
    class IBEEvalCiphertext: public IBECiphertext<Element>{
        /*
        	*@brief Default destructor
        	*/
            ~IBEEvalCiphertext(){}
            /*
        	*@brief Default constructor
        	*/
            IBEEvalCiphertext(){}
            /*
            *@brief Constructor for ciphertext
            *@param C0 Helper matrix to decrypt the actual ciphertext
            *@param c1 Evaluated ciphertext in form of a ring element
            */
            IBEEvalCiphertext(shared_ptr<Matrix<Element>> C0, const Element & c1):IBECiphertext<Element>(C0,c1){}
        protected:
        /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
     /*
	*@brief Templated class for IBE scheme, derived from general ABE scheme
	*@tparam Element ring element
	*/
    template<class Element>
    class IBEScheme:public ABECoreScheme<Element>{
    	public:
    		/*
    		*@brief Default destructor
    		*/
    		~IBEScheme(){}
    		/*
    		*@brief Default constructor
    		*/
    		IBEScheme(){}
    		/*
    		*@brief Method for setup phase of an IBE cycle
            *@param m_params Parameters used in operations
    		*@param mpk Master public key - Output
    		*@param msk Master secret key - Output
    		*/
    		void Setup(shared_ptr<ABECoreParams<Element>> m_params,ABECoreMasterPublicKey<Element> * mpk, ABECoreMasterSecretKey<Element> * msk);
    			/*
    		*@brief Method for key generation phase of an IBE cycle
            *@param m_params Parameters used in operations
    		*@param mpk Master public key
    		*@param msk Master secret key
    		*@param id User identifier defining who will be able to decrypt
    		*@param sk Secret key for decryption - Output
    		*/
    		void KeyGen(shared_ptr<ABECoreParams<Element>> m_params,
                        const ABECoreMasterSecretKey<Element> & msk,
                        const ABECoreMasterPublicKey<Element> & mpk, 
                        const ABECoreAccessPolicy<Element> & id,
                        ABECoreSecretKey<Element>* sk);
            /*
            *@brief Method for offline sampling for key generation phase of an IBE cycle
            *@param m_params Parameters used in operations
            *@param msk Master secret key
            *@return Perturbation vector sampled
            */
            PerturbationVector<Element> KeyGenOffline(
				        shared_ptr<IBEParams<Element>> m_params,
				        const IBEMasterSecretKey<Element> & msk);
            /*
            *@brief Method for online phase for key generation phase of an IBE cycle without sampling
            *@param m_params Parameters used in operations
            *@param msk Master secret key
            *@param mpk Master public key
            *@param id User identifier defining who will be able to decrypt 
            *@param pvector Perturbation vector sampled before hand
            *@param sk Secret key for decryption - Output
            */
            void KeyGenOnline(
				shared_ptr<IBEParams<Element>> m_params,
                const IBEMasterSecretKey<Element> & msk,
                const IBEMasterPublicKey<Element> & mpk, 
                const IBEUserIdentifier<Element> & id,
                const PerturbationVector<Element> & pvector,
                IBESecretKey<Element>* sk);
    		/*
    		*@brief Method for encryption phase of an IBE cycle
            *@param m_params Parameters used in operations
    		*@param mpk Master public key
    		*@param ap User identifier defining who will be able to decrypt
    		*@param ptext Plaintext to be encrypted
    		*@param ctext Ciphertext corresponding to the plaintext - Output
    		*/
    		void Encrypt(shared_ptr<ABECoreParams<Element>> m_params,
                         const ABECoreMasterPublicKey<Element> & mpk, 
                         const ABECoreAccessPolicy<Element> & ap, 
                         Element ptext,
                         ABECoreCiphertext<Element> * ctext);
    		/*
    		*@brief Method for decryption phase of an IBE cycle
            *@param m_params Parameters used in operations
            *@param ap User's id (acting as the access structure)
            *@param ua User's id (acting as user's access rights)
    		*@param sk Secret key to be used for decryption
    		*@param ctext Ciphertext to be decrypted
            *@param ptext Decrypted plaintext - Output
    		*/
    		void Decrypt(shared_ptr<ABECoreParams<Element>> m_params,
                         const ABECoreAccessPolicy<Element> & ap,
                         const ABECoreAccessPolicy<Element> & ua,
                         const ABECoreSecretKey<Element> & sk,  
                         const ABECoreCiphertext<Element> & ctext, 
                         Element* ptext);
            /*
    		*@brief Method for decryption phase of an IBE cycle, assumes that ciphertext was evaluated under the identifier beforehand
            *@param m_params Parameters used in operations
    		*@param sk Secret key to be used for decryption
    		*@param ctext Evaluated Ciphertext to be decrypted
            *@param ptext Decrypted plaintext - Output
    		*/
    		void Decrypt(shared_ptr<ABECoreParams<Element>> m_params,
                         const ABECoreSecretKey<Element> & sk,  
                         const ABECoreCiphertext<Element> & ectext, 
                         Element* ptext);
    	protected:
        /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
}

#endif