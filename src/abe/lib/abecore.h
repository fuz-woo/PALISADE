/*
* @file abecore.h - Virtual classes for core functionality of ABE related schemes.
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

#ifndef ABE_ABECORE_H
#define ABE_ABECORE_H

#include <cmath>
#include <vector>
#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "math/backend.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/trapdoorparameters.h"

namespace lbcrypto{
      /*
	*@brief Virtual templated class for parameters used in ABE schemes
	*@tparam Element ring element
	*/
    template<class Element>
    class ABECoreParams{
        public:
        	/*
        	*@brief Default destructor
        	*/
            virtual ~ABECoreParams(){};
            /*
            @brief Constructor for ABE core params
            @param tparams Parameters related to trapdoor
            @param dug Discrete Uniform Generator used to generate random numbers
            @param eparams Encoding params used
            @param ell Number of attributes
            */
            ABECoreParams(shared_ptr<RLWETrapdoorParams<Element>> tparams,typename Element::DugType& dug,const EncodingParams & eparams, int32_t ell=1):m_tparams(tparams),m_ell(ell),m_dug(dug),m_encParams(eparams){}
            /*
            @brief Accessor function for trapdoor parameters
            @return Parameters related to trapdoor
            */
            shared_ptr<RLWETrapdoorParams<Element>> GetTrapdoorParams(){return m_tparams;};
              /*
            @brief Mutator function for trapdoor parameters
            @param tparams Parameters related to trapdoor
            */
            void SetTrapdoorParams(shared_ptr<RLWETrapdoorParams<Element>> tparams){this->m_tparams = tparams;}
             /*
            @brief Accessor function for number of attributes
            @return Number of attributes
            */
            int32_t GetEll()const {return m_ell;}
            /*
            @brief Mutator function for number of attributes
            @param ell Number of attributes
            */
            void SetEll(int32_t ell){this->m_ell = ell;}
            /*
            @brief Accessor function for Discrete Uniform Generator
            @return Discrete Uniform Generator used
            */
            typename Element::DugType& GetDUG(){return m_dug;}
            /*
            *@brief Accessor function for Encoding Params
            *@return Encoding params used 
            */
            const EncodingParams GetEncodingParams() const {return m_encParams;}

        protected:
            //Trapdoor parameters
            shared_ptr<RLWETrapdoorParams<Element>> m_tparams;
            //Number of attributes
            int32_t m_ell;
            //Discrete uniform generator
            typename Element::DugType m_dug;
            //Encoding parameters
            EncodingParams m_encParams;
            /**
             *@brief Dummy method to achieve abstract base class
             */
            virtual void forceImplement()=0;
    };

     /*
	*@brief Virtual templated class for master public key  that ABE schemes use
	*@tparam Element ring element
	*/
    template<class Element>
    class ABECoreMasterPublicKey{
        public:
        	/*
        	*@brief Default destructor
        	*/
            virtual ~ABECoreMasterPublicKey(){};
            /*
            *@brief Default constructor
            */
            ABECoreMasterPublicKey(){};
            /*
            *@brief Constructor for master public key
            *@param A Matrix of element generated during trapdoor generation
            */
            ABECoreMasterPublicKey(shared_ptr<Matrix<Element>> A){this->m_A=A;}
            /*
            *@brief Accessor function for the matrix
            *@return The matrix containing ring elements
            */
            const Matrix<Element> &  GetA() const{return *m_A;}
             /*
            *@brief Mutator function for the matrix
            *@param A The matrix containing ring elements
            */
            void SetA(shared_ptr<Matrix<Element>> A){this->m_A = A;}

        protected:
            //Public key from trapdoor
            shared_ptr<Matrix<Element>> m_A;
               /**
             *@brief Dummy method to achieve abstract base class
             */
            virtual void forceImplement()=0;
    };
    /*
	*@brief Virtual templated class for master secret key  that ABE schemes use
	*@tparam Element ring element
	*/
    template<class Element>
    class ABECoreMasterSecretKey{
    public:
    	/*
    	*@brief Default destructor
    	*/
        virtual ~ABECoreMasterSecretKey(){};
        /*
        *@brief Default constructor
        */
        ABECoreMasterSecretKey(){}
        /*
        *@brief Constructor for the master secret key
        *@param TA trapdoor pair which is used for master secret key
        */
        ABECoreMasterSecretKey(shared_ptr<RLWETrapdoorPair<Element>> TA){this->m_TA=TA;}
        /*
        *@brief Accessor function for the trapdoor pair
        *@return the trapdoor pair
        */
         const RLWETrapdoorPair<Element> &  GetTA() const{return *m_TA;}
        /*
        *@brief Mutator function for the trapdoor pair
        *@param TA the trapdoor pair
        */
        void SetTA(shared_ptr<RLWETrapdoorPair<Element>> TA){this->m_TA = TA;}
    protected:
        //Private key from trapdoor
        shared_ptr<RLWETrapdoorPair<Element>> m_TA;
           /**
             *@brief Dummy method to achieve abstract base class
             */
        virtual void forceImplement()=0;
    };
    /*
	*@brief Virtual templated class for secret key used by user in ABE schemes
	*@tparam Element ring element
	*/
    template<class Element>
    class ABECoreSecretKey{
        public:
        	/*
        	*@brief Default destructor
        	*/
            virtual ~ABECoreSecretKey(){};
            /*
            *@brief Default constructor
            */
            ABECoreSecretKey() {};
            /*
            *@brief Constructor for the secret key
            *@param sk Matrix of ring elements that acts as the secret key
            */
            ABECoreSecretKey(shared_ptr<Matrix<Element>> sk){this->m_sk = sk;}
            /*
            *@brief Accessor function for the secret key
            *@return Matrix containing the secret key
            */
            const Matrix<Element> & GetSK() const {return *m_sk;}
            /*
            *@brief Mutator function for the secret key
            *@return sk Matrix containing the secret key
            */
            void SetSK(shared_ptr<Matrix<Element>> sk){this->m_sk = sk;}
        protected:
            //Matrix of ring elements acting as secret key
            shared_ptr<Matrix<Element>> m_sk;
               /**
             *@brief Dummy method to achieve abstract base class
             */
            virtual void forceImplement()=0;
    };
      /*
	*@brief Virtual templated class for defining accessibility of ciphertext in ABE schemes
	*@tparam Element ring element
	*/
    template <class Element>
    class ABECoreAccessPolicy{
        public:
        	/*
        	*@brief Default destructor
        	*/
            virtual ~ABECoreAccessPolicy(){};
            /*
        	*@brief Default constructor
        	*/
            ABECoreAccessPolicy(){}
        protected:
           /**
             *@brief Dummy method to achieve abstract base class
             */
            virtual void forceImplement()=0;
    };
     /*
	*@brief Virtual templated class for ciphertext in ABE schemes
	*@tparam Element ring element
	*/
    template <class Element>
    class ABECoreCiphertext{
        public:
        	/*
        	*@brief Default destructor
        	*/
            virtual ~ABECoreCiphertext(){};
            /*
        	*@brief Default constructor
        	*/
            ABECoreCiphertext(){}
             /*
            *@brief Constructor for ciphertext
            *@param c1 Actual ciphertext in form of a ring element
            */
            ABECoreCiphertext(const Element & c1):m_c1(c1){}
            /*
            *@brief Accessor function for the ciphertext
            *@return Ciphertext
            */
            const Element & GetC1() const {return m_c1;}
            /*
            *@brief Mutator function for the ciphertext
            *@param c1 Ciphertext
            */
            void SetC1(const Element & c1){this->m_c1 = c1;}
        protected:
            Element m_c1;
               /**
             *@brief Dummy method to achieve abstract base class
             */
            virtual void forceImplement()=0;
    };
     /*
	*@brief Virtual templated class for ABE schemes in general
	*@tparam Element ring element
	*/
    template<class Element>
    class ABECoreScheme{
    	public:
    		/*
    		*@brief Default destructor
    		*/
    		virtual ~ABECoreScheme(){};
    		/*
    		*@brief Default constructor
    		*/
    		ABECoreScheme(){}
    		/*
    		*@brief Method for setup phase of an ABE cycle
    		*@param mpk Master public key - Output
    		*@param msk Master secret key - Output
    		*/
    		virtual void Setup(shared_ptr<ABECoreParams<Element>> m_params,ABECoreMasterPublicKey<Element>* mpk,ABECoreMasterSecretKey<Element>* msk){}
    		/*
    		*@brief Method for key generation phase of an ABE cycle
    		*@param mpk Master public key
    		*@param msk Master secret key
    		*@param ap Access policy defining who will be able to decrypt
    		*@param sk Secret key for decryption - Output
    		*/
    		virtual void KeyGen(shared_ptr<ABECoreParams<Element>> m_params,
                                const ABECoreMasterSecretKey<Element> & msk,
                                const ABECoreMasterPublicKey<Element> & mpk,
                                const ABECoreAccessPolicy<Element> & ap,
                                ABECoreSecretKey<Element>* sk){};
            /*
    		*@brief Method for key generation phase of an ABE cycle, tailored to the case where target audience is not known beforehand
    		*@param mpk Master public key
    		*@param msk Master secret key
    		*@param sk Secret key for decryption - Output
    		*/
    		virtual void KeyGen(shared_ptr<ABECoreParams<Element>> m_params,
                                const ABECoreMasterSecretKey<Element> & msk,
                                const ABECoreMasterPublicKey<Element> & mpk,
                                ABECoreSecretKey<Element>* sk){};
    		/*
    		*@brief Method for encryption phase of an ABE cycle
    		*@param mpk Master public key
    		*@param ap Access policy defining who will be able to decrypt
    		*@param ptext Plaintext to be encrypted
    		*@param ctext Ciphertext corresponding to the plaintext - Output
    		*/
    		virtual void Encrypt(shared_ptr<ABECoreParams<Element>> m_params,
                                 const ABECoreMasterPublicKey<Element> & mpk,
                                 const ABECoreAccessPolicy<Element> & ap,
                                 Element ptext,
                                 ABECoreCiphertext<Element>* ctext){};
            /*
    		*@brief Method for encryption phase of an ABE cycle, tailored to the case where target audience is not known beforehand
    		*@param mpk Master public key, must be somehow evaluated according to access scheme beforehand
    		*@param ptext Plaintext to be encrypted
    		*@param ctext Ciphertext corresponding to the plaintext - Output
    		*/
    		virtual void Encrypt(shared_ptr<ABECoreParams<Element>> m_params,
                                 const ABECoreMasterPublicKey<Element> & mpk,
                                 Element ptext,
                                 ABECoreCiphertext<Element>* ctext){};
    		/*
    		*@brief Method for decryption phase of an ABE cycle
            *@param ap Access structure defined on scheme
            *@param ua User access rights
    		*@param sk Secret key to be used for decryption
    		*@param ctext Ciphertext to be decrypted
            *@param ptext Decrypted plaintext - Output
    		*/
    		virtual void Decrypt(shared_ptr<ABECoreParams<Element>> m_params,
                                 const ABECoreAccessPolicy<Element> & ap, 
                                 const ABECoreAccessPolicy<Element> & ua,
                                 const ABECoreSecretKey<Element> & sk, 
                                 const ABECoreCiphertext<Element> & ctext, 
                                 Element* ptext){};
            /*
    		*@brief Method for decryption phase of an ABE cycle, tailored to the case where target audience is not known beforehand
    		*@param sk Secret key to be used for decryption
    		*@param ctext Ciphertext to be decrypted, must be evaluated according to access scheme beforehand
            *@param ptext Decrypted plaintext - Output
    		*/
    		virtual void Decrypt(shared_ptr<ABECoreParams<Element>> m_params,
                                 const ABECoreSecretKey<Element> & sk, 
                                 const ABECoreCiphertext<Element> & ctext, 
                                 Element* ptext){};
            protected:
               /**
             *@brief Dummy method to achieve abstract base class
             */
                virtual void forceImplement()=0;
    };
}

#endif
