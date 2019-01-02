/*
* @file cpabe.h - Header file for CPABE scheme related classes.
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
#ifndef ABE_CPABE_H
#define ABE_CPABE_H

#include "abecore.h"

namespace lbcrypto{
     /*
	*@brief Templated class for parameters used in CPABE scheme, derived from the main ABE ones
	*@tparam Element ring element
	*/
    template <class Element>
    class CPABEParams: public ABECoreParams<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~CPABEParams(){}
             /*
            @brief Constructor for ABE core params
            @param tparams Parameters related to trapdoor
            @param dug Discrete Uniform Generator used to generate random numbers
            @param encParams Encoding params used
            @param ell Number of attributes
            */
            CPABEParams(shared_ptr<RLWETrapdoorParams<Element>> params,int32_t ell,typename Element::DugType& dug,const EncodingParams & encparams):ABECoreParams<Element>(params,dug,encparams,ell){}     
            /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
     /*
	*@brief Templated class for master public key that CPABE scheme use, derived from the main ABE one
	*@tparam Element ring element
	*/
    template<class Element>
    class CPABEMasterPublicKey:public ABECoreMasterPublicKey<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~CPABEMasterPublicKey(){};
            /*
            *@brief Default constructor
            */
            CPABEMasterPublicKey(){};
            /*
            *@brief Constructor for master public key
            *@param A Matrix of element generated during trapdoor generation
            *@param Bpos Matrix of positive attributes
            *@param Bneg Matrix of negative attributes
            *@param pubElemD the public element
            */
            CPABEMasterPublicKey(shared_ptr<Matrix<Element>> A, shared_ptr<Matrix<Element>> Bpos, shared_ptr<Matrix<Element>> Bneg, const Element & pubElemD):ABECoreMasterPublicKey<Element>(A){
                this->m_Bpos = Bpos;
                this->m_Bneg = Bneg;
                this->m_pubElemD = pubElemD;
            }
            /*
            *@brief Accessor function for Bpos
            *@return Bpos
            */
            const Matrix<Element> & GetBPos() const{return *m_Bpos;}
             /*
            *@brief Mutator function for Bpos
            *@param Bpos
            */
            void SetBPos(shared_ptr<Matrix<Element>> Bpos){this->m_Bpos = Bpos;}
            /*
            *@brief Accessor function for BNeg
            *@return Bneg
            */
            const Matrix<Element> & GetBNeg() const {return *m_Bneg;}
             /*
            *@brief Mutator function for Bneg
            *@param Bneg
            */
            void SetBNeg(shared_ptr<Matrix<Element>> Bneg){this->m_Bneg = Bneg;}
            /*
            *@brief Accessor function for public element
            *@return public element
            */
            const Element & GetPubElemD() const {return m_pubElemD;}
            /*
            *@brief Mutator function for public element
            *@param pubElemD public element
            */
            void SetPubElemD(const Element & pubElemD){this-> m_pubElemD = pubElemD;}

        protected:
            //Uniformly distributed vectors
            shared_ptr<Matrix<Element>> m_Bpos, m_Bneg;
            //Public Element D
            Element m_pubElemD; 
            /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
     /*
	*@brief Templated class for master secret key  that CPABE scheme use, derived from main ABE one
	*@tparam Element ring element
	*/
    template<class Element>
    class CPABEMasterSecretKey:public ABECoreMasterSecretKey<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~CPABEMasterSecretKey(){}
            /*
        	*@brief Default constructor
        	*/
            CPABEMasterSecretKey(){};
              /*
            *@brief Constructor for master secret key
            *@param TA the trapdoor pair
            */
            CPABEMasterSecretKey(shared_ptr<RLWETrapdoorPair<Element>> TA): ABECoreMasterSecretKey<Element>(TA){}
            /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
    /*
	*@brief Templated class for secret key used by user in CPABE scheme, derived from the main one
	*@tparam Element ring element
	*/
    template <class Element>
    class CPABESecretKey:public ABECoreSecretKey<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~CPABESecretKey(){}
             /*
        	*@brief Default constructor
        	*/
            CPABESecretKey(){}
             /*
            *@brief Constructor for the secret key
            *@param sk Matrix of ring elements that acts as the secret key
            */
            CPABESecretKey(shared_ptr<Matrix<Element>> sk): ABECoreSecretKey<Element>(sk){}
            /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};

    };
    /*
    *@brief Templated class for attribute set used for accessibility controls in CPABE scheme, derived from ABE one
	*@tparam Element ring element
	*/
    template <class Element>
    class CPABEAccessPolicy: public ABECoreAccessPolicy<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~CPABEAccessPolicy(){}
            /*
        	*@brief Default constructor
        	*/
            CPABEAccessPolicy(){}
             /*
            *@brief Constructor for access policy
            *@param w Attribute set for the access policy
            */
            CPABEAccessPolicy(const std::vector<int32_t> & w):m_w(w){}
             /*
            *@brief Accessor function for the attribute set for the access policy
            *@return Attribute set for the access policy
            */
            const std::vector<int32_t>& GetW() const{return m_w;};
            /*
            *@brief Mutator function for the attribute set for the access policy
            *@return w Attribute set for the access policy
            */
            void SetW(const std::vector<int32_t> & w){this->m_w = w;}
        protected:
            //Array of integers to represent access scheme defined on attributes
            std::vector<int32_t> m_w;
            /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
    /*
    *@brief Templated class for attribute set usedby user in CPABE scheme, derived from ABE one
	*@tparam Element ring element
	*/
     template <class Element>
    class CPABEUserAccess: public ABECoreAccessPolicy<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~CPABEUserAccess(){}
            /*
        	*@brief Default constructor
        	*/
            CPABEUserAccess(){}
             /*
            *@brief Constructor for user access capabilities
            *@param s Attribute set for user access capabilities
            */
            CPABEUserAccess(const std::vector<usint> & s):m_s(s){}
            /*
            *@brief Accessor function for the attribute set of user
            *@return Attribute set of user
            */
            const std::vector<usint> & GetS() const{return m_s;};
            /*
            *@brief Mutator function for the attribute set of user
            *@return s Attribute set of user
            */
            void SetS(const std::vector<usint> & s){this->m_s = s;}
        protected:
            //Array of integers to represent user's attribute set
            std::vector<usint> m_s;
            /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
     /*
	*@brief Templated class for ciphertext in CPABE scheme, derived from main ABE one
	*@tparam Element ring element
	*/
    template <class Element>
    class CPABECiphertext: public ABECoreCiphertext<Element>{
        public:
        	/*
        	*@brief Default destructor
        	*/
            ~CPABECiphertext(){}
             /*
        	*@brief Default constructor
        	*/
            CPABECiphertext(){}
            /*
            *@brief Constructor for ciphertext
            *@param CW Helper matrix to decrypt the actual ciphertext
            *@param cPos Helper matrix to decrypt the actual ciphertext
            *@param cNeg Helper matrix to decrypt the actual ciphertext
            *@param c1 Actual ciphertext in form of a ring element
            */
            CPABECiphertext(shared_ptr<Matrix<Element>> CW,shared_ptr<Matrix<Element>>cPos,shared_ptr<Matrix<Element>> cNeg, const Element & c1):ABECoreCiphertext<Element>(c1){
                this->m_CW = CW;
                this->m_cPos = cPos;
                this->m_cNeg = cNeg;
            }
            /*
            *@brief Accessor function for the helper cPos for ciphertext
            *@return Helper cPos for ciphertext
            */
            const Matrix<Element> & GetCPos() const {return *m_cPos;}
            /*
            *@brief Mutator function for the helper cPos for ciphertext
            *@param cPos Helper for ciphertext
            */
            void SetCPos(shared_ptr<Matrix<Element>> cPos){this->m_cPos = cPos;}
            /*
            *@brief Accessor function for the helper cNeg for ciphertext
            *@return Helper cNeg for ciphertext
            */
            const Matrix<Element> & GetCNeg() const{return *m_cNeg;}
            /*
            *@brief Mutator function for the helper cNeg for ciphertext
            *@param cNeg Helper for ciphertext
            */
            void SetCNeg(shared_ptr<Matrix<Element>> cNeg){this->m_cNeg = cNeg;}
            /*
            *@brief Accessor function for the helper CW for ciphertext
            *@return Helper CW for ciphertext
            */
            const Matrix<Element> & GetCW() const {return *m_CW;}
            /*
            *@brief Mutator function for the helper CW for ciphertext
            *@param CW Helper for ciphertext
            */
            void SetCW(shared_ptr<Matrix<Element>> CW){this->m_CW = CW;}

        protected:
                //Vectors used to help decryption process
                shared_ptr<Matrix<Element>> m_cPos, m_cNeg,m_CW ;
                /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };
     /*
	*@brief Templated class for CPABE scheme, derived from general ABE scheme
	*@tparam Element ring element
	*/
    template<class Element>
    class CPABEScheme:public ABECoreScheme<Element>{
    	public:
    		/*
    		*@brief Default destructor
    		*/
    		~CPABEScheme(){}
    		/*
    		*@brief Default constructor
    		*/
    		CPABEScheme(){}
    		/*
    		*@brief Method for setup phase of a CPABE cycle
            *@param m_params Parameters associated with operations
    		*@param mpk Master public key - Output
    		*@param msk Master secret key - Output
    		*/
    		void Setup(shared_ptr<ABECoreParams<Element>> m_params,ABECoreMasterPublicKey<Element>* mpk, ABECoreMasterSecretKey<Element>* msk);
    			/*
    		*@brief Method for key generation phase of a CPABE cycle
            *@param m_params Parameters associated with operations
    		*@param mpk Master public key
    		*@param msk Master secret key
    		*@param id Access policy defining who will be able to decrypt
    		*@param usk Secret key for decryption - Output
    		*/
    		void KeyGen(shared_ptr<ABECoreParams<Element>> m_params,
                        const ABECoreMasterSecretKey<Element> & msk,
                        const ABECoreMasterPublicKey<Element> & mpk, 
                        const ABECoreAccessPolicy<Element> & id,
                        ABECoreSecretKey<Element>* usk);
            /*
            *@brief Method for offline sampling for key generation phase of an CPABE cycle
            *@param m_params Parameters associated with operations
            *@param msk Master secret key
            *@return Perturbation vector sampled
            */ 
            PerturbationVector<Element> KeyGenOffline(shared_ptr<CPABEParams<Element>> m_params,
			                                          const CPABEMasterSecretKey<Element> & msk);
            /*
            *@brief Method for online phase for key generation phase of an CPABE cycle without sampling
            *@param m_params Parameters used in operations
            *@param msk Master secret key
            *@param mpk Master public key
            *@param id User access rights defining who will be able to decrypt 
            *@param pvector Perturbation vector sampled before hand
            *@param usk Secret key for decryption - Output
            */ 
            void KeyGenOnline(shared_ptr<CPABEParams<Element>> m_params,
                              const CPABEMasterSecretKey<Element> & msk,
                              const CPABEMasterPublicKey<Element> & mpk, 
                              const CPABEUserAccess<Element> & id,
                              const PerturbationVector<Element> & pvector,
                              CPABESecretKey<Element>* usk);
            
    		/*
    		*@brief Method for encryption phase of a CPABE cycle
            *@param m_params Parameters associated with operations
    		*@param mpk Master public key
    		*@param ap Access policy defining who will be able to decrypt
    		*@param ptext Plaintext to be encrypted
    		*@param ctext Ciphertext corresponding to the plaintext - Output
    		*/
    		void Encrypt(shared_ptr<ABECoreParams<Element>> m_params,
                         const ABECoreMasterPublicKey<Element> & mpk,
                         const ABECoreAccessPolicy<Element> & ap,
                         Element ptext,
                         ABECoreCiphertext<Element> * ctext);
    		/*
    		*@brief Method for decryption phase of a CPABE cycle
            *@param m_params Parameters associated with operations
    		*@param ap Access policy defining who will be able to decrypt
    		*@param ua User access showing attribute set of the user
    		*@param usk Secret key to be used for decryption
    		*@param ptext Decrypted plaintext - Output
    		*@param ctext Ciphertext to be decrypted
    		*/
    		void Decrypt(shared_ptr<ABECoreParams<Element>> m_params,
                         const ABECoreAccessPolicy<Element> & ap, 
                         const ABECoreAccessPolicy<Element>& ua,
                         const ABECoreSecretKey<Element> & usk,
                         const ABECoreCiphertext<Element> & ctext, 
                         Element* ptext);
    	protected:
        /**
             *@brief Overloaded dummy method 
             */
            void forceImplement(){};
    };

}

#endif
