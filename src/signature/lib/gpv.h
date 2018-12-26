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

#ifndef SIGNATURE_LWESIGN_H
#define SIGNATURE_LWESIGN_H

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
#include "encoding/stringencoding.h"
#include "lattice/trapdoor.h"
#include "lattice/trapdoorparameters.h"
#include "signaturecore.h"

namespace lbcrypto {

	/*
	*  @brief Templated class for holding signatures.
	*  @tparam is the ring element
	*/
	template <class Element>
	class GPVSignature: public LPSignature<Element> {
	public:
		/**
		* Default constructor
		*/
		GPVSignature(){
		}

		/**
		*Method for setting the element in signature
		*
		*@param signature Element vector to be set as the signature
		*/
		void SetSignature(shared_ptr<Matrix<Element>> signature) {
			m_signature = signature;
		}
		/**
		*Method for getting the element in signature
		*
		*@return the element held as signature
		*/
		const Matrix<Element>& GetSignature() const { return *m_signature; }

		/**
		*Destructor
		*/
		~GPVSignature() { }
	
	private:
		//Matrix of polynomials acting as actual signature
		shared_ptr<Matrix<Element>> m_signature;
			/*
		*@brief Overloaded dummy method
		*/
		void forceImplement(){} 
	};

	/*
	*  @brief Templated class for holding signatures.
	*  @tparam is the ring element
	*/
	template <class Element>
	class GPVPlaintext : public LPSignPlaintext<Element> {
	public:
		/**
		* Default constructor
		*/
		GPVPlaintext(){
		}
		/**
		*@brief Constructor
		*@param plaintext Plaintext to be set for signing
		*/
		GPVPlaintext(const string & plaintext){
			this->m_plaintext = plaintext;
		}

		/**
		*Method for setting the element in plaintext
		*
		*@param plaintext Plaintext to be set for signing
		*/
		void SetPlaintext(const string & plaintext) {
			this->m_plaintext = plaintext;
		}
		/**
		*Method for getting the element in plaintext
		*
		*@return the element held as plaintext
		*/
		const string& GetPlaintext() const { return m_plaintext; }

		/**
		*Destructor
		*/
		~GPVPlaintext() { }

	private:
		//String as plaintext to be signed
		string m_plaintext;
		/*
		*@brief Overloaded dummy method
		*/
		void forceImplement(){} 
	};

	/**
	* @brief  Class holding parameters required for calculations in signature schemes
	*/
	template <class Element>
	class GPVSignatureParameters : public LPSignatureParameters<Element> {
	public:
		/**
		*Method for setting the ILParams held in this class
		*
		*@param params Parameters to be held, used in Element construction
		*/
		void SetElemParams(shared_ptr<typename Element::Params> params, usint base = 2) {
			m_params = params; 
			m_base = base;
			const typename Element::Integer & q = params->GetModulus();
			size_t n = params->GetRingDimension();
			usint nBits = floor(log2(q.ConvertToDouble() - 1.0) + 1.0);
			m_k = ceil(nBits / log2(base));
			double c = (base + 1) * SIGMA;
			double s = SPECTRAL_BOUND(n, m_k, base);
			if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
				m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
			else
				m_dggLargeSigma = m_dgg;
		};

		/**
		*Method for accessing the ILParams held in this class
		*
		*@return Parameters held
		*/
		shared_ptr<typename Element::Params> GetILParams() const{ return m_params; }

		/**
		*Method for accessing the DiscreteGaussianGenerator object held in this class
		*
		*@return DiscreteGaussianGenerator object held
		*/
		typename Element::DggType & GetDiscreteGaussianGenerator() { return m_dgg; }

		/**
		*Method for accessing the base for Gadget matrix
		*
		*@return the value of base held by the object
		*/
		usint & GetBase() { return m_base; }

		/**
		*Method for accessing the dimension for Gadget matrix
		*
		*@return the value of the dimension held by the object
		*/
		usint & GetK() { return m_k; }

		/**
		*Method for accessing the DiscreteGaussianGenerator object held in this class
		*
		*@return DiscreteGaussianGenerator object held
		*/
		typename Element::DggType & GetDiscreteGaussianGeneratorLargeSigma() { return m_dggLargeSigma; }

		/**
		*Constructor
		*@param params Parameters used in Element construction
		*@param dgg DiscreteGaussianGenerator used in sampling
		*/
		GPVSignatureParameters(shared_ptr<typename Element::Params> params, typename Element::DggType& dgg, usint base = 2) : m_dgg(dgg), m_base(base) {
			m_params = params;
			const typename Element::Integer & q = params->GetModulus();
			size_t n = params->GetRingDimension();
			usint nBits = floor(log2(q.ConvertToDouble()-1.0)+1.0);
			m_k = ceil(nBits / log2(base));
			double c = (base + 1) * SIGMA;
			double s = SPECTRAL_BOUND(n, m_k, base);
			if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
				m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
			else
				m_dggLargeSigma = m_dgg;
		}


	private:
		//Parameters related to elements
		shared_ptr<typename Element::Params> m_params;
		//Discrete Gaussian Generator for random number generation
		typename Element::DggType m_dgg;
		//Discrete Gaussian Generator with high distribution parameter for random number generation
		typename Element::DggType m_dggLargeSigma;
		//Trapdoor base
		usint m_base;
		//Trapdoor length
		usint m_k;
			/*
		*@brief Overloaded dummy method
		*/
		void forceImplement(){} 
	};

	/**
	*  @brief Class holding signing key for Ring LWE variant of GPV signing algorithm with GM17 improvements. The values held in this class are trapdoor and public key
	*  @tparam is the ring element
	*/
	template <class Element>
	class GPVSignKey : public LPSignKey<Element>{
	public:
		/**
		* Default constructor
		*/
		GPVSignKey(){
		}

		/**Constructor
		*
		* @param x trapdoor pair used for signing
		*/
		GPVSignKey(shared_ptr<RLWETrapdoorPair<Element>> x) {
			this->m_sk = (x);
		}

		/**
		*Destructor
		*/
		~GPVSignKey() {
		}


		/**
		*Method for accessing key in signing process
		*
		*@return Key used in signing
		*/
		const  RLWETrapdoorPair<Element> & GetSignKey() const { return *m_sk; }
		/**
		*Method for setting the private key used in the signing process
		*
		*@param &x a trapdoor pair used for signing
		*/
		void SetSignKey(shared_ptr<RLWETrapdoorPair<Element>> x) {
			
			this->m_sk = (x);
		}
	private:
		//Trapdoor pair acting as signing key
		shared_ptr<RLWETrapdoorPair<Element>> m_sk;
			/*
		*@brief Overloaded dummy method
		*/
		void forceImplement(){} 
	};

	/**
	* @brief Class holding verification key for Ring LWE variant of GPV signing algorithm with GM17 improvements. The value held in this class is the  public key of the trapdoor
	* @tparam is the ring element
	*/
	template <class Element>
	class GPVVerificationKey: public LPVerificationKey<Element> {
	public:

		/**
		*  Default constructor
		*/
		GPVVerificationKey(){
		}

		/**
		* Constructor
		* @param vk Verification key
		*/
		GPVVerificationKey(shared_ptr<Matrix<Element>> vk) {
			this->m_vk = vk;
		}

		/**
		*  Destructor
		*/
		~GPVVerificationKey() {
		}
		/**
		*Method for accessing key in verification process
		*
		*@return Key used in verification
		*/
		const Matrix<Element> & GetVerificationKey() const { return *m_vk; }
		/**
		* Method for setting key used in verification process
		*
		* @param x Key used in verification
		*/
		void SetVerificationKey(shared_ptr<Matrix<Element>> x) {
			
			this->m_vk = x;
		}
	private:
		//Public key from trapdoor acting as verification key
		shared_ptr<Matrix<Element>> m_vk;
			/*
		*@brief Overloaded dummy method
		*/
		void forceImplement(){} 
	};
	/**
	*@brief Implementation of Ring LWE variant of GPV signature scheme. Currently it supports only one type of vectors, therefore it is not templated
	*  @tparam is the ring element
	*/
	template <class Element>
	class GPVSignatureScheme: public LPSignatureScheme<Element>{
	public:
		/**
		* Default constructor
		*/
		GPVSignatureScheme() : seed(0) {}

		/**
		*Method for signing given text
		*@param m_params parameters for signing 
		*@param sk private signing key
		*@param vk public verification key
		*@param pt encoding of the text to be signed
		*@param sign signature generated after the signing process - output of the function
		*/
		void Sign(shared_ptr<LPSignatureParameters<Element>> m_params,const LPSignKey<Element> & sk,const LPVerificationKey<Element> &vk, const LPSignPlaintext<Element> & pt, LPSignature<Element>* sign);

		/**
		*Method for offline perturbation sampling
		*@param m_params parameters used for signing
		*@param signKey private signing key
		*return perturbation vector
		*/
		shared_ptr<Matrix<Element>> SampleOffline(shared_ptr<GPVSignatureParameters<Element>> m_params,const GPVSignKey<Element> &signKey);

		/**
		*Method for signing given text
		*@param m_params parameters used for signing
		*@param signKey private signing key
		*@param verificationKey public verification key
		*@param Pre-computed perturbation vector
		*@param plainText encoding of the text to be signed
		*@param signatureText signature generated after the signing process - output of the function
		*/
		void SignOnline(shared_ptr<GPVSignatureParameters<Element>> m_params,const GPVSignKey<Element> &signKey,const GPVVerificationKey<Element> &verificationKey, const shared_ptr<Matrix<Element>> parturbationVector, const string &plainText,
			GPVSignature<Element> * signatureText);

		/**
		*Method for verifying given text & signature
		*@param m_params parameters used for the scheme
		*@param vk public verification key
		*@param sign signature to be verified
		*@param pt encoding of the text to be verified
		*@return result of the verification process
		*/
		bool Verify(shared_ptr<LPSignatureParameters<Element>> m_params,const LPVerificationKey<Element> & vk,
		const LPSignature<Element> & sign, const LPSignPlaintext<Element> & pt);

		/**
		*
		*Method for generating signing and verification keys
		*@param m_params parameters used for the scheme
		*@param sk private signing key generated after trapdoor & perturbation matrix - output of the function
		*@param vk public verification key generated after trapdoor - output of the function
		*/
		void KeyGen(shared_ptr<LPSignatureParameters<Element>> m_params,LPSignKey<Element>* sk, LPVerificationKey<Element>* vk);
	private:
		std::vector<char> seed;
		/*
		*@brief Overloaded dummy method
		*/
		void forceImplement(){} 
	};
}
#endif
