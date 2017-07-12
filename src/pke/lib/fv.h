/**
 * @file fv.h -- Operations for the FV cryptoscheme.
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
 /*
 *
 * This code implements the Fan-Vercauteren (FV) homomorphic encryption scheme.
 * The FV scheme is introduced here:
 *   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 *
 * Our implementation builds from the designs here:
 *   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 *
 */

#ifndef LBCRYPTO_CRYPTO_FV_H
#define LBCRYPTO_CRYPTO_FV_H

#include "palisade.h"

namespace lbcrypto {

	/**
 	* @brief This is the parameters class for the FV encryption scheme.
 	*
 	* The FV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
 	* @tparam Element a ring element type.
 	*/
	template <class Element>
	class LPCryptoParametersFV : public LPCryptoParametersRLWE<Element> {

		public:
			/**
			 * Default constructor.
			 */
			LPCryptoParametersFV() : LPCryptoParametersRLWE<Element>() {
				m_delta = BigInteger(0);
				m_mode = RLWE;
				m_bigModulus = BigInteger(0);
				m_bigRootOfUnity = BigInteger(0);
				m_bigModulusArb = BigInteger(0);
				m_bigRootOfUnityArb = BigInteger(0);
			}

			/**
		 	 * Copy constructor.
	 		 * @param rhs - source
			 */
			LPCryptoParametersFV(const LPCryptoParametersFV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {
				m_delta = rhs.m_delta;
				m_mode = rhs.m_mode;
				m_bigModulus = rhs.m_bigModulus;
				m_bigRootOfUnity = rhs.m_bigRootOfUnity;
				m_bigModulusArb = rhs.m_bigModulusArb;
				m_bigRootOfUnityArb = rhs.m_bigRootOfUnityArb;
			}

			/**
			 * Constructor that initializes values.  Note that it is possible to set parameters in a way that is overall
			 * infeasible for actual use.  There are fewer degrees of freedom than parameters provided.  Typically one
			 * chooses the basic noise, assurance and security parameters as the typical community-accepted values, 
			 * then chooses the plaintext modulus and depth as needed.  The element parameters should then be choosen 
			 * to provide correctness and security.  In some cases we would need to operate over already 
			 * encrypted/provided ciphertext and the depth needs to be pre-computed for initial settings.
			 *
			 * @param &params Element parameters.  This will depend on the specific class of element being used.
			 * @param &plaintextModulus Plaintext modulus, typically denoted as p in most publications.
			 * @param distributionParameter Noise distribution parameter, typically denoted as /sigma in most publications.  Community standards typically call for a value of 3 to 6. Lower values provide more room for computation while larger values provide more security.
			 * @param assuranceMeasure Assurance level, typically denoted as w in most applications.  This is oftern perceived as a fudge factor in the literature, with a typical value of 9.
			 * @param securityLevel Security level as Root Hermite Factor.  We use the Root Hermite Factor representation of the security level to better conform with US ITAR and EAR export regulations.  This is typically represented as /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less provides reasonable security for RLWE crypto schemes, although extra care is need for the LTV scheme because LTV makes an additional security assumption that make it suceptible to subfield lattice attacks.
			 * @param relinWindow The size of the relinearization window.  This is relevant when using this scheme for proxy re-encryption, and the value is denoted as r in the literature.
			 * @param delta FV-specific factor that is multiplied by the plaintext polynomial.
			 * @param mode optimization setting (RLWE vs OPTIMIZED)
			 * @param bigModulus modulus used in polynomial multiplications in EvalMult
			 * @param bigRootOfUnity root of unity for bigModulus
			 * @param bigModulusArb modulus used in polynomial multiplications in EvalMult (for arbitrary cyclotomics)
			 * @param bigRootOfUnityArb root of unity for bigModulus (for arbitrary cyclotomics)
			 * @param depth Depth is the depth of computation supprted which is set to 1 by default.  Use the default setting unless you're using SHE, levelled SHE or FHE operations.
			 */
			LPCryptoParametersFV(shared_ptr<typename Element::Params> params,
				const BigInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				const BigInteger &delta,
				MODE mode,
				const BigInteger &bigModulus,
				const BigInteger &bigRootOfUnity,
				const BigInteger &bigModulusArb,
				const BigInteger &bigRootOfUnityArb,
				int depth = 1)
					: LPCryptoParametersRLWE<Element>(params,
						plaintextModulus,
						distributionParameter,
						assuranceMeasure,
						securityLevel,
						relinWindow,
						depth) {
						m_delta = delta;
						m_mode = mode;
						m_bigModulus = bigModulus;
						m_bigRootOfUnity = bigRootOfUnity;
						m_bigModulusArb = bigModulusArb;
						m_bigRootOfUnityArb = bigRootOfUnityArb;
					}

			/**
			* Constructor that initializes values.
			*
			* @param &params element parameters.
			* @param &encodingParams plaintext space parameters.
			* @param distributionParameter noise distribution parameter.
			* @param assuranceMeasure assurance level.
			* @param securityLevel security level (root Hermite factor).
			* @param relinWindow the size of the relinearization window.
			* @param delta FV-specific factor that is multiplied by the plaintext polynomial.
			* @param mode optimization setting (RLWE vs OPTIMIZED)
			* @param bigModulus modulus used in polynomial multiplications in EvalMult
			* @param bigRootOfUnity root of unity for bigModulus
			* @param bigModulusArb modulus used in polynomial multiplications in EvalMult (arbitrary cyclotomics)
			* @param bigRootOfUnityArb root of unity for bigModulus (arbitrary cyclotomics)
			* @param depth depth which is set to 1.
			*/
			LPCryptoParametersFV(shared_ptr<typename Element::Params> params,
				shared_ptr<EncodingParams> encodingParams,
				float distributionParameter,
				float assuranceMeasure,
				float securityLevel,
				usint relinWindow,
				const BigInteger &delta,
				MODE mode,
				const BigInteger &bigModulus,
				const BigInteger &bigRootOfUnity,
				const BigInteger &bigModulusArb,
				const BigInteger &bigRootOfUnityArb,
				int depth = 1)
				: LPCryptoParametersRLWE<Element>(params,
					encodingParams,
					distributionParameter,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					depth) {
				m_delta = delta;
				m_mode = mode;
				m_bigModulus = bigModulus;
				m_bigRootOfUnity = bigRootOfUnity;
				m_bigModulusArb = bigModulusArb;
				m_bigRootOfUnityArb = bigRootOfUnityArb;
			}

			/**
			* Destructor
			*/
			virtual ~LPCryptoParametersFV() {}
			
			/**
			* Serialize the object
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj) const;

			/**
			* Populate the object from the deserialization of the Serialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj);

			/**
			* Gets the value of the delta factor.
			*
			* @return the delta factor. It is an FV-specific factor that is multiplied by the plaintext polynomial.
			*/
			const BigInteger& GetDelta() const { return m_delta; }

			/**
			* Gets the mode setting: RLWE or OPTIMIZED.
			*
			* @return the mode setting.
			*/
			MODE GetMode() const { return m_mode; }

			/**
			* Gets the modulus used for polynomial multiplications in EvalMult
			*
			* @return the modulus value.
			*/
			const BigInteger& GetBigModulus() const { return m_bigModulus; }

			/**
			* Gets the primitive root of unity used for polynomial multiplications in EvalMult
			*
			* @return the primitive root of unity value.
			*/
			const BigInteger& GetBigRootOfUnity() const { return m_bigRootOfUnity; }

			/**
			* Gets the modulus used for polynomial multiplications in EvalMult (arbitrary cyclotomics)
			*
			* @return the modulus value.
			*/
			const BigInteger& GetBigModulusArb() const { return m_bigModulusArb; }

			/**
			* Gets the primitive root of unity used for polynomial multiplications in EvalMult (arbitrary cyclotomics)
			*
			* @return the primitive root of unity value.
			*/
			const BigInteger& GetBigRootOfUnityArb() const { return m_bigRootOfUnityArb; }

			/**
			* Sets the value of the delta factor
			* @param &delta is the delta factor
			*/
			void SetDelta(const BigInteger &delta) { m_delta = delta; }

			/**
			* Configures the mode for generating the secret key polynomial
			* @param mode is RLWE or OPTIMIZED.  OPTIMIZED is preferred for increased performance.
			*/
			void SetMode(MODE mode) { m_mode = mode; }

			/**
			* Sets the modulus used for polynomial multiplications in EvalMult
			* 
			* @param &bigModulus the modulus value.
			*/
			void SetBigModulus(const BigInteger &bigModulus) { m_bigModulus = bigModulus; }

			/**
			* Sets primitive root of unity used for polynomial multiplications in EvalMult
			* @param &bigRootOfUnity is the root of unity used for EvalMult operations.
			*/
			void SetBigRootOfUnity(const BigInteger &bigRootOfUnity) { m_bigRootOfUnity = bigRootOfUnity; }

			/**
			* Sets the modulus used for polynomial multiplications in EvalMult (arbitrary cyclotomics)
			*/
			void SetBigModulusArb(const BigInteger &bigModulusArb) { m_bigModulusArb = bigModulusArb; }

			/**
			* Sets primitive root of unity used for polynomial multiplications in EvalMult (arbitrary cyclotomics)
			*/
			void SetBigRootOfUnityArb(const BigInteger &bigRootOfUnityArb) { m_bigRootOfUnityArb = bigRootOfUnityArb; }

			/**
			* == operator to compare to this instance of LPCryptoParametersFV object. 
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersFV<Element> *el = dynamic_cast<const LPCryptoParametersFV<Element> *>(&rhs);

				if( el == 0 ) return false;

				if (m_delta != el->m_delta) return false;
				if (m_mode != el->m_mode) return false;
				if (m_bigModulus != el->m_bigModulus) return false;
				if (m_bigRootOfUnity != el->m_bigRootOfUnity) return false;
				if (m_bigModulusArb != el->m_bigModulusArb) return false;
				if (m_bigRootOfUnityArb != el->m_bigRootOfUnityArb) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}

			void PrintParameters(std::ostream& os) const {
				LPCryptoParametersRLWE<Element>::PrintParameters(os);

				os << " delta: " << m_delta <<
						" mode: " << m_mode <<
						" bigmodulus: " << m_bigModulus <<
						" bigrootofunity: " << m_bigRootOfUnity <<
						" bigmodulusarb: " << m_bigModulusArb <<
						" bigrootofunityarb: " << m_bigRootOfUnityArb;
			}

		private:
			// factor delta = floor(q/p) that is multipled by the plaintext polynomial 
			// in FV (most significant bit ranges are used to represent the message)
			BigInteger m_delta;
			
			// specifies whether the keys are generated from discrete 
			// Gaussian distribution or ternary distribution with the norm of unity
			MODE m_mode;
			
			// larger modulus that is used in polynomial multiplications within EvalMult (before rounding is done)
			BigInteger m_bigModulus;
			
			// primitive root of unity for m_bigModulus
			BigInteger m_bigRootOfUnity;

			// Large modulus used for CRT with m_bigModulus
			BigInteger m_bigModulusArb;

			// Primitive root of unity for m_bigModulusArb
			BigInteger m_bigRootOfUnityArb;
	};

	/**
	* @brief Parameter generation for FV.
	*
 	* The FV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmParamsGenFV : public LPParameterGenerationAlgorithm<Element> { 
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmParamsGenFV() {}

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		*/
		bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const;

	};

	/**
	* @brief Encryption algorithm implementation for FV for the basic public key encrypt, decrypt and key generation methods for the FV encryption scheme.
	*
 	* The FV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmFV : public LPEncryptionAlgorithm<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmFV() {}

		/**
		* Method for encrypting plaintext using FV.
		*
		* @param publicKey public key used for encryption.
		* @param &plaintext the plaintext input.
		* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
		* @return ciphertext which results from encryption.
		*/
		shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
			Poly &plaintext, bool doEncryption = true) const;

		/**
		* Method for decrypting using FV. See the class description for citations on where the algorithms were
	 	* taken from.
		*
		* @param privateKey private key used for decryption.
		* @param ciphertext ciphertext to be decrypted.
		* @param *plaintext the plaintext output.
		* @return the decrypted plaintext returned.
		*/
		DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
			const shared_ptr<Ciphertext<Element>> ciphertext,
			Poly *plaintext) const;

		/**
		* Function to generate public and private keys. See the class description for citations on where the algorithms were
	 	* taken from.
		*
		* @param cc cryptocontext for the keys to be generated.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.  Generally this should always be false.
		* @return key pair including the private and public key
		*/
		LPKeyPair<Element> KeyGen(CryptoContext<Element>* cc, bool makeSparse=false);

	};

	/**
	* @brief SHE algorithms implementation for FV.
	*
 	* The FV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmSHEFV : public LPSHEAlgorithm<Element> { 
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmSHEFV() {}

		/**
		* Function for homomorphic addition of ciphertexts.
		*
		* @param ct1 fist input ciphertext.
		* @param ct2 second input ciphertext.
		* @return new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ct1, 
			const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Function for homomorphic subtraction of ciphertexts.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @return new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ct1, 
			const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Function for homomorphic evaluation of ciphertexts.
		* Currently it assumes that the input arguments are fresh ciphertexts (of depth 1). Support for the input ciphertexts of higher depths will be added later.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @return resulting EvalMult ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ct1,
			const shared_ptr<Ciphertext<Element>> ct2) const;

		/**
		* Function for multiplying ciphertext by plaintext.
		*
		* @param ciphertext input ciphertext.
		* @param plaintext input plaintext embedded in the cryptocontext.
		* @return result of the multiplication.
		*/
		shared_ptr<Ciphertext<Element>> EvalMultPlain(const shared_ptr<Ciphertext<Element>> ciphertext,
			const shared_ptr<Ciphertext<Element>> plaintext) const;

		/**
		* Function for evaluating multiplication on ciphertext followed by key switching operation.
		* Currently it assumes that the input arguments are fresh ciphertexts (of depth 1). Support for the input ciphertexts of higher depths will be added later.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext 
		*  decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ct1,
			const shared_ptr<Ciphertext<Element>> ct, const shared_ptr<LPEvalKey<Element>> ek) const;

		/**
		* Function for homomorphic negation of ciphertexts.
		*
		* @param ct first input ciphertext.
		* @return new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalNegate(const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Method for generating a KeySwitchHint using RLWE relinearization
		*
		* @param originalPrivateKey Original private key used for encryption.
		* @param newPrivateKey New private key to generate the keyswitch hint.
		* @return resulting keySwitchHint.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey,
			const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const;

		/**
		* Method for key switching based on a KeySwitchHint using RLWE relinearization
		*
		* @param keySwitchHint Hint required to perform the ciphertext switching.
		* @param &cipherText Original ciphertext to perform switching on.
		* @return new ciphertext
		*/
		shared_ptr<Ciphertext<Element>> KeySwitch(const shared_ptr<LPEvalKey<Element>> keySwitchHint,
			const shared_ptr<Ciphertext<Element>> cipherText) const;

		/**
		* Method for KeySwitching based on RLWE relinearization and NTRU key generation.
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		* Not implemented for FV.
		*
		* @param &newPublicKey encryption key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchRelinGen(const shared_ptr<LPPublicKey<Element>> newPublicKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
			std::string errMsg = "LPAlgorithmSHEFV:KeySwitchRelinGen is not needed for this scheme as relinearization is the default technique and no NTRU key generation is used.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Method for KeySwitching based on RLWE relinearization and NTRU key generation
		* Not implemented for FV.
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return the resulting Ciphertext
		*/
		shared_ptr<Ciphertext<Element>> KeySwitchRelin(const shared_ptr<LPEvalKey<Element>> evalKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const {
			std::string errMsg = "LPAlgorithmSHEFV:KeySwitchRelin is not needed for this scheme as relinearization is the default technique and no NTRU key generation is used.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function to generate 1..log(q) encryptions for each bit of the square of the original private key
		*
		* @param k1 private key.
		* @return evaluation key.
		*/
		shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(
					const shared_ptr<LPPrivateKey<Element>> k1) const;

		/**
		* Function for evaluating automorphism of ciphertext at index i.
		*
		* @param ciphertext the input ciphertext.
		* @param i automorphism index
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		shared_ptr<Ciphertext<Element>> EvalAutomorphism(const shared_ptr<Ciphertext<Element>> ciphertext, usint i,
			const std::map<usint, shared_ptr<LPEvalKey<Element>>> &evalKeys) const;

		/**
		* Generate automophism keys for a given private key; Uses the private key for encryption
		*
		* @param privateKey private key.
		* @param indexList list of automorphism indices to be computed
		* @return returns the evaluation keys
		*/
		shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> EvalAutomorphismKeyGen(const shared_ptr<LPPrivateKey<Element>> privateKey,
			const std::vector<usint> &indexList) const;

		/**
		* Generate automophism keys for a given private key; Uses the public key for encryption
		*
		* @param publicKey public key.
		* @param privateKey private key.
		* @param indexList list of automorphism indices to be computed
		* @return returns the evaluation keys
		*/
		shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
			const shared_ptr<LPPrivateKey<Element>> privateKey, const std::vector<usint> &indexList) const {
			std::string errMsg = "LPAlgorithmSHEFV::EvalAutomorphismKeyGen is not implemented for FV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}

	};

	/**
	* @brief PRE scheme based on FV. This functionality is currently DISABLED in LPPublicKeyEncryptionSchemeFV because
	* it needs more testing
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmPREFV : public LPPREAlgorithm<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmPREFV() {}

		/*
		* DISABLED. Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
		* Variant that uses the new secret key directly.
		*
		* @param newKey new private key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
		*/
		shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPrivateKey<Element>> newKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const;

		/**
		* DISABLED. Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
		* Variant that uses the public key for the new secret key. Not implemented for FV.
		*
		* @param newKey public key for the new private key.
		* @param origPrivateKey original private key used for decryption.
		* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
		*/
		shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPublicKey<Element>> newKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
			std::string errMsg = "LPAlgorithmPREFV::ReKeyGen using a public key of the new secret key is not implemented for the BV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* DISABLED. Function to define the re-encryption method using the evaluation key generated by ReKeyGen
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return resulting ciphertext after the re-encryption operation.
		*/
		shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const;

	};



	/**
	 * @brief Concrete class for the FHE Multiparty algorithms on FV.  A version of this multiparty scheme built on the BGV scheme is seen here:
	 *   - Asharov G., Jain A., López-Alt A., Tromer E., Vaikuntanathan V., Wichs D. (2012) Multiparty Computation with Low Communication, Computation and Interaction via Threshold FHE. In: Pointcheval D., Johansson T. (eds) Advances in Cryptology – EUROCRYPT 2012. EUROCRYPT 2012. Lecture Notes in Computer Science, vol 7237. Springer, Berlin, Heidelberg
	 *
	 * During offline key generation, this multiparty scheme relies on the clients coordinating their public key generation.  To do this, a single client generates a public-secret key pair.
	 * This public key is shared with other keys which use an element in the public key to generate their own public keys.
	 * The clients generate a shared key pair using a scheme-specific approach, then generate re-encryption keys.  Re-encryption keys are uploaded to the server.
	 * Clients encrypt data with their public keys and send the encrypted data server.
	 * The data is re-encrypted.  Computations are then run on the data.
	 * The result is sent to each of the clients.
	 * One client runs a "Leader" multiparty decryption operation with its own secret key.  All other clients run a regular "Main" multiparty decryption with their own secret key.
	 * The resulting partially decrypted ciphertext are then fully decrypted with the decryption fusion algorithms.
	 *
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAlgorithmMultipartyFV : public LPMultipartyAlgorithm<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmMultipartyFV() {}

		/**
		* Function to generate public and private keys for multiparty homomrophic encryption in coordination with a leading client that generated a first public key.
		*
		* @param cc cryptocontext for the keys to be generated.
		* @param pk1 private key used for decryption to be fused.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
		* @return key pair including the private and public key
		*/
		LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element>* cc,
				const shared_ptr<LPPublicKey<Element>> pk1,
				bool makeSparse=false);

		/**
		* Function to generate public and private keys for multiparty homomrophic encryption server key pair in coordination with secret keys of clients.
		*
		* @param cc cryptocontext for the keys to be generated.
		* @param secretkeys private keys used for decryption to be fused.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
		* @return key pair including the private and public key
		*/
		LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element>* cc,
				const vector<shared_ptr<LPPrivateKey<Element>>>& secretKeys,
				bool makeSparse=false);

		/**
		 * Method for main decryption operation run by most decryption clients for multiparty homomorphic encryption
		 *
		 * @param privateKey private key used for decryption.
		 * @param ciphertext ciphertext id decrypted.
		 */
		shared_ptr<Ciphertext<Element>> MultipartyDecryptMain(const shared_ptr<LPPrivateKey<Element>> privateKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const;

		/**
		 * Method for decryption operation run by the lead decryption client for multiparty homomorphic encryption
		 *
		 * @param privateKey private key used for decryption.
		 * @param ciphertext ciphertext id decrypted.
		 */
		shared_ptr<Ciphertext<Element>> MultipartyDecryptLead(const shared_ptr<LPPrivateKey<Element>> privateKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const;

		/**
		 * Method for fusing the partially decrypted ciphertext.
		 *
		 * @param &ciphertextVec ciphertext id decrypted.
		 * @param *plaintext the plaintext output.
		 * @return the decoding result.
		 */
		DecryptResult MultipartyDecryptFusion(const vector<shared_ptr<Ciphertext<Element>>>& ciphertextVec,
			Poly *plaintext) const;

	};


	/**
	* @brief Main public key encryption scheme for FV implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeFV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeFV() : LPPublicKeyEncryptionScheme<Element>() {
			this->m_algorithmParamsGen = new LPAlgorithmParamsGenFV<Element>();
		}

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
