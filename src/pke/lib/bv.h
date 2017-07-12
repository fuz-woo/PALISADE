/**
 * @file bv.h -- Operations for the BV cryptoscheme.
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
 * This code implements the Brakerski-Vaikuntanathan (BV) homomorphic encryption scheme.
 * The basic scheme is described here:
 *   -  Brakerski Z., Vaikuntanathan V. (2011) Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent Messages. In: Rogaway P. (eds) Advances in Cryptology – CRYPTO 2011. CRYPTO 2011. Lecture Notes in Computer Science, vol 6841. Springer, Berlin, Heidelberg
 *      (http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf) or alternative Internet source: (http://dx.doi.org/10.1007/978-3-642-22792-9_29).
 * 
 * We use advances from the BGV scheme for levelled homomorphic capabilities from here:
 *   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in LWE-Based Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds) Public-Key Cryptography – PKC 2013. Lecture Notes in Computer Science, vol 7778. Springer, Berlin, Heidelberg
 *     (https://eprint.iacr.org/2011/277.pdf).
 *
 * Implementation design details that we use in our implementation are discussed here: 
 *   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology – CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin, Heidelberg
 *     ( https://eprint.iacr.org/2012/099.pdf)
 */


#ifndef LBCRYPTO_CRYPTO_BV_H
#define LBCRYPTO_CRYPTO_BV_H

//Includes Section
#include "palisade.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	/**
	 * @brief Crypto parameters class for RLWE-based schemes.
	 * The basic scheme is described here:
	 *   -  Brakerski Z., Vaikuntanathan V. (2011) Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent Messages. In: Rogaway P. (eds) Advances in Cryptology – CRYPTO 2011. CRYPTO 2011. Lecture Notes in Computer Science, vol 6841. Springer, Berlin, Heidelberg
	 *      (http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf) or alternative Internet source: (http://dx.doi.org/10.1007/978-3-642-22792-9_29).
	 * 
	 * We use advances from the BGV scheme for levelled homomorphic capabilities from here:
	 *   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in LWE-Based Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds) Public-Key Cryptography – PKC 2013. Lecture Notes in Computer Science, vol 7778. Springer, Berlin, Heidelberg
	 *     (https://eprint.iacr.org/2011/277.pdf).
	 *
	 * Implementation design details that we use in our implementation are discussed here: 
	 *   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology – CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin, Heidelberg
	 *     ( https://eprint.iacr.org/2012/099.pdf)
	 *
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPCryptoParametersBV : public LPCryptoParametersRLWE<Element> {
		public:
			
			/**
			 * Default Constructor.
			 */
			LPCryptoParametersBV() : LPCryptoParametersRLWE<Element>() {
				m_mode = RLWE;
			}

			/**
			 * Copy constructor.
			 *
	 		 * @param rhs - source
			 */
			LPCryptoParametersBV(const LPCryptoParametersBV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {
				m_mode = rhs.m_mode;
			}

			/**
			 * Constructor that initializes values.  Note that it is possible to set parameters in a way that is overall
			 * infeasible for actual use.  There are fewer degrees of freedom than parameters provided.  Typically one
			 * chooses the basic noise, assurance and security parameters as the typical community-accepted values, 
			 * then chooses the plaintext modulus and depth as needed.  The element parameters should then be choosen 
			 * to provide correctness and security.  In some cases we would need to operate over already 
			 * encrypted/provided ciphertext and the depth needs to be pre-computed for initial settings.
			 *
			 * @param &params element parameters.
			 * @param &plaintextModulus plaintext modulus.
			 * @param distributionParameter noise distribution parameter.
			 * @param assuranceMeasure assurance level.
			 * @param securityLevel security level.
			 * @param relinWindow the size of the relinearization window.
			 * @param mode sets the mode of operation: RLWE or OPTIMIZED
			 * @param depth depth which is set to 1.
			 */
			LPCryptoParametersBV(
				shared_ptr<typename Element::Params> params,
				const BigInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				MODE mode,
				int depth = 1)
					: LPCryptoParametersRLWE<Element>(
						params,
						plaintextModulus,
						distributionParameter,
						assuranceMeasure,
						securityLevel,
						relinWindow,
						depth) {
				m_mode = mode;
			}

			/**
			* Constructor that initializes values.
			*
			* @param &params element parameters.
			* @param &encodingParams plaintext space parameters.
			* @param distributionParameter noise distribution parameter.
			* @param assuranceMeasure assurance level.
			* @param securityLevel security level.
			* @param relinWindow the size of the relinearization window.
			* @param mode sets the mode of operation: RLWE or OPTIMIZED
			* @param depth depth which is set to 1.
			*/
			LPCryptoParametersBV(
				shared_ptr<typename Element::Params> params,
				shared_ptr<EncodingParams> encodingParams,
				float distributionParameter,
				float assuranceMeasure,
				float securityLevel,
				usint relinWindow,
				MODE mode,
				int depth = 1)
				: LPCryptoParametersRLWE<Element>(
					params,
					encodingParams,
					distributionParameter,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					depth) {
				m_mode = mode;
			}

			/**
			* Destructor.
			*/
			virtual ~LPCryptoParametersBV() {}
			
			/**
			* Serialize the object into a Serialized
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
			* Gets the mode setting: RLWE or OPTIMIZED.
			*
			* @return the mode setting.
			*/
			MODE GetMode() const { return m_mode; }

			/**
			* Configures the mode for generating the secret key polynomial
			*/
			void SetMode(MODE mode) { m_mode = mode; }

			/**
			* == operator to compare to this instance of LPCryptoParametersBV object.
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersBV<Element> *el = dynamic_cast<const LPCryptoParametersBV<Element> *>(&rhs);

				if (el == 0) return false;

				if (m_mode != el->m_mode) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}

			void PrintParameters(std::ostream& os) const {
				LPCryptoParametersRLWE<Element>::PrintParameters(os);

				os << " mode: " << m_mode;
			}

	private:
		// specifies whether the keys are generated from discrete 
		// Gaussian distribution or ternary distribution with the norm of unity
		MODE m_mode;

	};


	/**
	* @brief Encryption algorithm implementation template for BV-based schemes.
	* The basic scheme is described here:
	*   -  Brakerski Z., Vaikuntanathan V. (2011) Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent Messages. In: Rogaway P. (eds) Advances in Cryptology – CRYPTO 2011. CRYPTO 2011. Lecture Notes in Computer Science, vol 6841. Springer, Berlin, Heidelberg
	*      (http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf) or alternative Internet source: (http://dx.doi.org/10.1007/978-3-642-22792-9_29).
	* 
	* We use advances from the BGV scheme for levelled homomorphic capabilities from here:
	*   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in LWE-Based Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds) Public-Key Cryptography – PKC 2013. Lecture Notes in Computer Science, vol 7778. Springer, Berlin, Heidelberg
	*     (https://eprint.iacr.org/2011/277.pdf).
	*
	* Implementation design details that we use in our implementation are discussed here: 
	*   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology – CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin, Heidelberg
	*     ( https://eprint.iacr.org/2012/099.pdf)
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmBV : public LPEncryptionAlgorithm<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmBV() {};

		/**
		* Method for encrypting plaintext using BV Scheme
		*
		* @param publicKey is the public key used for encryption.
		* @param &plaintext the plaintext input.
		* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
		* @return ciphertext which results from encryption.
		*/
		shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey, Poly &plaintext, bool doEncryption = true) const;

		/**
		* Method for decrypting plaintext using BV
		*
		* @param &privateKey private key used for decryption.
		* @param &ciphertext ciphertext id decrypted.
		* @param *plaintext the plaintext output.
		* @return the success/fail result
		*/
		DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
			const shared_ptr<Ciphertext<Element>> ciphertext,
			Poly *plaintext) const;

		/**
		* Function to generate public and private keys
		*
		* @param cc is the cryptoContext which encapsulates the crypto paramaters.
		* @param makeSparse is a boolean flag that species if the key is sparse(interleaved zeroes) or not.
		* @return KeyPair containting private key and public key.
		*/
		LPKeyPair<Element> KeyGen(CryptoContext<Element>* cc, bool makeSparse=false);

	};

	/**
	* Class for evaluation of somewhat homomorphic operations.
	* The basic scheme is described here:
	*   -  Brakerski Z., Vaikuntanathan V. (2011) Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent Messages. In: Rogaway P. (eds) Advances in Cryptology – CRYPTO 2011. CRYPTO 2011. Lecture Notes in Computer Science, vol 6841. Springer, Berlin, Heidelberg
	*      (http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf) or alternative Internet source: (http://dx.doi.org/10.1007/978-3-642-22792-9_29).
	* 
	* We use advances from the BGV scheme for levelled homomorphic capabilities from here:
	*   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in LWE-Based Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds) Public-Key Cryptography – PKC 2013. Lecture Notes in Computer Science, vol 7778. Springer, Berlin, Heidelberg
	*     (https://eprint.iacr.org/2011/277.pdf).
	*
	* Implementation design details that we use in our implementation are discussed here: 
	*   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology – CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin, Heidelberg
	*     ( https://eprint.iacr.org/2012/099.pdf)
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmSHEBV : public LPSHEAlgorithm<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmSHEBV() {}

		/**
		* Function for homomorphic addition of ciphertexts.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @return result of homomorphic addition of input ciphertexts.
		*/
		shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

		/**
		* Function for homomorphic subtraction of ciphertexts.
		*
		* @param ciphertext1 the input ciphertext.
		* @param ciphertext2 the input ciphertext.
		* @return result of homomorphic subtraction of input ciphertexts.
		*/
		shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1, 
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

		/**
		* Function for homomorphic multiplication of ciphertexts without key switching. 
		* Currently it assumes that the input arguments are fresh ciphertexts (of depth 1). Support for the input ciphertexts of higher depths will be added later.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @return result of homomorphic multiplication of input ciphertexts.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

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
		* Function for homomorphic multiplication of ciphertexts followed by key switching operation.
		* Currently it assumes that the input arguments are fresh ciphertexts (of depth 1). Support for the input ciphertexts of higher depths will be added later.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @return result of homomorphic multiplication of input ciphertexts.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2,
			const shared_ptr<LPEvalKey<Element>> ek) const;

		/**
		* Function for homomorphic negation of ciphertexts.
		*
		* @param ct first input ciphertext.
		* @return new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalNegate(const shared_ptr<Ciphertext<Element>> ct) const;

		/**
		* Method for generating a KeySwitchHint using RLWE relinearization (based on the RLWE assumption only)
		*
		* @param originalPrivateKey is the original private key used for encryption.
		* @param newPrivateKey is the new private key to generate the keyswitch hint.
		* @return resulting keySwitchHint to switch the ciphertext to be decryptable by new private key.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey, 
			const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const;

		/**
		* Method for KeySwitching based on a KeySwitchHint - uses the RLWE relinearization
		*
		* @param keySwitchHint Hint required to perform the ciphertext switching.
		* @param cipherText Original ciphertext to perform switching on.
		* @return cipherText decryptable by new private key.
		*/
		shared_ptr<Ciphertext<Element>> KeySwitch(const shared_ptr<LPEvalKey<Element>> keySwitchHint, 
			const shared_ptr<Ciphertext<Element>> cipherText) const;

		/**
		* Method for KeySwitching based on NTRU key generation and RLWE relinearization. Not used for BV.
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		*
		* @param &newPublicKey encryption key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchRelinGen(const shared_ptr<LPPublicKey<Element>> newPublicKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
			std::string errMsg = "LPAlgorithmSHEBV:KeySwitchRelinGen is not implemented for BV as relinearization is the default technique and no NTRU key generation is used in BV.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Method for KeySwitching based on NTRU key generation and RLWE relinearization. Not used for BV.
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return the resulting Ciphertext
		*/
		shared_ptr<Ciphertext<Element>> KeySwitchRelin(const shared_ptr<LPEvalKey<Element>> evalKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const {
			std::string errMsg = "LPAlgorithmSHEBV:KeySwitchRelin is not implemented for BV as relinearization is the default technique and no NTRU key generation is used in BV.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function to generate key switch hint on a ciphertext for depth 2.
		*
		* @param originalPrivateKey is the original private key used for generating ciphertext.
		* @return keySwitchHint generated to switch the ciphertext.
		*/
		shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const;

		/**
		* Function for evaluating automorphism of ciphertext at index i
		*
		* @param ciphertext the input ciphertext.
		* @param i automorphism index
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		shared_ptr<Ciphertext<Element>> EvalAutomorphism(const shared_ptr<Ciphertext<Element>> ciphertext, usint i,
			const std::map<usint,shared_ptr<LPEvalKey<Element>>> &evalKeys) const;


		/**
		* Generate automophism keys for a given private key; Uses the private key for encryption
		*
		* @param privateKey private key.
		* @param indexList list of automorphism indices to be computed
		* @return returns the evaluation keys
		*/
		shared_ptr<std::map<usint,shared_ptr<LPEvalKey<Element>>>> EvalAutomorphismKeyGen(const shared_ptr<LPPrivateKey<Element>> privateKey,
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
			std::string errMsg = "LPAlgorithmSHEBV::EvalAutomorphismKeyGen is not implemented for BV SHE Scheme.";
			throw std::runtime_error(errMsg);
		}

	};

	/**
	* @brief PRE scheme based on BV.
	* The basic scheme is described here:
	*   -  Brakerski Z., Vaikuntanathan V. (2011) Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent Messages. In: Rogaway P. (eds) Advances in Cryptology – CRYPTO 2011. CRYPTO 2011. Lecture Notes in Computer Science, vol 6841. Springer, Berlin, Heidelberg
	*      (http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf) or alternative Internet source: (http://dx.doi.org/10.1007/978-3-642-22792-9_29).
	* 
	* We use advances from the BGV scheme for levelled homomorphic capabilities from here:
	*   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in LWE-Based Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds) Public-Key Cryptography – PKC 2013. Lecture Notes in Computer Science, vol 7778. Springer, Berlin, Heidelberg
	*     (https://eprint.iacr.org/2011/277.pdf).
	*
 	* Our PRE design and algorithms are informed by the design here:
 	*   - Polyakov, Yuriy, Kurt Rohloff, Gyana Sahu and Vinod Vaikuntanathan. Fast Proxy Re-Encryption for Publish/Subscribe Systems. Under Review in ACM Transactions on Privacy and Security (ACM TOPS).
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmPREBV : public LPPREAlgorithm<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmPREBV() {}

		/**
		* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
		* Variant that uses the new secret key directly.
		*
		* @param newKey new private key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
		*/
		shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPrivateKey<Element>> newKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const;

		/**
		* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
		* Variant that uses the public key for the new secret key.
		*
		* @param newKey public key for the new private key.
		* @param origPrivateKey original private key used for decryption.
		* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
		*/
		shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPublicKey<Element>> newKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
			std::string errMsg = "LPAlgorithmPREBV::ReKeyGen using a public key of the new secret key is not implemented for the BV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function to define the re-encryption method using the evaluation key generated by ReKeyGen
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return resulting ciphertext after the re-encryption operation.
		*/
		shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const;

	};

	/**
	 * @brief The multiparty homomorphic encryption capability for the BV scheme. A version of this multiparty scheme built on the BGV scheme is seen here:
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
	class LPAlgorithmMultipartyBV : public LPMultipartyAlgorithm<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmMultipartyBV() {}

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
	* @brief Concrete feature class for Leveled SHEBV operations. This class adds leveled (BGV scheme) features to the BV scheme.
	* 
	* We use advances from the BGV scheme for levelled homomorphic capabilities from here:
	*   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in LWE-Based Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds) Public-Key Cryptography – PKC 2013. Lecture Notes in Computer Science, vol 7778. Springer, Berlin, Heidelberg
	*     (https://eprint.iacr.org/2011/277.pdf).
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPLeveledSHEAlgorithmBV : public LPLeveledSHEAlgorithm<Element> {
	public:
		/**
		* Default constructor
		*/
		LPLeveledSHEAlgorithmBV() {}

		/**
		* Method for ModReducing CipherText.
		*
		* @param cipherText is the ciphertext to perform modreduce on.
		* @return ciphertext after the modulus reduction performed.
		*/
		virtual shared_ptr<Ciphertext<Element>> ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const;

		/**
		* Method for RingReducing CipherText. Not implemented for the BV/BGV scheme.
		*
		* @param cipherText is the ciphertext to perform ringreduce on.
		* @param keySwitchHint is the keyswitchhint to switch the ciphertext from original private key to a sparse private key.
		*/
		virtual shared_ptr<Ciphertext<Element>> RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const {

			std::string errMsg = "LPAlgorithmSHEBV::RindReduce is not currently implemented for the BV/BGV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Method for Composed EvalMult, which includes homomorphic multiplication, key switching, and modulo reduction. Not implemented for the BV/BGV scheme.
		*
		* @param cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
		* @param cipherText2 cipherText2, second input ciphertext to perform multiplication on.
		* @param quadKeySwitchHint is used for EvalMult operation.
		* @return resulting ciphertext.
		*/
		virtual shared_ptr<Ciphertext<Element>> ComposedEvalMult(
			const shared_ptr<Ciphertext<Element>> cipherText1,
			const shared_ptr<Ciphertext<Element>> cipherText2,
			const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const
		{
			std::string errMsg = "LPAlgorithmSHEBV::ComposedEvalMult is not currently implemented for the BV/BGV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
		* Not implemented for the BV/BGV scheme.
		*
		* @param cipherText1 is the original ciphertext to be key switched and mod reduced.
		* @param linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
		* @return resulting ciphertext.
		*/
		virtual shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
			const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const 
		{
			std::string errMsg = "LPAlgorithmSHEBV::LevelReduce is not currently implemented for the BV/BGV Scheme.";
			throw std::runtime_error(errMsg);
		}

		/**
		* Function that determines if security requirements are met if ring dimension is reduced by half.
		* Not implemented for the BV/BGV scheme.
		*
		* @param ringDimension is the original ringDimension
		* @param &moduli is the vector of moduli that is used
		* @param rootHermiteFactor is the security threshold
		* @return boolean value that determines if the ring is reducable.
		*/
		virtual bool CanRingReduce(usint ringDimension, const std::vector<BigInteger> &moduli, const double rootHermiteFactor) const
		{
			std::string errMsg = "LPAlgorithmSHEBV::CanRingReduce is not currently implemented for the BV/BGV Scheme.";
			throw std::runtime_error(errMsg);
		}
	};


	/**
	* @brief Main public key encryption scheme for the BV/BGV implementation
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeBV : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeBV() : LPPublicKeyEncryptionScheme<Element>() {}

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
