/**
 * @file bfvrnsB.h -- Operations for the BEHZ variant of BFV.
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
 * This code implements the BEHZ variant of the Brakerski-Fan-Vercauteren (BFV) homomorphic encryption scheme.  This scheme is also referred to as the FV scheme.
 *
 * The BFV scheme is introduced in the following papers:
 *   - Zvika Brakerski (2012). Fully Homomorphic Encryption without Modulus Switching from Classical GapSVP. Cryptology ePrint Archive, Report 2012/078. (https://eprint.iacr.org/2012/078)
 *   - Junfeng Fan and Frederik Vercauteren (2012). Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 *
 * Our implementation builds from the designs here:
 *	 - Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent Zucca (2016). A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes. Cryptology ePrint Archive, Report 2016/510. (https://eprint.iacr.org/2016/510)
 *   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 *   - Ahmad Al Badawi and Yuriy Polyakov and Khin Mi Mi Aung and Bharadwaj Veeravalli and Kurt Rohloff (2018). Implementation and Performance Evaluation of RNS Variants of the BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report 2018/589. {https://eprint.iacr.org/2018/589}
 *
  */

#ifndef LBCRYPTO_CRYPTO_BFVRNS_B_H
#define LBCRYPTO_CRYPTO_BFVRNS_B_H

#include "palisade.h"

namespace lbcrypto {

	/**
 	* @brief This is the parameters class for the BFVrnsB encryption scheme.  This scheme is also referred to as the FVrns scheme.
 	*
 	* @tparam Element a ring element type.
 	*/
	template <class Element>
	class LPCryptoParametersBFVrnsB : public LPCryptoParametersRLWE<Element> {

		public:
			/**
			 * Default constructor.
			 */
			LPCryptoParametersBFVrnsB();

			/**
		 	 * Copy constructor.
	 		 * @param rhs - source
			 */
			LPCryptoParametersBFVrnsB(const LPCryptoParametersBFVrnsB &rhs);
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
			 * @param mode optimization setting (RLWE vs OPTIMIZED)
			 * @param depth is the depth of computation circuit supported for these parameters (not used now; for future use).
			 * @param maxDepth is the maximum homomorphic multiplication depth before performing relinearization
			 */
			LPCryptoParametersBFVrnsB(shared_ptr<typename Element::Params> params,
				const PlaintextModulus &plaintextModulus,
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				MODE mode = RLWE,
				int depth = 1,
				int maxDepth = 2);

			/**
			* Constructor that initializes values.
			*
			* @param &params element parameters.
			* @param &encodingParams plaintext space parameters.
			* @param distributionParameter noise distribution parameter.
			* @param assuranceMeasure assurance level. = BigInteger::ZERO
			* @param securityLevel security level (root Hermite factor).
			* @param relinWindow the size of the relinearization window.
			* @param mode optimization setting (RLWE vs OPTIMIZED)
			* @param depth is the depth of computation circuit supported for these parameters (not used now; for future use).
			* @param maxDepth is the maximum homomorphic multiplication depth before performing relinearization
			*/
			LPCryptoParametersBFVrnsB(shared_ptr<typename Element::Params> params,
				EncodingParams encodingParams,
				float distributionParameter,
				float assuranceMeasure,
				float securityLevel,
				usint relinWindow,
				MODE mode = RLWE,
				int depth = 1,
				int maxDepth = 2);

			/**
			* Constructor that initializes values.
			*
			* @param &params element parameters.
			* @param &encodingParams plaintext space parameters.
			* @param distributionParameter noise distribution parameter.
			* @param assuranceMeasure assurance level. = BigInteger::ZERO
			* @param securityLevel standard security level
			* @param relinWindow the size of the relinearization window.
			* @param mode optimization setting (RLWE vs OPTIMIZED)
			* @param depth is the depth of computation circuit supported for these parameters (not used now; for future use).
			* @param maxDepth is the maximum homomorphic multiplication depth before performing relinearization
			*/
			LPCryptoParametersBFVrnsB(shared_ptr<typename Element::Params> params,
				EncodingParams encodingParams,
				float distributionParameter,
				float assuranceMeasure,
				SecurityLevel securityLevel,
				usint relinWindow,
				MODE mode = RLWE,
				int depth = 1,
				int maxDepth = 2);

			/**
			* Destructor
			*/
			virtual ~LPCryptoParametersBFVrnsB() {}
			
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
			* Computes all tables needed for decryption, homomorphic multiplication, and key switching
			* @return true on success
			*/
			bool PrecomputeCRTTables();

			/**
			* == operator to compare to this instance of LPCryptoParametersBFVrnsB object.
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersBFVrnsB<Element> *el = dynamic_cast<const LPCryptoParametersBFVrnsB<Element> *>(&rhs);

				if( el == 0 ) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}

			void PrintParameters(std::ostream& os) const {
				LPCryptoParametersRLWE<Element>::PrintParameters(os);
			}

			/**
			* Gets the precomputed table of floor(Q/p) mod qi
			*
			* @return the precomputed table
			*/
			const std::vector<NativeInteger>& GetCRTDeltaTable() const { return m_CRTDeltaTable; }

			// BFVrnsB getters and setters
			const shared_ptr<ILDCRTParams<BigInteger>> GetDCRTParamsBsk() const { return m_paramsBsk; }

			std::vector<NativeInteger> const &GetDCRTParamsqModuli() const { return m_qModuli; }

			std::vector<DoubleNativeInteger> const &GetDCRTParamsqModulimu() const { return m_qModulimu; }

			std::vector<NativeInteger> const &GetDCRTParamsBskModuli() const { return m_BskModuli; }

			std::vector<DoubleNativeInteger> const &GetDCRTParamsBskModulimu() const { return m_BskModulimu; }

			NativeInteger const &GetDCRTParamsmtilde() const { return m_mtilde; }

			std::vector<NativeInteger> const &GetDCRTParamsBskmtildeModuli() const { return m_BskmtildeModuli; }

			std::vector<DoubleNativeInteger> const &GetDCRTParamsBskmtildeModulimu() const { return m_BskmtildeModulimu; }

			std::vector<NativeInteger> const &GetDCRTParamsmtildeqDivqiModqi() const { return m_mtildeqDivqiTable; }

			std::vector<NativeInteger> const &GetDCRTParamsmtildeqDivqiModqiPrecon() const { return m_mtildeqDivqiPreconTable; }

			std::vector<std::vector<NativeInteger>> const &GetDCRTParamsqDivqiModBskmtilde() const { return m_qDivqiModBskmtildeTable; }

			std::vector<NativeInteger> const &GetDCRTParamsqModBski() const { return m_qModBskiTable; }

			std::vector<NativeInteger> const &GetDCRTParamsqModBskiPrecon() const { return m_qModBskiPreconTable; }

			NativeInteger const &GetDCRTParamsnegqInvModmtilde() const { return m_negqInvModmtilde; }

			NativeInteger const &GetDCRTParamsnegqInvModmtildePrecon() const { return m_negqInvModmtildePrecon; }

			std::vector<NativeInteger> const &GetDCRTParamsmtildeInvModBskiTable() const { return m_mtildeInvModBskiTable; }

			std::vector<NativeInteger> const &GetDCRTParamsmtildeInvModBskiPreconTable() const { return m_mtildeInvModBskiPreconTable; }

			std::vector<NativeInteger> const &GetDCRTParamsqDivqiModqiTable() const { return m_qDivqiModqiTable; }

			std::vector<NativeInteger> const &GetDCRTParamstqDivqiModqiTable() const { return m_tqDivqiModqiTable; }

			std::vector<NativeInteger> const &GetDCRTParamstqDivqiModqiPreconTable() const { return m_tqDivqiModqiPreconTable; }

			std::vector<NativeInteger> const &GetDCRTParamstgammaqDivqiModqiTable() const { return m_tgammaqDivqiModqiTable; }

			std::vector<NativeInteger> const &GetDCRTParamstgammaqDivqiModqiPreconTable() const { return m_tgammaqDivqiModqiPreconTable; }

			std::vector<NativeInteger> const &GetDCRTParamsqInvModBiTable() const { return m_qInvModBskiTable; }

			std::vector<NativeInteger> const &GetDCRTParamsqInvModBiPreconTable() const { return m_qInvModBskiPreconTable; }

			std::vector<NativeInteger> const &GetBDivBiModBi() const { return m_BDivBiModBiTable; }

			std::vector<NativeInteger> const &GetBDivBiModBiPrecon() const { return m_BDivBiModBiPreconTable; }

			std::vector<NativeInteger> const &GetBDivBiModmsk() const { return m_BDivBiModmskTable; }

			NativeInteger const &GetBInvModmsk() const { return m_BInvModmsk; }

			NativeInteger const &GetBInvModmskPrecon() const { return m_BInvModmskPrecon; }

			std::vector<std::vector<NativeInteger>> const &GetBDivBiModqj() const { return m_BDivBiModqTable; }

			std::vector<NativeInteger> const &GetBModqi() const { return m_BModqiTable; }

			std::vector<NativeInteger> const &GetBModqiPrecon() const { return m_BModqiPreconTable; }

			NativeInteger const &GetDCRTParamsgamma() const { return m_gamma; }

			NativeInteger const &GetDCRTParamsgammaInvModt() const { return m_gammaInvModt; }

			NativeInteger const &GetDCRTParamsgammaInvModtPrecon() const { return m_gammaInvModtPrecon; }

			std::vector<NativeInteger> const &GetDCRTParamsnegqInvModtgammaTable() const { return m_negqInvModtgammaTable; }

			std::vector<NativeInteger> const &GetDCRTParamsnegqInvModtgammaPreconTable() const { return m_negqInvModtgammaPreconTable; }

			std::vector<std::vector<NativeInteger>> const &GetDCRTParamsqDivqiModtgammaTable() const { return m_qDivqiModtgammaTable; }

			std::vector<std::vector<NativeInteger>> const &GetDCRTParamsqDivqiModtgammaPreconTable() const { return m_qDivqiModtgammaPreconTable; }

		private:

			// Stores a precomputed table of floor(Q/p) mod qi
			std::vector<NativeInteger> m_CRTDeltaTable;

			// Precomputed tables of Bajard et al. BFVrns variant (we call it BFVrnsB )
			// naming convention:
			// 1) let RNS base q = {q0, q1, ..., q(k-1)}, then q is used to refer to the RNS base or its dynamic value which is equal to q = q0*q1*...*q(k-1)

			// EvalMulRNS parameters

			// 1)
			shared_ptr<ILDCRTParams<BigInteger>> m_paramsBsk;

			// 2) number of moduli in the ciphertext coefficient base (q)
			uint32_t m_numq;

			// 3) number of moduli in the auxilliary base (B)
			uint32_t m_numB;

			// 4) mtilde
			NativeInteger m_mtilde;

			// 5) msk
			NativeInteger m_msk;

			// 6) Stores the crt moduli of base B (size of B moduli is chosen such that )
			std::vector<NativeInteger> m_qModuli;
			std::vector<DoubleNativeInteger> m_qModulimu;

			// 7) Stores the auxilliary base B moduli
			std::vector<NativeInteger> m_BModuli;

			// 8) Stores the roots of unity modulo Bsk
			std::vector<NativeInteger> m_BskRoots;

			// 9) Stores the crt moduli of base Bsk = {B U msk}
			std::vector<NativeInteger> m_BskModuli;
			std::vector<DoubleNativeInteger> m_BskModulimu;

			// 10) Stores the crt moduli of base Bskmtilde = {Bsk U mtilde}
			std::vector<NativeInteger> m_BskmtildeModuli;
			std::vector<DoubleNativeInteger> m_BskmtildeModulimu; // Barrett constant

			// 11) Stores (q/qi)^-1 mod qi
			std::vector<NativeInteger> m_qDivqiModqiTable;

			// 12) Stores t*(q/qi)^-1 mod qi
			std::vector<NativeInteger> m_tqDivqiModqiTable;
			std::vector<NativeInteger> m_tqDivqiModqiPreconTable;

			// 13) Stores q/qi mod Bj table (Matrix) where Bj \in {Bsk U mtilde}
			std::vector<std::vector<NativeInteger>> m_qDivqiModBskmtildeTable;

			// 14) Stores mtilde*(q/qi)^-1 mod qi table
			std::vector<NativeInteger> m_mtildeqDivqiTable;
			std::vector<NativeInteger> m_mtildeqDivqiPreconTable;

			// 15) Stores -1/q mod mtilde
			NativeInteger m_negqInvModmtilde;
			NativeInteger m_negqInvModmtildePrecon;

			// 16) Stores q mod Bski
			std::vector<NativeInteger> m_qModBskiTable;
			std::vector<NativeInteger> m_qModBskiPreconTable;

			// 17) Stores mtilde^-1 mod Bski
			std::vector<NativeInteger> m_mtildeInvModBskiTable;
			std::vector<NativeInteger> m_mtildeInvModBskiPreconTable;

			// 18) Stores q^-1 mod Bski
			std::vector<NativeInteger> m_qInvModBskiTable;
			std::vector<NativeInteger> m_qInvModBskiPreconTable;

			// 19) Stores (B/Bi)^-1 mod Bi
			std::vector<NativeInteger> m_BDivBiModBiTable;
			std::vector<NativeInteger> m_BDivBiModBiPreconTable;

			// 20) Stores B/Bi mod qj table (Matrix) where qj \in {q}
			std::vector<std::vector<NativeInteger>> m_BDivBiModqTable;

			// 21) stores B/Bi mod msk
			std::vector<NativeInteger> m_BDivBiModmskTable;

			// 22) Stores B^-1 mod msk
			NativeInteger m_BInvModmsk;
			NativeInteger m_BInvModmskPrecon;

			// 23) Stores B mod qi
			std::vector<NativeInteger> m_BModqiTable;
			std::vector<NativeInteger> m_BModqiPreconTable;

			// DecRNS parameters

			// 24) Stores gamma
			NativeInteger m_gamma;

			// 25) Stores gamma^-1 mod t
			NativeInteger m_gammaInvModt;
			NativeInteger m_gammaInvModtPrecon;

			// 26) Stores -1/q mod {t U gamma}
			std::vector<NativeInteger> m_negqInvModtgammaTable;
			std::vector<NativeInteger> m_negqInvModtgammaPreconTable;

			// 27) Stores q/qi mod mj table (matrix) where mj \in {t U gamma}
			std::vector<std::vector<NativeInteger>> m_qDivqiModtgammaTable;
			std::vector<std::vector<NativeInteger>> m_qDivqiModtgammaPreconTable;

			// 28) Stores (t*gamma*q/qi)^-1 mod qi
			std::vector<NativeInteger> m_tgammaqDivqiModqiTable;
			std::vector<NativeInteger> m_tgammaqDivqiModqiPreconTable;
	};

	/**
	* @brief Parameter generation for BFVrnsB.  This scheme is also referred to as the FV scheme.
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmParamsGenBFVrnsB : public LPAlgorithmParamsGenBFV<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmParamsGenBFVrnsB() {}

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		*/
		bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0, size_t dcrBits = 60) const;

	};

	/**
	* @brief Encryption algorithm implementation for BFVrnsB for the basic public key encrypt, decrypt and
	* key generation methods for the BFVrnsB encryption scheme.
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmBFVrnsB : public LPAlgorithmBFV<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmBFVrnsB() {}

		/**
		* Method for encrypting plaintext using BFVrnsB.
		*
		* @param publicKey public key used for encryption.
		* @param &plaintext the plaintext input.
		* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
		* @return ciphertext which results from encryption.
		*/
		Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
			Element plaintext) const;

		/**
		* Method for encrypting plaintext with private key using BFVrnsB.
		*
		* @param privateKey private key used for encryption.
		* @param plaintext the plaintext input.
		* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
		* @return ciphertext which results from encryption.
		*/
		Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
			Element plaintext) const;

		/**
		* Method for decrypting using BFVrnsB. See the class description for citations on where the algorithms were
	 	* taken from.
		*
		* @param privateKey private key used for decryption.
		* @param ciphertext ciphertext to be decrypted.
		* @param *plaintext the plaintext output.
		* @return the decrypted plaintext returned.
		*/
		DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
			ConstCiphertext<Element> ciphertext,
			NativePoly *plaintext) const;


	};

	/**
	* @brief SHE algorithms implementation for BFVrnsB.
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmSHEBFVrnsB : public LPAlgorithmSHEBFV<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmSHEBFVrnsB() {}

		/**
		* Function for homomorphic addition of ciphertext and plaintext.
		*
		* @param ct1 input ciphertext.
		* @param pt  input ciphertext.
		* @return new ciphertext.
		*/
		Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ct,
			ConstPlaintext pt) const;

		/**
		* Function for homomorphic subtraction of ciphertext ans plaintext.
		*
		* @param ct input ciphertext.
		* @param pt input ciphertext.
		* @return new ciphertext.
		*/
		Ciphertext<Element> EvalSub(ConstCiphertext<Element> ct,
			ConstPlaintext pt) const;

		/**
		* Function for homomorphic evaluation of ciphertexts.
		* The multiplication is supported for a fixed level without keyswitching requirement (default level=2).
		* If the total depth of the ciphertexts exceeds the supported level, it throws an error.
		*
		* @param ciphertext1 first input ciphertext.
		* @param ciphertext2 second input ciphertext.
		* @return resulting EvalMult ciphertext.
		*/
		Ciphertext<Element> EvalMult(ConstCiphertext<Element> ct1,
				ConstCiphertext<Element> ct2) const;

		/**
		* Method for generating a KeySwitchHint using RLWE relinearization
		*
		* @param originalPrivateKey Original private key used for encryption.
		* @param newPrivateKey New private key to generate the keyswitch hint.
		* @return resulting keySwitchHint.
		*/
		LPEvalKey<Element> KeySwitchGen(const LPPrivateKey<Element> originalPrivateKey,
			const LPPrivateKey<Element> newPrivateKey) const;

		/**
		* Method for key switching based on a KeySwitchHint using RLWE relinearization
		*
		* @param keySwitchHint Hint required to perform the ciphertext switching.
		* @param &cipherText Original ciphertext to perform switching on.
		* @return new ciphertext
		*/
		Ciphertext<Element> KeySwitch(const LPEvalKey<Element> keySwitchHint,
			ConstCiphertext<Element> cipherText) const;

		/**
		* Function for evaluating multiplication on ciphertext followed by relinearization operation.
		* Currently it assumes that the input arguments have total depth smaller than the supported depth. Otherwise, it throws an error.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext
		*  decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @return new ciphertext
		*/
		Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ct1,
			ConstCiphertext<Element> ct, const vector<LPEvalKey<Element>> &ek) const;


	};

	/**
	* @brief PRE algorithms implementation for BFVrnsB.
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmPREBFVrnsB : public LPAlgorithmPREBFV<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmPREBFVrnsB() {}


	};


	/**
	 * @brief Concrete class for the FHE Multiparty algorithms on BFVrnsB.    This scheme is also referred to as the FV scheme.  A version of this multiparty scheme built on the BGV scheme is seen here:
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
	class LPAlgorithmMultipartyBFVrnsB : public LPAlgorithmMultipartyBFV<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmMultipartyBFVrnsB() {}

		/**
		 * Method for fusing the partially decrypted ciphertext.
		 *
		 * @param &ciphertextVec ciphertext id decrypted.
		 * @param *plaintext the plaintext output.
		 * @return the decoding result.
		 */
		DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
			NativePoly *plaintext) const;


	};


	/**
	* @brief Main public key encryption scheme for BFVrnsB implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeBFVrnsB : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeBFVrnsB();

		bool operator==(const LPPublicKeyEncryptionScheme<Element>& sch) const {
			if( dynamic_cast<const LPPublicKeyEncryptionSchemeBFVrnsB<Element> *>(&sch) == 0 )
				return false;
			return true;
		}

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
