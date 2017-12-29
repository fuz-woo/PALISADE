/**
 * @file ltv.h -- Operations for the LTV cryptoscheme.
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
 * This code provides support for the LTV cryptoscheme.
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our design is informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
 *
 * Note that weaknesses have been discovered in this scheme and it should be used carefully.  Weaknesses come from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *   
 */

#ifndef LBCRYPTO_CRYPTO_LTV_H
#define LBCRYPTO_CRYPTO_LTV_H

#include "palisade.h"

namespace lbcrypto {

/**
 * @brief This is the parameters class for the LTV encryption scheme.  Note there have been recent advancements in the cryptanalysis of the LTV scheme, so parameters should be chosen with care.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 *  Parameters for this scheme are defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * @tparam Element a ring element type.
 */
template <class Element>
class LPCryptoParametersLTV: public LPCryptoParametersRLWE<Element> {
public:

	/**
	 * Default constructor
	 */
	LPCryptoParametersLTV() : LPCryptoParametersRLWE<Element>() {}

	/**
	 * Copy constructor.
	 * @param rhs - source
	 */
	LPCryptoParametersLTV(const LPCryptoParametersLTV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {}

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
	 * @param depth Depth is the depth of computation supprted which is set to 1 by default.  Use the default setting unless you're using SHE, levelled SHE or FHE operations.
	 */
	LPCryptoParametersLTV(
			shared_ptr<typename Element::Params> params,
			const PlaintextModulus &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			int depth = 1)
	: LPCryptoParametersRLWE<Element>(
			params,
			EncodingParams( new EncodingParamsImpl(plaintextModulus) ),
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {}

	/**
	* Constructor that initializes values.  Note that it is possible to set parameters in a way that is overall
	* infeasible for actual use.  There are fewer degrees of freedom than parameters provided.  Typically one
	* chooses the basic noise, assurance and security parameters as the typical community-accepted values,
	* then chooses the plaintext modulus and depth as needed.  The element parameters should then be choosen
	* to provide correctness and security.  In some cases we would need to operate over already
	* encrypted/provided ciphertext and the depth needs to be pre-computed for initial settings.
	*
	* @param &params Element parameters.  This will depend on the specific class of element being used.
	* @param &encodingParams Plaintext space parameters.
	* @param distributionParameter Noise distribution parameter, typically denoted as /sigma in most publications.  Community standards typically call for a value of 3 to 6. Lower values provide more room for computation while larger values provide more security.
	* @param assuranceMeasure Assurance level, typically denoted as w in most applications.  This is oftern perceived as a fudge factor in the literature, with a typical value of 9.
	* @param securityLevel Security level as Root Hermite Factor.  We use the Root Hermite Factor representation of the security level to better conform with US ITAR and EAR export regulations.  This is typically represented as /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less provides reasonable security for RLWE crypto schemes, although extra care is need for the LTV scheme because LTV makes an additional security assumption that make it suceptible to subfield lattice attacks.
	* @param relinWindow The size of the relinearization window.  This is relevant when using this scheme for proxy re-encryption, and the value is denoted as r in the literature.
	* @param depth Depth is the depth of computation supprted which is set to 1 by default.  Use the default setting unless you're using SHE, levelled SHE or FHE operations.
	*/
	LPCryptoParametersLTV(
		shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		int depth = 1)
		: LPCryptoParametersRLWE<Element>(
			params,
			encodingParams,
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {}

	/**
	 * Destructor
	 */
	virtual ~LPCryptoParametersLTV() {}

	/**
	 * Serialize the LTV Crypto Parameters using rapidJson representation.
	 *
	 * @param serObj RapidJson object for the serializaion
	 * @return True on success
	 */
	bool Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);
		if( this->SerializeRLWE(serObj, cryptoParamsMap) == false )
			return false;

		serObj->AddMember("LPCryptoParametersLTV", cryptoParamsMap.Move(), serObj->GetAllocator());
		serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersLTV", serObj->GetAllocator());

		return true;
	}

	/**
	 * Deserialize the LTV Crypto Parameters using rapidJson representation.
	 *
	 * @param serObj The serialized object to deserialize.
	 * @return True on success
	 */
	bool Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersLTV");
		if( mIter == serObj.MemberEnd() ) return false;

		return this->DeserializeRLWE(mIter);
	}

	/**
	 * == operator to compare to this instance of LPCryptoParametersLTV object.
	 *
	 * @param &rhs LPCryptoParameters to check equality against.
	 */
	bool operator==(const LPCryptoParameters<Element> &rhs) const {
		const LPCryptoParametersLTV<Element> *el = dynamic_cast<const LPCryptoParametersLTV<Element> *>(&rhs);

		if( el == 0 ) return false;
		return LPCryptoParametersRLWE<Element>::operator ==(rhs);
	}

	void PrintParameters(std::ostream& os) const {
		LPCryptoParametersRLWE<Element>::PrintParameters(os);
	}
};

/**
 * @brief Parameter generation for LTV.
 *
 * This is an implementation of the algorithm in the "Parameter Selection" section of
 * Rohloff & Cousins' "A Scalable Implementation of Fully Homomorphic Encryption Built on NTRU"
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmParamsGenLTV : public LPParameterGenerationAlgorithm<Element> {
public:

	/**
	 * Default constructor
	 */
	LPAlgorithmParamsGenLTV() {}

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
* @brief This is the algorithms class for the basic public key encrypt, decrypt and key generation methods for the LTV encryption scheme.  
 * Note there have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our algorithms are informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
*
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmLTV : public LPEncryptionAlgorithm<Element> {
public:

	/**
	 * Default Constructor
	 */
	LPAlgorithmLTV() {}

	/**
	 * Encrypt method for the LTV Scheme.  See the class description for citations on where the algorithms were
	 * taken from.
	 *
	 * @param publicKey The encryption key.
	 * @param plaintext copy of Plaintext to be encrypted.
	 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	 * @return A shared pointer to the encrypted Ciphertext.
	 */
	Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey, Element plaintext) const;

	/**
	 * Encrypt method for the LTV Scheme.  See the class description for citations on where the algorithms were
	 * taken from.
	 *
	 * @param privateKey The encryption key.
	 * @param plaintext Plaintext to be encrypted.
	 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	 * @return A shared pointer to the encrypted Ciphertext.
	 */
	Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey, Element plaintext) const;

	/**
	 * Decrypt method for the LTV Scheme.  See the class description for citations on where the algorithms were
	 * taken from.
	 *
	 * @param privateKey Decryption key.
	 * @param ciphertext Diphertext to be decrypted.
	 * @param plaintext Plaintext result of Decrypt operation.
	 * @return DecryptResult indicating success or failure and number of bytes decrypted.
	 */
	DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext,
		NativePoly *plaintext) const;

	/**
	 * Key Generation method for the LTV scheme.
	 * This method provides a "sparse" mode where all even indices are non-zero
	 * and odd indices are set to zero.  This sparse mode can be used to generate keys used for the LTV ring
	 * switching method.  We do not current support the generation of odd indices with even indices set to zero.
	 * See the class description for citations on where the algorithms were taken from.
	 *
	 * @param cc Drypto context in which to generate a key pair.
	 * @param makeSparse True to generate a sparse key pair.
	 * @return Public and private key pair.
	 */
	LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse = false);
};

/**
 * @brief This is the algorithms class for the Proxy Re-Encryption methods Re-Encryption Key Generation (ReKeyGen) and Re-Encryption (ReEncrypt) for the LTV encryption scheme.  
 * Note there have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This basic public key scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our PRE design and algorithms are informed by the design here:
 *   - Polyakov, Yuriy, Kurt Rohloff, Gyana Sahu and Vinod Vaikuntanathan. Fast Proxy Re-Encryption for Publish/Subscribe Systems. Under Review in ACM Transactions on Privacy and Security (ACM TOPS).
*
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmPRELTV : public LPPREAlgorithm<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmPRELTV() {}

	/**
	* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
	* This variant that uses the new secret key directly along with the original secret key.
	*
	* @param newKey new private key for the new ciphertext.
	* @param origPrivateKey original private key used for decryption.
	* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
	*/
	LPEvalKey<Element> ReKeyGen(const LPPrivateKey<Element> newKey,
		const LPPrivateKey<Element> origPrivateKey) const {
		std::string errMsg = "LPAlgorithmPRELTV::ReKeyGen using the new secret key is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
	* This variant that uses the new public key with the original secret key.
	*
	* @param newKey new private key for the new ciphertext.
	* @param origPrivateKey original private key used for decryption.
	* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
	*/
	LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
		const LPPrivateKey<Element> origPrivateKey) const;

	/**
	* Function to define the interface for re-encypting ciphertext using the array generated by ProxyGen.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param evalKey the evaluation key.
	* @param ciphertext the input ciphertext.
	* @return A shared pointer to the resulting ciphertext.
	*/
	Ciphertext<Element> ReEncrypt(const LPEvalKey<Element> evalKey,
		const Ciphertext<Element> ciphertext) const;
	
};

	/**
	 * @brief The multiparty homomorphic encryption capability is not implemented for this scheme yet.
	 *
	 * @tparam Element a ring element.
	 */
template <class Element>
class LPAlgorithmMultipartyLTV : public LPMultipartyAlgorithm<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmMultipartyLTV() {}

		/**
		* Function to generate public and private keys for multiparty homomrophic encryption in coordination with a leading client that generated a first public key.
		*
		* @param cc cryptocontext for the keys to be generated.
		* @param pk1 private key used for decryption to be fused.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
		* @param pre set to true if proxy re-encryption is used in multi-party protocol
		* @return key pair including the private and public key
		*/
	LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
		const LPPublicKey<Element> pk1,
		bool makeSparse=false,
		bool pre=false) {
		std::string errMsg = "LPAlgorithmPRELTV::MultipartyKeyGen using the new secret key is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}
	
		/**
		 * Method for main decryption operation run by most decryption clients for multiparty homomorphic encryption
		 *
		 * @param privateKey private key used for decryption.
		 * @param ciphertext ciphertext id decrypted.
		 */
	LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
		const vector<LPPrivateKey<Element>>& secretKeys,
		bool makeSparse=false) {
		std::string errMsg = "LPAlgorithmPRELTV::MultipartyKeyGen using the new secret key is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

		/**
		 * Method for decryption operation run by the lead decryption client for multiparty homomorphic encryption
		 *
		 * @param privateKey private key used for decryption.
		 * @param ciphertext ciphertext id decrypted.
		 */
	Ciphertext<Element> MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext) const {
		std::string errMsg = "LPAlgorithmPRELTV::MultipartyDecryptMain is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

		/**
		 * Method for fusing the partially decrypted ciphertext.
		 *
		 * @param &ciphertextVec ciphertext id decrypted.
		 * @param *plaintext the plaintext output.
		 * @return the decoding result.
		 */
	Ciphertext<Element> MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext) const {
		std::string errMsg = "LPAlgorithmPRELTV::MultipartyDecryptLead is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Method for decrypting plaintext using LTV
	*
	* @param &privateKey private key used for decryption.
	* @param &ciphertext1 ciphertext id decrypted.
	* @param &ciphertext2 ciphertext id decrypted.
	* @param *plaintext the plaintext output.
	* @return the success/fail result
	*/
	DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
		NativePoly *plaintext) const {
		std::string errMsg = "LPAlgorithmPREBGV::MultipartyDecrypt is not implemented for the BGV Scheme.";
		throw std::runtime_error(errMsg);
	}
};

/**
* @brief This is the algorithms class for the Somewhat Homomorphic Encryption methods for the LTV encryption scheme.  These methods include the standard EvalAdd, EvalMult, EvalSub operations.
 * Note there have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our algorithms are informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
*
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmSHELTV : public LPSHEAlgorithm<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmSHELTV() {}

	/**
	* Function for evaluation addition on ciphertext.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
	*/
	Ciphertext<Element> EvalAdd(const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2) const;

	/**
	* Function for evaluation addition on ciphertext.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext The input ciphertext.
	* @param plaintext The input plaintext.
	* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
	*/
	Ciphertext<Element> EvalAdd(const Ciphertext<Element> ciphertext,
		const Plaintext plaintext) const;

	/**
	* Function for homomorphic subtraction of ciphertexts.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
	*/
	Ciphertext<Element> EvalSub(const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2) const;

	/**
	* Function for homomorphic subtraction of ciphertexts.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext The input ciphertext.
	* @param plaintext The input plaintext.
	* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
	*/
	Ciphertext<Element> EvalSub(const Ciphertext<Element> ciphertext,
			const Plaintext plaintext) const;

	/**
	* Function for evaluating multiplication on ciphertext.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
	*/
	Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2) const;

	/**
	* Function for multiplying a ciphertext by plaintext.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext Input ciphertext.
	* @param plaintext input plaintext.
	* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
	*/
	Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext,
		const Plaintext plaintext) const;


	/**
	* Function for evaluating multiplication on ciphertext, but with a key switch performed after the
	* EvalMult using the Evaluation Key input.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @param evalKey The evaluation key input.
	* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
	*/
	Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2,
		const LPEvalKey<Element> evalKey) const;

	/**
	* Unimplemented function to support  a multiplication with depth larger than 2 for the LTV scheme.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @param ek is the evaluation keys input.
	* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
	*/
	Ciphertext<Element> EvalMultAndRelinearize(const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2,
		const vector<LPEvalKey<Element>> &ek) const {
		std::string errMsg = "LPAlgorithmLTV::EvalMultAndRelinearize is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Unimplemented function to support multiplication of a list of ciphertexts with depth larger than 2 for the LTV scheme.
	*
	* @param cipherTextList is the input ciphertexts.
	* @param evalKey is the evaluation keys input.
	* @return A shared pointer to the ciphertext which is the result of the multiplication.
	*/
	Ciphertext<Element> EvalMultMany(const vector<Ciphertext<Element>>& cipherTextList,
			const vector<LPEvalKey<Element>> &evalKeys) const {
		std::string errMsg = "LPAlgorithmLTV::EvalMultMany is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Function for homomorphic negation of ciphertexts.
	* At a high level, this operation substracts the plaintext value encrypted in the ciphertext from the
	* plaintext modulus p.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ct The input ciphertext.
	* @return A shared pointer to a new ciphertext which is the negation of the input.
	*/
	Ciphertext<Element> EvalNegate(const Ciphertext<Element> ct) const;
													 
	/**
	* Method for generating a Key Switch Hint.
	* See the class description for citations on where the algorithms were taken from.
	* This method generates a key switch hint which is not secure, even without the subfield lattice attacks.
	* We recommend that one uses key switch hints only for scenarios where security is not of critical 
	* importance.
	*
	* @param &k1 Original private key used for encryption.
	* @param &k2 New private key to generate the keyswitch hint.
	* @result A shared point to the resulting key switch hint.
	*/
	LPEvalKey<Element> KeySwitchGen(
		const LPPrivateKey<Element> k1,
		const LPPrivateKey<Element> k2) const;

	/**
	* Method for KeySwitching based on a KeySwitchHint.
	* See the class description for citations on where the algorithms were taken from.
	* This method uses a key switch hint which is not secure, even without the subfield lattice attacks.
	* We recommend that one uses key switch hints only for scenarios where security is not of critical 
	* importance.
	*
	* @param keySwitchHint Hint required to perform the ciphertext switching.
	* @param cipherText Original ciphertext to perform switching on.
	* @result A shared pointer to the resulting ciphertext.
	*/
	Ciphertext<Element> KeySwitch(
		const LPEvalKey<Element> keySwitchHint,
		const Ciphertext<Element> cipherText) const;

	/**
	* Method for KeySwitching based on RLWE relinearization.
	* Function to generate 1..log(q) encryptions for each bit of the original private key
	*
	* @param &newPublicKey encryption key for the new ciphertext.
	* @param origPrivateKey original private key used for decryption.
	*/
	LPEvalKey<Element> KeySwitchRelinGen(const LPPublicKey<Element> newPublicKey,
		const LPPrivateKey<Element> origPrivateKey) const;

	/**
	* Method for KeySwitching based on RLWE relinearization
	*
	* @param evalKey the evaluation key.
	* @param ciphertext the input ciphertext.
	* @return the resulting Ciphertext
	*/
	Ciphertext<Element> KeySwitchRelin(const LPEvalKey<Element> evalKey,
		const Ciphertext<Element> ciphertext) const;

	/**
	* Function to generate key switch hint on a ciphertext of depth 2.
	* This method uses a key switch hint which is not secure, even without the subfield lattice attacks.
	* We recommend that one uses key switch hints only for scenarios where security is not of critical 
	* importance.
	*
	* @param originalPrivateKey private key to start from.
	* @return resulting evalkeyswitch hint
	*/
	LPEvalKey<Element> EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const;

	/**
	* Function to generate key switch hint on a ciphertext of depth more than 2.
	* This method is not currently supported.
	* This method uses a key switch hint which is not secure, even without the subfield lattice attacks.
	*
	* @param originalPrivateKey private key to start from.
	* @return resulting evalkeyswitch hint
	*/
	vector<LPEvalKey<Element>> EvalMultKeysGen(const LPPrivateKey<Element> originalPrivateKey) const {
		std::string errMsg = "LPAlgorithmSHELTV::EvalMultKeysGen is not implemented for LTV SHE Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Function for evaluating automorphism of ciphertext at index i
	*
	* @param ciphertext the input ciphertext.
	* @param i automorphism index
	* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalAutomorphism(const Ciphertext<Element> ciphertext, usint i,
		const std::map<usint, LPEvalKey<Element>> &evalKeys) const;


	/**
	* Generate automophism keys for a given private key; Uses the private key for encryption.  This method is not currently supported.
	*
	* @param privateKey private key.
	* @param indexList list of automorphism indices to be computed
	* @return returns the evaluation keys
	*/
	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<usint> &indexList) const {
		std::string errMsg = "LPAlgorithmSHELTV::EvalAutomorphismKeyGen is not implemented for LTV SHE Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Generate automophism keys for a given private key; Uses the public key for encryption
	*
	* @param publicKey public key.
	* @param privateKey private key.
	* @param indexList list of automorphism indices to be computed
	* @return returns the evaluation keys
	*/
	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
		const LPPrivateKey<Element> privateKey, const std::vector<usint> &indexList) const;

};

/**
* @brief This is the concrete class for the leveled version of the LTV encryption scheme, and it includes methods not included in the LPAlgorithmSHELTV. This methods include RingReduce, ModReduce, ComposedEvalMult, LevelReduce, CanRingReduce.
 *
 * There have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our algorithms are informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
*
* @tparam Element a ring element.
*/
template <class Element>
class LPLeveledSHEAlgorithmLTV : public LPLeveledSHEAlgorithm<Element> {
public:
	/**
	* Default constructor
	*/
	LPLeveledSHEAlgorithmLTV() {}

	/**
	* Method for ModReducing CipherText
	*
	* @param cipherText Ciphertext to perform and apply modreduce on.
	* @return resulting modreduced ciphertext
	*/
	Ciphertext<Element> ModReduce(Ciphertext<Element> cipherText) const;

	/**
	* Method for RingReducing CipherText and the Private Key used for encryption.
	*
	* @param cipherText Ciphertext to perform and apply ringreduce on.
	* @param keySwitchHint is the keyswitchhint from the ciphertext's private key to a sparse key
	* @return resulting RingReduced ciphertext
	*/
	Ciphertext<Element> RingReduce(Ciphertext<Element> cipherText, const LPEvalKey<Element> keySwitchHint) const;

	/**
	* Method for ComposedEvalMult.  This method performs an EvalMult on two input ciphertext, then a
	* modululus reduction and a key switch on the result.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param cipherText1 The first input ciphertext to perform multiplication on.
	* @param cipherText2 THe second input ciphertext to perform multiplication on.
	* @param quadKeySwitchHint The resultant quadratic secret key after multiplication to the secret key of the particular level.
	* @return The resulting ciphertext that can be decrypted with the secret key of the particular level.
	*/
	Ciphertext<Element> ComposedEvalMult(
		const Ciphertext<Element> cipherText1,
		const Ciphertext<Element> cipherText2,
		const LPEvalKey<Element> quadKeySwitchHint) const;

	/**
	* Method for Level Reduction from sk -> sk1. 
	* This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
	*
	* @param cipherText1 is the original ciphertext to be key switched and mod reduced.
	* @param linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
	* @return the resulting ciphertext.
	*/
	Ciphertext<Element> LevelReduce(const Ciphertext<Element> cipherText1,
		const LPEvalKey<Element> linearKeySwitchHint) const;

	/**
	* Function that determines if security requirements are met if ring dimension is reduced by half.
	* This method is useful for testing if a ring reduction can be performed on a ciphertext without violating
	* a security boundary for the parameter setting.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ringDimension The original ringDimension.
	* @param &moduli The vector of moduli that is used.
	* @param rootHermiteFactor The security threshold.
	* @return True if the security threshold is satisfied in the new ring dimension.
	*/
	bool CanRingReduce(usint ringDimension, const std::vector<BigInteger> &moduli, const double rootHermiteFactor) const;
};

/**
* @brief This is the algorithms class for to enable deatures for an LTV encryption scheme, notably public key encryption, proxy re-encryption, somewhat homomorphic encryption and/or fully homomorphic encryption. 
 *
 * There have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our algorithms are informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
*
* @tparam Element a ring element.
*/
template <class Element>
class LPPublicKeyEncryptionSchemeLTV : public LPPublicKeyEncryptionScheme<Element> {
public:
	/**
	* Inherited constructor
	*/
	LPPublicKeyEncryptionSchemeLTV() : LPPublicKeyEncryptionScheme<Element>() {
		this->m_algorithmParamsGen = new LPAlgorithmParamsGenLTV<Element>();
	}

	bool operator==(const LPPublicKeyEncryptionScheme<Element>& sch) const {
		if( dynamic_cast<const LPPublicKeyEncryptionSchemeLTV<Element> *>(&sch) == 0 )
			return false;
		return true;
	}

	/**
	* Enable. Allows a particular feature set to be used
	*
	*@param feature code for the feature to enable
	*/
	void Enable(PKESchemeFeature feature);
};

}

#endif
