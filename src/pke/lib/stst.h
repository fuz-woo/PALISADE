/**
 * @file stst.h -- definitions for StehleSteinfeld Crypto Params
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
 * This code provides support for the Stehle-Steinfeld cryptoscheme.
 *
 * Our Stehle-Steinfeld scheme implementation is described here:
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publish–Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * This scheme is based on the subfield lattice attack immunity condition proposed in the Conclusions section here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *
 */

#ifndef LBCRYPTO_CRYPTO_STST_H
#define LBCRYPTO_CRYPTO_STST_H

#include "palisade.h"

namespace lbcrypto {

	//forward declarations
	template <class Element>
	class LPAlgorithmLTV;

	template <class Element>
	class LPPublicKeyEncryptionSchemeLTV;

	template <class Element>
	class LPAlgorithmPRELTV;

	template <class Element>
	class LPAlgorithmSHELTV;

/**
 * @brief This is the parameters class for the Stehle-Stenfeld encryption scheme.
 *
 *  Parameters for this scheme are defined here:
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publish–Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * @tparam Element a ring element type.
 */
template <class Element>
class LPCryptoParametersStehleSteinfeld : public LPCryptoParametersRLWE<Element> {
public:
	/**
	 * Default constructor.  This constructor initializes all values to 0.
	 */
	LPCryptoParametersStehleSteinfeld() : LPCryptoParametersRLWE<Element>() {
		m_distributionParameterStSt = 0.0f;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * Copy constructor.
	 *
	 * @param rhs - source
	 */
	LPCryptoParametersStehleSteinfeld(const LPCryptoParametersStehleSteinfeld &rhs) : LPCryptoParametersRLWE<Element>(rhs) {
		m_distributionParameterStSt = rhs.m_distributionParameterStSt;
		m_dggStSt.SetStd(m_distributionParameterStSt);
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
	 * @param depth Depth is the depth of computation supprted which is set to 1 by default.  Use the default setting unless you're using SHE, levelled SHE or FHE operations.
	 */
	LPCryptoParametersStehleSteinfeld(
			shared_ptr<typename Element::Params> params,
			const PlaintextModulus &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			float distributionParmStst,
			int depth = 1)
	: LPCryptoParametersRLWE<Element>(params,
			EncodingParams( new EncodingParamsImpl(plaintextModulus) ),
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {
		m_distributionParameterStSt = distributionParmStst;
		m_dggStSt.SetStd(m_distributionParameterStSt);
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
	* @param &encodingParams Plaintext space parameters.
	* @param distributionParameter Noise distribution parameter, typically denoted as /sigma in most publications.  Community standards typically call for a value of 3 to 6. Lower values provide more room for computation while larger values provide more security.
	* @param assuranceMeasure Assurance level, typically denoted as w in most applications.  This is oftern perceived as a fudge factor in the literature, with a typical value of 9.
	* @param securityLevel Security level as Root Hermite Factor.  We use the Root Hermite Factor representation of the security level to better conform with US ITAR and EAR export regulations.  This is typically represented as /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less provides reasonable security for RLWE crypto schemes, although extra care is need for the LTV scheme because LTV makes an additional security assumption that make it suceptible to subfield lattice attacks.
	* @param relinWindow The size of the relinearization window.  This is relevant when using this scheme for proxy re-encryption, and the value is denoted as r in the literature.
	* @param depth Depth is the depth of computation supprted which is set to 1 by default.  Use the default setting unless you're using SHE, levelled SHE or FHE operations.
	*/
	LPCryptoParametersStehleSteinfeld(
		shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		float distributionParmStst,
		int depth = 1)
		: LPCryptoParametersRLWE<Element>(params,
			encodingParams,
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {
		m_distributionParameterStSt = distributionParmStst;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * Returns the value of standard deviation r for discrete Gaussian distribution used in Key Generation
	 *
	 * @return the standard deviation r.
	 */
	float GetDistributionParameterStSt() const {return m_distributionParameterStSt;}

	/**
	 * Returns reference to Discrete Gaussian Generator for keys
	 *
	 * @return reference to Discrete Gaussian Generaror.
	 */
	const typename Element::DggType &GetDiscreteGaussianGeneratorStSt() const {return m_dggStSt;}

	//@Set Properties

	/**
	 * Sets the value of standard deviation r for discrete Gaussian distribution
	 *
	 * @param distributionParameterStSt distribution parameter r.
	 */
	void SetDistributionParameterStSt(float distributionParameterStSt) {
		m_distributionParameterStSt = distributionParameterStSt;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);
		if( this->SerializeRLWE(serObj, cryptoParamsMap) == false )
			return false;

		cryptoParamsMap.AddMember("DistributionParameterStSt", std::to_string(this->GetDistributionParameterStSt()), serObj->GetAllocator());

		serObj->AddMember("LPCryptoParametersStehleSteinfeld", cryptoParamsMap.Move(), serObj->GetAllocator());
		serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersStehleSteinfeld", serObj->GetAllocator());

		return true;
	}

	/**
	 * Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersStehleSteinfeld");
		if( mIter == serObj.MemberEnd() ) return false;

		if( this->DeserializeRLWE(mIter) == false )
			return false;

		SerialItem::ConstMemberIterator pIt;
		if( (pIt = mIter->value.FindMember("DistributionParameterStSt")) == mIter->value.MemberEnd() )
			return false;
		float distributionParameterStSt = atof(pIt->value.GetString());
		this->SetDistributionParameterStSt(distributionParameterStSt);
		return true;
	}

	/**
	 * == operator to compare to this instance of LPCryptoParametersStehleSteinfeld object.
	 *
	 * @param &rhs LPCryptoParameters to check equality against.
	 */
	bool operator==(const LPCryptoParameters<Element>& cmp) const {
		const LPCryptoParametersStehleSteinfeld<Element> *el = dynamic_cast<const LPCryptoParametersStehleSteinfeld<Element> *>(&cmp);

		if( el == 0 ) return false;

		return  LPCryptoParametersRLWE<Element>::operator==( cmp ) &&
				m_distributionParameterStSt == el->GetDistributionParameterStSt();
	}

	void PrintParameters(std::ostream& os) const {
		LPCryptoParametersRLWE<Element>::PrintParameters(os);

		os << " StSt distribution parm: " << m_distributionParameterStSt;
	}

private:
	//standard deviation in Discrete Gaussian Distribution used for Key Generation
	float m_distributionParameterStSt;
	//Discrete Gaussian Generator for Key Generation
	typename Element::DggType m_dggStSt;
};

/**
 * @brief This is the algorithms class for the basic public key encrypt, decrypt and key generation methods for the Stehle-Stenfeld scheme encryption scheme.  
 *
 * Our Stehle-Steinfeld scheme implementation is described here:
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publish–Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * This scheme is based on the subfield lattice attack immunity condition proposed in the Conclusions section here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
*
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmStSt : public LPAlgorithmLTV<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmStSt() : LPAlgorithmLTV<Element>() {};

	/**
	 * Key Generation method for the StehleSteinfeld scheme.
	 * This method provides a "sparse" mode where all even indices are non-zero
	 * and odd indices are set to zero.  This sparse mode can be used to generate keys used for the LTV ring
	 * switching method.  We do not current support the generation of odd indices with even indices set to zero.
	 * See the class description for citations on where the algorithms were taken from.
	 *
	 * @param cc Drypto context in which to generate a key pair.
	 * @param makeSparse True to generate a saprse key pair.
	 * @return Public and private key pair.
	 */
	LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse=false) { 		//makeSparse is not used

		LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));

		const shared_ptr<LPCryptoParametersStehleSteinfeld<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersStehleSteinfeld<Element>>(cc->GetCryptoParameters());

		const auto &p = cryptoParams->GetPlaintextModulus();

		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGeneratorStSt();

		Element f(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);

		f = p*f;

		f = f + 1;

		f.SwitchFormat();

		//check if inverse does not exist
		while (!f.InverseExists())
		{
			//std::cout << "inverse does not exist" << std::endl;
			Element temp(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);
			f = temp;
			f = p*f;
			f = f + 1;
			f.SwitchFormat();
		}

		kp.secretKey->SetPrivateElement(f);

		Element g(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);

		g.SwitchFormat();

		//public key is generated
		kp.publicKey->SetPublicElementAtIndex(0, cryptoParams->GetPlaintextModulus()*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse());

		return kp;
	}
};

template <class Element>
class LPAlgorithmSHEStSt : public LPAlgorithmSHELTV<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmSHEStSt() : LPAlgorithmSHELTV<Element>() {};
	/**
	* Unimplemented function to generate an evaluation key for the Stehle-Steinfeld scheme. 
	* EvalMult is currently unsopported in the Stehle-Steinfeld scheme and there is no currently known method to 
	* support EvalMult in the Stehle-Steinfeld scheme.
	*
	* @param originalPrivateKey private key to start from when key switching.
	* @return resulting evalkeyswitch hint
	*/
	LPEvalKey<Element> EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const {
		std::string errMsg = "LPAlgorithmStSt::EvalMultKeyGen is not implemented for the Stehle-Steinfeld Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Unimplemented function to generate an evaluation key for the Stehle-Steinfeld scheme.
	*
	* @param originalPrivateKey private key to start from when key switching.
	* @return resulting evalkeyswitch hint
	*/
	vector<LPEvalKey<Element>> EvalMultKeysGen(const LPPrivateKey<Element> originalPrivateKey) const {
		std::string errMsg = "LPAlgorithmStSt::EvalMultKeysGen is not implemented for the Stehle-Steinfeld Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Unimplemented function to support  a multiplication with depth larger than 2 for the Stehle-Steinfeld scheme.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @param evalKey The evaluation key input.
	* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
	*/
	Ciphertext<Element> EvalMultAndRelinearize(const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2,
		const vector<LPEvalKey<Element>> &ek) const {
		std::string errMsg = "LPAlgorithmStSt::EvalMultAndRelinearize is not implemented for the Stehle-Steinfeld Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Unimplemented function to generate an evaluation key for the Stehle-Steinfeld scheme. 
	* EvalMult is currently unsopported in the Stehle-Steinfeld scheme and there is no currently known method to 
	* support EvalMult in the Stehle-Steinfeld scheme.
	*
	* @param &k1 Original private key used for encryption.
	* @param &k2 New private key to generate the keyswitch hint.
	* @result A shared point to the resulting key switch hint.
	*/
	LPEvalKey<Element> KeySwitchGen(
		const LPPrivateKey<Element> k1,
		const LPPrivateKey<Element> k2) const {
		std::string errMsg = "LPAlgorithmStSt::KeySwitchGen is not implemented for the Stehle-Steinfeld Scheme.";
		throw std::runtime_error(errMsg);
	}


	/**
	* Generate automophism keys for a given private key.  Thess methods are not currently supported.
	*/
	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
		const LPPrivateKey<Element> origPrivateKey, const std::vector<usint> &indexList) const {
		throw std::runtime_error("LPAlgorithmSHELTV::EvalAutomorphismKeyGen is not implemented for Stehle-Steinfeld SHE Scheme.");
	}

	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<usint> &indexList) const {
		throw std::runtime_error("LPAlgorithmSHELTV::EvalAutomorphismKeyGen is not implemented for Stehle-Steinfeld SHE Scheme.");
	}

};

/**
* @brief Main public key encryption scheme for Stehle-Stenfeld scheme implementation,
* @tparam Element a ring element.
*/
/**
* @brief This is the algorithms class for to enable deatures for the Stehle-Stenfeld scheme encryption scheme.  
 *
 * Our Stehle-Steinfeld scheme implementation is described here:
 *   - Cristian Borcea, Arnab "Bobby" Deb Gupta, Yuriy Polyakov, Kurt Rohloff, Gerard Ryan, PICADOR: End-to-end encrypted Publish–Subscribe information distribution with proxy re-encryption, Future Generation Computer Systems, Volume 71, June 2017, Pages 177-191. http://dx.doi.org/10.1016/j.future.2016.10.013
 *
 * This scheme is based on the subfield lattice attack immunity condition proposed in the Conclusions section here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
*
* @tparam Element a ring element.
*/
template <class Element>
class LPPublicKeyEncryptionSchemeStehleSteinfeld : public LPPublicKeyEncryptionSchemeLTV<Element> {
public:
	/**
	* Inherited constructor
	*/
	LPPublicKeyEncryptionSchemeStehleSteinfeld() : LPPublicKeyEncryptionSchemeLTV<Element>() {}

	bool operator==(const LPPublicKeyEncryptionScheme<Element>& sch) const {
		if( dynamic_cast<const LPPublicKeyEncryptionSchemeStehleSteinfeld<Element> *>(&sch) == 0 )
			return false;
		return true;
	}

	/**
	* Function to enable a scheme.
	*
	*@param feature is the feature to enable
	*/
	void Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPAlgorithmStSt<Element>();
			break;
		case PRE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPAlgorithmStSt<Element>();
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>();
			break;
		case SHE:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPAlgorithmStSt<Element>();
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE = new LPAlgorithmSHEStSt<Element>();
			break;
		case MULTIPARTY:
			throw std::logic_error("MULTIPARTY feature not supported for StehleSteinfeld scheme");
		case FHE:
			throw std::logic_error("FHE feature not supported for StehleSteinfeld scheme");
		case LEVELEDSHE:
			throw std::logic_error("LEVELEDSHE feature not supported for StehleSteinfeld scheme");
		}
	}
};


}

#endif
