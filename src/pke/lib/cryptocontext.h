/**
 * @file cryptocontext.h -- Control for encryption operations.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#ifndef SRC_DEMO_PRE_CRYPTOCONTEXT_H_
#define SRC_DEMO_PRE_CRYPTOCONTEXT_H_

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptotiming.h"

namespace lbcrypto {

template<typename Element>
class CryptoContextFactory;

template<typename Element>
class CryptoContextImpl;

template<typename Element>
using CryptoContext = shared_ptr<CryptoContextImpl<Element>>;

/**
 * @brief CryptoContextImpl
 *
 * A CryptoContextImpl is the object used to access the PALISADE library
 *
 * All PALISADE functionality is accessed by way of an instance of a CryptoContextImpl; we say that various objects are
 * "created in" a context, and can only be used in the context in which they were created
 *
 * All PALISADE methods are accessed through CryptoContextImpl methods. Guards are implemented to make certain that
 * only valid objects that have been created in the context are used
 *
 * Contexts are created using the CryptoContextFactory, and can be serialized and recovered from a serialization
 */
template<typename Element>
class CryptoContextImpl : public Serializable {
	friend class CryptoContextFactory<Element>;

private:
	shared_ptr<LPCryptoParameters<Element>>				params;			/*!< crypto parameters used for this context */
	shared_ptr<LPPublicKeyEncryptionScheme<Element>>		scheme;			/*!< algorithm used; accesses all crypto methods */

	static std::map<string,std::vector<LPEvalKey<Element>>>					evalMultKeyMap;	/*!< cached evalmult keys, by secret key UID */
	static std::map<string,shared_ptr<std::map<usint,LPEvalKey<Element>>>>	evalSumKeyMap;	/*!< cached evalsum keys, by secret key UID */

	bool doTiming;
	vector<TimingInfo>* timeSamples;

	/**
	 * Private methods to compare two contexts; this is only used internally and is not generally available
	 * @param a - shared pointer in the object
	 * @param b - this object, usually
	 * @return true if the shared pointer is a pointer to "this"
	 */
	friend bool operator==(const CryptoContext<Element>& a, const CryptoContext<Element>& b) {
		if( a->params.get() != b->params.get() ) return false;
		return true;
	}

	friend bool operator!=(const CryptoContext<Element>& a, const CryptoContext<Element>& b) {
		return !( a == b );
	}

	/**
	 * Private methods to compare two contexts; this is only used internally and is not generally available
	 * @param a - shared pointer in the object
	 * @param b - this object, usually
	 * @return true if the shared pointer is a pointer to "this"
	 */
	friend bool operator==(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
		if( a.params.get() != b.params.get() ) return false;
		return true;
	}

	friend bool operator!=(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
		return !( a == b );
	}

	/**
	 * TypeCheck makes sure that an operation between two ciphertexts is permitted
	 * @param a
	 * @param b
	 */
	void TypeCheck(const Ciphertext<Element> a, const Ciphertext<Element> b) const {
		if( a == NULL || b == NULL )
			PALISADE_THROW( type_error, "Null Ciphertext");
		if( a->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContextImpl");
		if( a->GetCryptoContext() != b->GetCryptoContext() )
			PALISADE_THROW( type_error, "Ciphertexts were not created in the same CryptoContextImpl");
		if( a->GetKeyTag() != b->GetKeyTag() )
			PALISADE_THROW( type_error, "Ciphertexts were not encrypted with same keys" );
		if( a->GetEncodingType() != b->GetEncodingType() )
			PALISADE_THROW( type_error, "Ciphertext encoding types do not match");
	}

	/**
	 * TypeCheck makes sure that an operation between a ciphertext and a plaintext is permitted
	 * @param a
	 * @param b
	 */
	void TypeCheck(const Ciphertext<Element> a, const Plaintext b) const {
		if( a == NULL )
			PALISADE_THROW( type_error, "Null Ciphertext");
		if( b == NULL )
			PALISADE_THROW( type_error, "Null Plaintext");
		if( a->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContextImpl");
		if( a->GetEncodingType() != b->GetEncodingType() )
			PALISADE_THROW( type_error, "Ciphertext and Plaintext encoding types do not match");
	}

	/**
	 * TypeCheck makes sure that an operation between two ciphertexts is permitted
	 * @param a
	 * @param b
	 */
	void TypeCheck(const RationalCiphertext<Element>& a, const RationalCiphertext<Element>& b) const {
		if( a.GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContextImpl");
		if( a.GetCryptoContext() != b.GetCryptoContext() )
			PALISADE_THROW( type_error, "Ciphertexts were not created in the same CryptoContextImpl");
		if( a.GetKeyTag() != b.GetKeyTag() )
			PALISADE_THROW( type_error, "Ciphertexts were not encrypted with same keys" );
		if( a.GetNumerator()->GetEncodingType() != b.GetNumerator()->GetEncodingType() )
			PALISADE_THROW( type_error, "Ciphertext encoding types do not match");
	}

	/**
	 * TypeCheck makes sure that an operation between a ciphertext and a plaintext is permitted
	 * @param a
	 * @param b
	 */
	void TypeCheck(const RationalCiphertext<Element>& a, const Plaintext b) const {
		if( b == NULL )
			PALISADE_THROW( type_error, "Null Plaintext");
		if( a.GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContextImpl");
		if( a.GetNumerator()->GetEncodingType() != b->GetEncodingType() )
			PALISADE_THROW( type_error, "Ciphertext and Plaintext encoding types do not match");
	}

	bool Mismatched(const CryptoContext<Element> a) const {
		if( a.get() != this ) {
			return true;
		}
		return false;
	}

public:
	/**
	 * CryptoContextImpl constructor from pointers to parameters and scheme
	 * @param params - pointer to CryptoParameters
	 * @param scheme - pointer to Crypto Scheme
	 */
	CryptoContextImpl(LPCryptoParameters<Element> *params = 0, LPPublicKeyEncryptionScheme<Element> *scheme = 0) {
		this->params.reset(params);
		this->scheme.reset(scheme);
		this->doTiming = false;
		this->timeSamples = 0;
	}

	/**
	 * CryptoContextImpl constructor from shared pointers to parameters and scheme
	 * @param params - shared pointer to CryptoParameters
	 * @param scheme - sharedpointer to Crypto Scheme
	 */
	CryptoContextImpl(shared_ptr<LPCryptoParameters<Element>> params, shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme) {
		this->params = params;
		this->scheme = scheme;
		this->doTiming = false;
		this->timeSamples = 0;
	}

	/**
	 * Copy constructor
	 * @param c - source
	 */
	CryptoContextImpl(const CryptoContextImpl<Element>& c) {
		params = c.params;
		scheme = c.scheme;
		doTiming = c.doTiming;
		timeSamples = c.timeSamples;
	}

	/**
	 * Assignment
	 * @param rhs - assigning from
	 * @return this
	 */
	CryptoContextImpl<Element>& operator=(const CryptoContextImpl<Element>& rhs) {
		params = rhs.params;
		scheme = rhs.scheme;
		doTiming = rhs.doTiming;
		timeSamples = rhs.timeSamples;
		return *this;
	}

	/**
	 * A CryptoContextImpl is only valid if the shared pointers are both valid
	 */
	operator bool() const { return bool(params) && bool(scheme); }

	// TIMING METHODS
	/**
	 * StartTiming method activates timing of CryptoMethods
	 *
	 * @param timeSamples points to a vector in which timing samples will be stored
	 */
	void StartTiming(vector<TimingInfo>* timeSamples) {
		this->timeSamples = timeSamples;
		doTiming = true;
	}

	/*
	 * StopTiming - turns off timing
	 */
	void StopTiming() {
		doTiming = false;
	}

	/**
	 * ResumeTiming - re-enables timing with existing TimingInfo vector
	 */
	void ResumeTiming() {
		doTiming = true;
	}

	/**
	 * ResetTiming - erases measurements
	 */
	void ResetTiming() {
		this->timeSamples->clear();
	}

	// SERIALIZATION METHODS
	/**
	 * Serialize the CryptoContextImpl
	 *
	 * @param serObj - rapidJson object for the serializaion
	 * @return true on success
	 */
	bool Serialize(Serialized* serObj) const;

	/**
	 * Deserialize the context AND initialize the algorithm
	 *
	 * @param serObj
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj) {
		throw std::logic_error("Deserialize by using CryptoContextFactory::DeserializeAndCreateContext");
	}

	/**
	 * SerializeEvalMultKey for all EvalMult keys
	 * method will serialize each CryptoContextImpl only once
	 *
	 * @param serObj - serialization
	 * @return true on success
	 */
	static bool SerializeEvalMultKey(Serialized* serObj);

	/**
	 * SerializeEvalMultKey for a single EvalMult key
	 * method will serialize entire key AND cryptocontext
	 *
	 * @param serObj - serialization
	 * @param id for key to serialize
	 * @return true on success (false on failure or key id not found)
	 */
	static bool SerializeEvalMultKey(Serialized* serObj, const string& id);

	/**
	 * SerializeEvalMultKey for all EvalMultKeys made in a given context
	 * method will serialize the context only once
	 *
	 * @param serObj - serialization
	 * @param cc whose keys should be serialized
	 * @return true on success (false on failure or no keys found)
	 */
	static bool SerializeEvalMultKey(Serialized* serObj, const CryptoContext<Element> cc);

	/**
	 * DeserializeEvalMultKey deserialize all keys in the serialization
	 * deserialized keys silently replace any existing matching keys
	 * deserialization will create CryptoContextImpl if necessary
	 *
	 * @param serObj - serialization
	 * @return true on success
	 */
	static bool DeserializeEvalMultKey(const Serialized& serObj);

	/**
	 * ClearEvalMultKeys - flush EvalMultKey cache
	 */
	static void ClearEvalMultKeys();

	/**
	 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
	 * @param id
	 */
	static void ClearEvalMultKeys(const string& id);

	/**
	 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
	 * @param cc
	 */
	static void ClearEvalMultKeys(const CryptoContext<Element> cc);

	/**
	 * InsertEvalMultKey - add the given vector of keys to the map, replacing the existing vector if there
	 * @param vectorToInsert
	 */
	static void InsertEvalMultKey(const std::vector<LPEvalKey<Element>>& vectorToInsert);

	/**
	 * SerializeEvalSumKey for all EvalSum keys
	 * method will serialize each CryptoContextImpl only once
	 *
	 * @param serObj - serialization
	 * @return true on success
	 */
	static bool SerializeEvalSumKey(Serialized* serObj);

	/**
	 * SerializeEvalSumKey for a single EvalSum key
	 * method will serialize entire key AND cryptocontext
	 *
	 * @param serObj - serialization
	 * @param id for key to serialize
	 * @return true on success (false on failure or key id not found)
	 */
	static bool SerializeEvalSumKey(Serialized* serObj, const string& id);

	/**
	 * SerializeEvalSumKey for all EvalSumKeys made in a given context
	 * method will serialize the context only once
	 *
	 * @param serObj - serialization
	 * @param cc whose keys should be serialized
	 * @return true on success (false on failure or no keys found)
	 */
	static bool SerializeEvalSumKey(Serialized* serObj, const CryptoContext<Element> cc);

	/**
	 * DeserializeEvalSumKey deserialize all keys in the serialization
	 * deserialized keys silently replace any existing matching keys
	 * deserialization will create CryptoContextImpl if necessary
	 *
	 * @param serObj - serialization
	 * @return true on success
	 */
	static bool DeserializeEvalSumKey(const Serialized& serObj);

	/**
	 * ClearEvalSumKeys - flush EvalSumKey cache
	 */
	static void ClearEvalSumKeys();

	/**
	 * ClearEvalSumKeys - flush EvalSumKey cache for a given id
	 * @param id
	 */
	static void ClearEvalSumKeys(const string& id);

	/**
	 * ClearEvalSumKeys - flush EvalSumKey cache for a given context
	 * @param cc
	 */
	static void ClearEvalSumKeys(const CryptoContext<Element> cc);

	/**
	 * InsertEvalSumKey - add the given map of keys to the map, replacing the existing map if there
	 * @param mapToInsert
	 */
	static void InsertEvalSumKey(const shared_ptr<std::map<usint,LPEvalKey<Element>>> mapToInsert);


	// TURN FEATURES ON
	/**
	 * Enable a particular feature for use with this CryptoContextImpl
	 * @param feature - the feature that should be enabled
	 */
	void Enable(PKESchemeFeature feature) { scheme->Enable(feature); }

	/**
	 * Enable several features at once
	 * @param featureMask - bitwise or of several PKESchemeFeatures
	 */
	void Enable(usint featureMask) { scheme->Enable(featureMask); }

	// GETTERS
	/**
	* Getter for Scheme
	* @return scheme
	*/
	const shared_ptr<LPPublicKeyEncryptionScheme<Element>> GetEncryptionAlgorithm() const { return scheme; }

	/**
	* Getter for CryptoParams
	* @return params
	*/
	const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return params; }

	/**
	 * Getter for element params
	 * @return
	 */
	const shared_ptr<typename Element::Params> GetElementParams() const { return params->GetElementParams(); }

	/**
	 * Getter for encoding params
	 * @return
	 */
	const EncodingParams GetEncodingParams() const { return params->GetEncodingParams(); }

	/**
	 * Get the cyclotomic order used for this context
	 *
	 * @return
	 */
	const usint GetCyclotomicOrder() const { return params->GetElementParams()->GetCyclotomicOrder(); }

	/**
	 * Get the ring dimension used for this context
	 *
	 * @return
	 */
	const usint GetRingDimension() const { return params->GetElementParams()->GetRingDimension(); }

	/**
	 * Get the ciphertext modulus used for this context
	 *
	 * @return
	 */
	const typename Element::Integer& GetModulus() const { return params->GetElementParams()->GetModulus(); }

	/**
	 * Get the ciphertext modulus used for this context
	 *
	 * @return
	 */
	const typename Element::Integer& GetRootOfUnity() const { return params->GetElementParams()->GetRootOfUnity(); }

	/**
	* KeyGen generates a key pair using this algorithm's KeyGen method
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> KeyGen() {
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->KeyGen(CryptoContextFactory<Element>::GetContextForPointer(this), false);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpKeyGen, currentDateTime() - start) );
		}
		return r;
	}

	/**
	* KeyGen generates a Multiparty key pair using this algorithm's KeyGen method from two keys
	* @param pk first public key used to coordinate the creation of later public keys.
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> MultipartyKeyGen(
		const LPPublicKey<Element> pk, bool makeSparse=false, bool pre=false) {
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->MultipartyKeyGen(CryptoContextFactory<Element>::GetContextForPointer(this), pk, makeSparse, pre);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyKeyGenKey, currentDateTime() - start) );
		}
		return r;
	}

	/**
	* KeyGen generates a Multiparty key pair using a vector of secret keys
	* @param secretKeys a vector of the secret keys to be used for multiparty computation.
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> MultipartyKeyGen(
		const vector<LPPrivateKey<Element>>& secretKeys) {
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r =  GetEncryptionAlgorithm()->MultipartyKeyGen(CryptoContextFactory<Element>::GetContextForPointer(this), secretKeys, false);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyKeyGenKeyvec, currentDateTime() - start) );
		}
		return r;
	}

	/**
	* Lead Multiparty Decryption method for PALISADE multiparty operations.
	* This should be performed by exactly one of the clients.
	* All other clients should perform the MultipartyDecryptMain operation.
	* @param privateKey the secret key of the lead decryption client
	* @param ciphertext vector of encrypted ciphertext
	* @return vector of partially decrypted ciphertexts
	*/
	vector<Ciphertext<Element>> MultipartyDecryptLead(
		const LPPrivateKey<Element> privateKey,
		const vector<Ciphertext<Element>>& ciphertext) const
	{
		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			throw std::logic_error("Information passed to MultipartyDecryptLead was not generated with this crypto context");

        vector<Ciphertext<Element>> newCiphertext;

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for( size_t i = 0; i < ciphertext.size(); i++ ) {
			if( ciphertext[i] == NULL || Mismatched(ciphertext[i]->GetCryptoContext()) )
				throw std::logic_error("A ciphertext passed to MultipartyDecryptLead was not generated with this crypto context");

			newCiphertext.push_back( GetEncryptionAlgorithm()->MultipartyDecryptLead(privateKey, ciphertext[i]) );

		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyDecryptLead, currentDateTime() - start) );
		}

		return newCiphertext;
	}

	/**
	* Multiparty decryption method for PALISADE multiparty operations.
	* The lead multiparty decryption operation should be performed by exactly one of the clients.
	* All other clients should perform this MultipartyDecryptMain operation.
	* @param privateKey - for decryption
	* @param ciphertext - vector of encrypted ciphertext
	* @return vector of partially decrypted ciphertexts
	*/
	vector<Ciphertext<Element>> MultipartyDecryptMain(
		const LPPrivateKey<Element> privateKey,
		const vector<Ciphertext<Element>>& ciphertext) const
	{
		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			throw std::logic_error("Information passed to MultipartyDecryptMain was not generated with this crypto context");

		vector<Ciphertext<Element>> newCiphertext;

		double start = 0;
		if( doTiming ) start = currentDateTime();

		for( size_t i = 0; i < ciphertext.size(); i++ ) {
			if( ciphertext[i] == NULL || Mismatched(ciphertext[i]->GetCryptoContext()) )
				throw std::logic_error("A ciphertext passed to MultipartyDecryptMain was not generated with this crypto context");

			newCiphertext.push_back( GetEncryptionAlgorithm()->MultipartyDecryptMain(privateKey, ciphertext[i]) );
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyDecryptMain, currentDateTime() - start) );
		}

		return newCiphertext;
	}

	/**
	* Final multiparty decryption method to fuse the partially decrypted ciphertexts into a decrypted plaintext.
	* The lead multiparty decryption operation should be performed by exactly one of the clients.
	* All other clients should perform the MultipartyDecryptMain operation.
	* @param partialCiphertextVec - vector of partially decrypted ciphertexts.
	* @param plaintext - pointer to destination for the result of decryption
	* @param doPadding - true if input plaintext was padded; causes unpadding on last piece of ciphertext
	* @return size of plaintext
	*/
	DecryptResult MultipartyDecryptFusion(
		const vector<Ciphertext<Element>>& partialCiphertextVec,
		Plaintext *plaintext) const
	{

		DecryptResult result;

		//Make sure we're processing ciphertexts.
		size_t last_ciphertext = partialCiphertextVec.size();
		if ( last_ciphertext < 1 )
			return result;

		double start = 0;
		if( doTiming ) start = currentDateTime();

		for( size_t i = 0; i < last_ciphertext; i++ ) {
			if (partialCiphertextVec[i] == NULL || Mismatched(partialCiphertextVec[i]->GetCryptoContext()))
				throw std::logic_error("A ciphertext passed to MultipartyDecryptFusion was not generated with this crypto context");
			if (partialCiphertextVec[i]->GetEncodingType() != partialCiphertextVec[0]->GetEncodingType())
				throw std::logic_error("Ciphertexts passed to MultipartyDecryptFusion have mismatched encoding types");
		}

		// determine which type of plaintext that you need to decrypt into
		Plaintext decrypted = GetPlaintextForDecrypt(partialCiphertextVec[0]->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());

		result = GetEncryptionAlgorithm()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<NativePoly>());

		if (result.isValid == false) return result;
		decrypted->Decode();

		*plaintext = decrypted;

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyDecryptFusion, currentDateTime() - start) );
		}
		return result;
	}


	/**
	* SparseKeyGen generates a key pair with special structure, and without full entropy,
	* for use in special cases like Ring Reduction
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> SparseKeyGen() {
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->KeyGen(CryptoContextFactory<Element>::GetContextForPointer(this), true);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpSparseKeyGen, currentDateTime() - start) );
		}
		return r;
	}

	/**
	* ReKeyGen produces an Eval Key that PALISADE can use for Proxy Re Encryption
	* @param newKey (public)
	* @param oldKey (private)
	* @return new evaluation key
	*/
	LPEvalKey<Element> ReKeyGen(
		const LPPublicKey<Element> newKey,
		const LPPrivateKey<Element> oldKey) const {

		if( newKey == NULL || oldKey == NULL ||
				Mismatched(newKey->GetCryptoContext()) ||
				Mismatched(oldKey->GetCryptoContext()) )
			throw std::logic_error("Keys passed to ReKeyGen were not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->ReKeyGen(newKey, oldKey);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpReKeyGenPubPri, currentDateTime() - start) );
		}
		return r;
	}

	/**
	* ReKeyGen produces an Eval Key that PALISADE can use for Proxy Re Encryption
	* @param newKey (private)
	* @param oldKey (private)
	* @return new evaluation key
	*/
	LPEvalKey<Element> ReKeyGen(
		const LPPrivateKey<Element> newKey,
		const LPPrivateKey<Element> oldKey) const {

		if (newKey == NULL || oldKey == NULL ||
				Mismatched(newKey->GetCryptoContext()) ||
				Mismatched(oldKey->GetCryptoContext()) )
			throw std::logic_error("Keys passed to ReKeyGen were not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->ReKeyGen(newKey, oldKey);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpReKeyGenPriPri, currentDateTime() - start) );
		}
		return r;
	}

	/**
	* EvalMultKeyGen creates a key that can be used with the PALISADE EvalMult operator
	* @param key
	* @return new evaluation key
	*/
	void EvalMultKeyGen(const LPPrivateKey<Element> key);

	/**
	* EvalMultsKeyGen creates a vector evalmult keys that can be used with the PALISADE EvalMult operator
	* 1st key (for s^2) is used for multiplication of ciphertexts of depth 1
	* 2nd key (for s^3) is used for multiplication of ciphertexts of depth 2, etc.
	*
	* @param key
	* @return a vector of evaluation keys
	*/
	void EvalMultKeysGen(const LPPrivateKey<Element> key);

	/**
	 * GetEvalMultKeyVector fetches the eval mult keys for a given KeyID
	 * @param keyID
	 * @return key vector from ID
	 */
	static const vector<LPEvalKey<Element>>& GetEvalMultKeyVector(const string& keyID);

	/**
	 * GetEvalMultKeys
	 * @return map of all the keys
	 */
	static const std::map<string,std::vector<LPEvalKey<Element>>>& GetAllEvalMultKeys();

	/**
	* KeySwitchGen creates a key that can be used with the PALISADE KeySwitch operation
	* @param key1
	* @param key2
	* @return new evaluation key
	*/
	LPEvalKey<Element> KeySwitchGen(
		const LPPrivateKey<Element> key1, const LPPrivateKey<Element> key2) const {

		if( key1 == NULL || key2 == NULL ||
				Mismatched(key1->GetCryptoContext()) ||
				Mismatched(key2->GetCryptoContext()) )
			throw std::logic_error("Keys passed to KeySwitchGen were not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->KeySwitchGen(key1, key2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpKeySwitchGen, currentDateTime() - start) );
		}
		return r;
	}

	/**
	 * Encrypt a plaintext using a given public key
	 * @param publicKey
	 * @param plaintext
	 * @return ciphertext (or null on failure)
	 */
	Ciphertext<Element> Encrypt(
			const LPPublicKey<Element> publicKey,
			Plaintext plaintext)
	{
		if( publicKey == NULL )
			throw std::logic_error("null key passed to Encrypt");

		if( plaintext == NULL )
			throw std::logic_error("null plaintext passed to Encrypt");

		if( Mismatched(publicKey->GetCryptoContext()) )
			throw std::logic_error("key passed to Encrypt was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();

		Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, plaintext->GetEncodedElement<Element>());

		if (ciphertext) {
			ciphertext->SetEncodingType( plaintext->GetEncodingType() );
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptPub, currentDateTime() - start) );
		}
		return ciphertext;
	}

	/**
	 * Encrypt a plaintext using a given private key
	 * @param privateKey
	 * @param plaintext
	 * @return ciphertext (or null on failure)
	 */
	Ciphertext<Element> Encrypt(
		const LPPrivateKey<Element> privateKey,
		Plaintext plaintext) const
	{
		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			throw std::logic_error("key passed to Encrypt was not generated with this crypto context");
		if( plaintext == NULL )
			throw std::logic_error("null plaintext passed to Encrypt");

		double start = 0;
		if( doTiming ) start = currentDateTime();

		Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(privateKey, plaintext->GetEncodedElement<Element>());

		if (ciphertext) {
			ciphertext->SetEncodingType( plaintext->GetEncodingType() );
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptPriv, currentDateTime() - start) );
		}
		return ciphertext;
	}
	
	/**
	* Encrypt a matrix of Plaintext
	* @param publicKey - for encryption
	* @param plaintext - to encrypt
	* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	* @return a vector of pointers to Ciphertexts created by encrypting the plaintext
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>> EncryptMatrix(
		const LPPublicKey<Element> publicKey,
		Matrix<Plaintext> &plaintext)
	{
		if (publicKey == NULL || Mismatched(publicKey->GetCryptoContext()))
			throw std::logic_error("key passed to EncryptMatrix was not generated with this crypto context");

		auto zeroAlloc = [=]() { return make_unique<RationalCiphertext<Element>>(publicKey->GetCryptoContext(), true); };

		shared_ptr<Matrix<RationalCiphertext<Element>>> cipherResults(new Matrix<RationalCiphertext<Element>>
			(zeroAlloc, plaintext.GetRows(), plaintext.GetCols()));

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for (size_t row = 0; row < plaintext.GetRows(); row++)
		{
			for (size_t col = 0; col < plaintext.GetCols(); col++)
			{
				if( plaintext(row,col)->Encode() == false )
					return 0;

				Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, plaintext(row,col)->GetElement<Element>());

				if (ciphertext) {
					ciphertext->SetEncodingType( plaintext(row,col)->GetEncodingType() );
				}

				(*cipherResults)(row, col).SetNumerator(ciphertext);
			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptMatrixPlain, currentDateTime() - start) );
		}
		return cipherResults;
	}

	/**
	* Perform an encryption by reading plaintext from a stream, serializing each piece of ciphertext,
	* and writing the serializations to an output stream
	* @param publicKey - the encryption key in use
	* @param instream - where to read the input from
	* @param ostream - where to write the serialization to
	* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	* @return
	*/
	void EncryptStream(
		const LPPublicKey<Element> publicKey,
		std::istream& instream,
		std::ostream& outstream) const
	{
		// NOTE timing this operation is not supported

		if( publicKey == NULL || Mismatched(publicKey->GetCryptoContext()) )
			throw std::logic_error("key passed to EncryptStream was not generated with this crypto context");

		bool padded = false;
		Plaintext px;
		size_t chunkSize = this->GetRingDimension();
		char *ptxt = new char[chunkSize];

		while (instream.good()) {
			instream.read(ptxt, chunkSize);
			size_t nRead = instream.gcount();

			if (nRead <= 0 && padded)
				break;

			px = this->MakeStringPlaintext(std::string(ptxt,nRead));

			if (nRead < chunkSize) {
				padded = true;
			}

			Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, px->GetEncodedElement<Element>());
			if (!ciphertext) {
				break;
			}
			ciphertext->SetEncodingType( px->GetEncodingType() );

			Serialized cS;

			if (ciphertext->Serialize(&cS)) {
				if (!SerializableHelper::SerializationToStream(cS, outstream)) {
					break;
				}
			}
			else {
				break;
			}
		}

		delete [] ptxt;
		return;
	}

	// PLAINTEXT FACTORY METHODS
	/**
	 * MakeScalarPlaintext constructs a ScalarEncoding in this context
	 * @param value
	 * @param isSigned
	 * @return plaintext
	 */
	Plaintext MakeScalarPlaintext(int64_t value) const {
		return Plaintext( new ScalarEncoding( this->GetElementParams(), this->GetEncodingParams(), value ) );
	}

	/**
	 * MakeStringPlaintext constructs a StringEncoding in this context
	 * @param str
	 * @return plaintext
	 */
	Plaintext MakeStringPlaintext(const string& str) const {
		return Plaintext( new StringEncoding( this->GetElementParams(), this->GetEncodingParams(), str ) );
	}

	/**
	 * MakeIntegerPlaintext constructs an IntegerEncoding in this context
	 * @param value
	 * @return plaintext
	 */
	Plaintext MakeIntegerPlaintext(int64_t value) const {
		return Plaintext( new IntegerEncoding( this->GetElementParams(), this->GetEncodingParams(), value ) );
	}

	/**
	 * MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context
	 * @param value
	 * @param isSigned
	 * @return plaintext
	 */
	Plaintext MakeCoefPackedPlaintext(const vector<int64_t>& value) const {
		return Plaintext( new CoefPackedEncoding( this->GetElementParams(), this->GetEncodingParams(), value ) );
	}

	/**
	 * MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context
	 * @param value
	 * @param isSigned
	 * @return plaintext
	 */
	Plaintext MakeCoefPackedPlaintext(const std::initializer_list<int64_t>& value) const {
		return Plaintext( new CoefPackedEncoding( this->GetElementParams(), this->GetEncodingParams(), value ) );
	}

	/**
	 * MakePackedPlaintext constructs a PackedEncoding in this context
	 * @param value
	 * @return plaintext
	 */
	Plaintext MakePackedPlaintext(const vector<uint64_t>& value) const {
		return Plaintext( new PackedEncoding( this->GetElementParams(), this->GetEncodingParams(), value ) );
	}

	/**
	 * MakePackedPlaintext constructs a PackedEncoding in this context
	 * @param value
	 * @return plaintext
	 */
	Plaintext MakePackedPlaintext(const std::initializer_list<uint64_t>& value) const {
		return Plaintext( new PackedEncoding( this->GetElementParams(), this->GetEncodingParams(), value ) );
	}

private:
	static Plaintext
	GetPlaintextForDecrypt(PlaintextEncodings pte, shared_ptr<typename Element::Params> evp, EncodingParams ep) {
		Plaintext pt;
		shared_ptr<typename NativePoly::Params> vp(
				new typename NativePoly::Params(evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1) );

		switch(pte) {
		case Unknown:
			throw std::logic_error("Unknown plaintext encoding type in GetPlaintextForDecrypt");
			break;
		case Scalar:
			pt.reset( new ScalarEncoding(vp,ep) );
			break;
		case Integer:
			pt.reset( new IntegerEncoding(vp,ep) );
			break;
		case CoefPacked:
			pt.reset( new CoefPackedEncoding(vp,ep) );
			break;
		case Packed:
			pt.reset( new PackedEncoding(vp,ep) );
			break;
		case String:
			pt.reset( new StringEncoding(vp,ep) );
			break;
		}

		return pt;
	}

public:
	/**
	 * Decrypt a single ciphertext into the appropriate plaintext
	 *
	 * @param privateKey - decryption key
	 * @param ciphertext - ciphertext to decrypt
	 * @param plaintext - resulting plaintext object pointer is here
	 * @return
	 */
	DecryptResult Decrypt(
			const LPPrivateKey<Element> privateKey,
			const Ciphertext<Element> ciphertext,
			Plaintext* plaintext)
	{
		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			throw std::logic_error("Information passed to Decrypt was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();

		// determine which type of plaintext that you need to decrypt into
		Plaintext decrypted = GetPlaintextForDecrypt(ciphertext->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());

		DecryptResult result = GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext, &decrypted->GetElement<NativePoly>());

		if (result.isValid == false) return result;
		decrypted->Decode();

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpDecrypt, currentDateTime() - start) );
		}

		*plaintext = decrypted;
		return result;
	}


	/**
	* Decrypt method for a matrix of ciphertexts
	* @param privateKey - for decryption
	* @param ciphertext - matrix of encrypted ciphertexts
	* @param plaintext - pointer to the destination martrix of plaintexts
	* @return size of plaintext
	*/
	DecryptResult DecryptMatrix(
		const LPPrivateKey<Element> privateKey,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext,
		shared_ptr<Matrix<Plaintext>> *numerator,
		shared_ptr<Matrix<Plaintext>> *denominator) const
	{

		// edge case
		if ((ciphertext->GetCols()== 0) && (ciphertext->GetRows() == 0))
			return DecryptResult();

		if (privateKey == NULL || Mismatched(privateKey->GetCryptoContext()))
			throw std::runtime_error("Information passed to DecryptMatrix was not generated with this crypto context");

		const Ciphertext<Element> ctN = (*ciphertext)(0, 0).GetNumerator();

		// need to build matrices for the result
		Plaintext ptx = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
		auto zeroPackingAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(ptx); };
		*numerator = shared_ptr<Matrix<Plaintext>>( new Matrix<Plaintext>(zeroPackingAlloc, ciphertext->GetRows(), ciphertext->GetCols()) );
		*denominator = shared_ptr<Matrix<Plaintext>>( new Matrix<Plaintext>(zeroPackingAlloc, ciphertext->GetRows(), ciphertext->GetCols()) );

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for (size_t row = 0; row < ciphertext->GetRows(); row++)
		{
			for (size_t col = 0; col < ciphertext->GetCols(); col++)
			{
				if (Mismatched((*ciphertext)(row, col).GetCryptoContext()))
					throw std::runtime_error("A ciphertext passed to DecryptMatrix was not generated with this crypto context");

				const Ciphertext<Element> ctN = (*ciphertext)(row, col).GetNumerator();

				// determine which type of plaintext that you need to decrypt into
				Plaintext decryptedNumerator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
				DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator->GetElement<NativePoly>());

				if (resultN.isValid == false) return resultN;

				(**numerator)(row,col) = decryptedNumerator;

				(**numerator)(row,col)->Decode();

				Plaintext decryptedDenominator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
				if( (*ciphertext)(row,col).GetIntegerFlag() == true ) {
					decryptedDenominator->GetElement<Poly>().SetValuesToZero();
					decryptedDenominator->GetElement<Poly>().at(0) = 1;
				}
				else {

					const Ciphertext<Element> ctD = (*ciphertext)(row, col).GetDenominator();

					DecryptResult resultD = GetEncryptionAlgorithm()->Decrypt(privateKey, ctD, &decryptedDenominator->GetElement<NativePoly>());

					if (resultD.isValid == false) return resultD;

					(**denominator)(row,col) = decryptedDenominator;
				}

				(**denominator)(row, col)->Decode();

			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpDecryptMatrixPlain, currentDateTime() - start) );
		}
		return DecryptResult((**numerator)((*numerator)->GetRows()-1,(*numerator)->GetCols()-1)->GetLength());

	}

	/**
	* Decrypt method for numerators in a matrix of ciphertexts (packed encoding)
	* @param privateKey - for decryption
	* @param ciphertext - matrix of encrypted ciphertexts
	* @param plaintext - pointer to the destination martrix of plaintexts
	* @return size of plaintext
	*/
	DecryptResult DecryptMatrixNumerator(
		const LPPrivateKey<Element> privateKey,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext,
		shared_ptr<Matrix<Plaintext>> *numerator) const
	{
		// edge case
		if ((ciphertext->GetCols() == 0) && (ciphertext->GetRows() == 0))
			return DecryptResult();

		if (privateKey == NULL || Mismatched(privateKey->GetCryptoContext()))
			throw std::runtime_error("Information passed to DecryptMatrix was not generated with this crypto context");

		double start = 0;
		if (doTiming) start = currentDateTime();

		//force all precomputations to take place in advance
		if( Mismatched((*ciphertext)(0, 0).GetCryptoContext()) )
			throw std::runtime_error("A ciphertext passed to DecryptMatrix was not generated with this crypto context");

		const Ciphertext<Element> ctN = (*ciphertext)(0, 0).GetNumerator();

		// need to build a numerator matrix for the result
		Plaintext ptx = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
		auto zeroPackingAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(ptx); };
		*numerator = shared_ptr<Matrix<Plaintext>>( new Matrix<Plaintext>(zeroPackingAlloc, ciphertext->GetRows(), ciphertext->GetCols()) );

		Plaintext decryptedNumerator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
		DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator->GetElement<NativePoly>());

		if (resultN.isValid == false) return resultN;

		(**numerator)(0, 0) = decryptedNumerator;
		(**numerator)(0, 0)->Decode();

		for (size_t row = 0; row < ciphertext->GetRows(); row++)
		{
#pragma omp parallel for
			for (size_t col = 0; col < ciphertext->GetCols(); col++)
			{
				if (row + col > 0)
				{
					if( Mismatched((*ciphertext)(row, col).GetCryptoContext()) )
						throw std::runtime_error("A ciphertext passed to DecryptMatrix was not generated with this crypto context");

					const Ciphertext<Element> ctN = (*ciphertext)(row, col).GetNumerator();

					Plaintext decryptedNumerator = GetPlaintextForDecrypt(ctN->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
					GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator->GetElement<NativePoly>());

					(**numerator)(row, col) = decryptedNumerator;
					(**numerator)(row, col)->Decode();
				}

			}
		}

		if (doTiming) {
			timeSamples->push_back(TimingInfo(OpDecryptMatrixPacked, currentDateTime() - start));
		}
		return DecryptResult((**numerator)((*numerator)->GetRows() - 1, (*numerator)->GetCols() - 1)->GetLength());

	}

	/**
	* read instream for a sequence of serialized ciphertext; deserialize it, decrypt it, and write it to outstream
	* @param privateKey - reference to the decryption key
	* @param instream - input stream with sequence of serialized ciphertexts
	* @param outstream - output stream for plaintext
	* @return total bytes processed
	*/
	size_t DecryptStream(
		const LPPrivateKey<Element> privateKey,
		std::istream& instream,
		std::ostream& outstream)
	{
		// NOTE timing this operation is not supported

		if( privateKey == NULL || Mismatched(privateKey->GetCryptoContext()) )
			throw std::logic_error("Information passed to DecryptStream was not generated with this crypto context");

		Serialized serObj;
		size_t tot = 0;

		bool firstTime = true;
		Plaintext pte[2];
		bool whichArray = false;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			Ciphertext<Element> ct;
			if( (ct = deserializeCiphertext(serObj)) != NULL ) {
				if( ct->GetEncodingType() != String ) {
					throw std::logic_error("Library can only stream string encodings");
				}

				pte[whichArray] = GetPlaintextForDecrypt(ct->GetEncodingType(), this->GetElementParams(), this->GetEncodingParams());
				DecryptResult res = GetEncryptionAlgorithm()->Decrypt(privateKey, ct, &pte[whichArray]->GetElement<NativePoly>());
				if( !res.isValid )
					return tot;
				tot += res.messageLength;

				pte[whichArray]->Decode();

				if( !firstTime ) {
					outstream << pte[!whichArray]->GetStringValue();
				}
				firstTime = false;
				whichArray = !whichArray;
			}
			else
				return tot;
		}

		outstream << pte[!whichArray]->GetStringValue();

		return tot;
	}

	/**
	* ReEncrypt - Proxy Re Encryption mechanism for PALISADE
	* @param evalKey - evaluation key from the PRE keygen method
	* @param ciphertext - vector of shared pointers to encrypted Ciphertext
	* @return vector of shared pointers to re-encrypted ciphertexts
	*/
	Ciphertext<Element> ReEncrypt(
		LPEvalKey<Element> evalKey,
		Ciphertext<Element> ciphertext) const
	{
		if( evalKey == NULL || Mismatched(evalKey->GetCryptoContext()) )
			throw std::logic_error("Information passed to ReEncrypt was not generated with this crypto context");

		if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
			throw std::logic_error("The ciphertext passed to ReEncrypt was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();

		Ciphertext<Element> newCiphertext = GetEncryptionAlgorithm()->ReEncrypt(evalKey, ciphertext);

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpReEncrypt, currentDateTime() - start) );
		}

		return newCiphertext;
	}

	/**
	* read instream for a serialized ciphertext. deserialize, re-encrypt, serialize, and write to outstream
	* @param evalKey - reference to the re-encryption key
	* @param instream - input stream with sequence of serialized ciphertext
	* @param outstream - output stream with sequence of serialized re-encrypted ciphertext
	*/
	void ReEncryptStream(
		const LPEvalKey<Element> evalKey,
		std::istream& instream,
		std::ostream& outstream)
	{
		// NOTE timing this operation is not supported

		if( evalKey == NULL || Mismatched(evalKey->GetCryptoContext()) )
			throw std::logic_error("Information passed to ReEncryptStream was not generated with this crypto context");

		Serialized serObj;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			Ciphertext<Element> ct;
			ct = deserializeCiphertext(serObj);
			if( ct ) {
				Ciphertext<Element> reCt = ReEncrypt(evalKey, ct);

				Serialized serReObj;
				if( reCt->Serialize(&serReObj) ) {
					SerializableHelper::SerializationToStream(serReObj, outstream);
				}
				else {
					return;
				}
			}
			else {
				return;
			}
		}
	}

	/**
	 * EvalAdd - PALISADE EvalAdd method for a pair of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 + ct2
	 */
	Ciphertext<Element>
	EvalAdd(const Ciphertext<Element> ct1, const Ciphertext<Element> ct2) const
	{
		TypeCheck(ct1, ct2);

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalAdd(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAdd, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * EvalAddMatrix - PALISADE EvalAdd method for a pair of matrices of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new matrix for ct1 + ct2
	 */
	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalAddMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		TypeCheck((*ct1)(0,0), (*ct2)(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		double start = 0;
		if( doTiming ) start = currentDateTime();
		Matrix<RationalCiphertext<Element>> rv = *ct1 + *ct2;
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAddMatrix, currentDateTime() - start) );
		}
		shared_ptr<Matrix<RationalCiphertext<Element>>> a(new Matrix<RationalCiphertext<Element>>(rv));
		return a;
	}

	/**
	 * EvalSub - PALISADE EvalSub method for a pair of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 - ct2
	 */
	Ciphertext<Element>
	EvalSub(const Ciphertext<Element> ct1, const Ciphertext<Element> ct2) const
	{
		TypeCheck(ct1, ct2);

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalSub(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSub, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * EvalSubMatrix - PALISADE EvalSub method for a pair of matrices of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new matrix for ct1 + ct2
	 */
	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalSubMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		TypeCheck((*ct1)(0,0), (*ct2)(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		double start = 0;
		if( doTiming ) start = currentDateTime();
		Matrix<RationalCiphertext<Element>> rv = *ct1 - *ct2;
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSubMatrix, currentDateTime() - start) );
		}
		shared_ptr<Matrix<RationalCiphertext<Element>>> a(new Matrix<RationalCiphertext<Element>>(rv));
		return a;
	}

	/**
	* EvalAdd - PALISADE EvalAdd method for a ciphertext and plaintext
	* @param ciphertext
	* @param plaintext
	* @return new ciphertext for ciphertext + plaintext 
	*/
	Ciphertext<Element>
	EvalAdd(const Ciphertext<Element> ciphertext, const Plaintext plaintext) const
	{
		TypeCheck(ciphertext, plaintext);

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalAdd(ciphertext, plaintext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAddPlain, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* EvalSubPlain - PALISADE EvalSub method for a ciphertext and plaintext
	* @param ciphertext
	* @param plaintext
	* @return new ciphertext for ciphertext - plaintext
	*/
	Ciphertext<Element>
	EvalSub(const Ciphertext<Element> ciphertext, const Plaintext plaintext) const
	{
		TypeCheck(ciphertext, plaintext);

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalSub(ciphertext, plaintext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSubPlain, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts - with key switching
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 * ct2
	 */
	Ciphertext<Element>
	EvalMult(const Ciphertext<Element> ct1, const Ciphertext<Element> ct2) const
	{
		TypeCheck(ct1, ct2);

		auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, ct2, ek[0]);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts - no key switching (relinearization)
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 * ct2
	 */
	Ciphertext<Element>
	EvalMultNoRelin(const Ciphertext<Element> ct1, const Ciphertext<Element> ct2) const
	{
		TypeCheck(ct1, ct2);

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* EvalMultMany - PALISADE function for evaluating multiplication on ciphertext followed by relinearization operation (at the end).
	* It computes the multiplication in a binary tree manner. Also, it reduces the number of
	* elements in the ciphertext to two after each multiplication.
	* Currently it assumes that the consecutive two input arguments have
	* total depth smaller than the supported depth. Otherwise, it throws an error.
	*
	* @param cipherTextList  is the ciphertext list.
	*
	* @return new ciphertext.
	*/
	Ciphertext<Element> EvalMultMany(const vector<Ciphertext<Element>>& ct) const{

		const auto ek = GetEvalMultKeyVector(ct[0]->GetKeyTag());

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalMultMany(ct, ek);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, currentDateTime() - start) );
		}
		return rv;

	}

	/**
	* Function for evaluating multiplication on ciphertext followed by relinearization operation.
	* Currently it assumes that the input arguments have total depth smaller than the supported depth. Otherwise, it throws an error.
	*
	* @param ct1 first input ciphertext.
	* @param ct2 second input ciphertext.
	*
	* @return new ciphertext
	*/
	Ciphertext<Element> EvalMultAndRelinearize(const Ciphertext<Element> ct1,
			const Ciphertext<Element> ct2) const{

		const auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalMultAndRelinearize(ct1, ct2, ek);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, currentDateTime() - start) );
		}
		return rv;

	}

	/**
	 * EvalMult - PALISADE EvalMult method for plaintext * ciphertext
	 * @param pt2
	 * @param ct1
	 * @return new ciphertext for ct1 * pt2
	 */
	Ciphertext<Element>
	EvalMult(const Plaintext pt2, const Ciphertext<Element> ct1) const
	{
		return EvalMult(ct1, pt2);
	}

	/**
	 * EvalMult - PALISADE EvalMult method for plaintext * ciphertext
	 * @param ct1
	 * @param pt2
	 * @return new ciphertext for ct1 * pt2
	 */
	Ciphertext<Element>
	EvalMult(const Ciphertext<Element> ct1, const Plaintext pt2) const
	{
		TypeCheck(ct1, pt2);

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, pt2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * EvalMultMatrix - PALISADE EvalMult method for two matrices of ciphertext
	 * @param ct1
	 * @param ct2
	 * @return new matrix for ct1 * ct2
	 */
	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalMultMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		TypeCheck((*ct1)(0,0), (*ct2)(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		double start = 0;
		if( doTiming ) start = currentDateTime();
		Matrix<RationalCiphertext<Element>> rv = *ct1 * *ct2;
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMultMatrix, currentDateTime() - start) );
		}
		shared_ptr<Matrix<RationalCiphertext<Element>>> a(new Matrix<RationalCiphertext<Element>>(rv));
		return a;
	}

	/**
	* EvalSub - PALISADE Negate method for a ciphertext
	* @param ct
	* @return new ciphertext -ct
	*/
	Ciphertext<Element>
	EvalNegate(const Ciphertext<Element> ct) const
	{
		if (ct == NULL || Mismatched(ct->GetCryptoContext()) )
			throw std::logic_error("Information passed to EvalNegate was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalNegate(ct);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalNeg, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* EvalSub - PALISADE Negate method for a ciphertext
	* @param ct
	* @return new ciphertext -ct
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalNegateMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct) const
	{
		if (ct == NULL || Mismatched((*ct)(0,0).GetCryptoContext()) )
			throw std::logic_error("Information passed to EvalNegateMatrix was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		shared_ptr<Matrix<RationalCiphertext<Element>>> m(
				new Matrix<RationalCiphertext<Element>>(ct->GetAllocator(), ct->GetRows(), ct->GetCols()));
		for( size_t r = 0; r < m->GetRows(); r++ )
			for( size_t c = 0; c < m->GetCols(); c++ )
				(*m)(r,c) = -((*ct)(r,c));
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalNegMatrix, currentDateTime() - start) );
		}
		return m;
	}

	/**
	* Generate automophism keys for a given private key
	*
	* @param publicKey original public key.
	* @param origPrivateKey original private key.
	* @param indexList list of automorphism indices to be computed
	* @return returns the evaluation keys; index 0 of the vector corresponds to plaintext index 2, index 1 to plaintex index 3, etc.
	*/
	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
		const LPPrivateKey<Element> origPrivateKey, const std::vector<usint> &indexList) const {

		if( publicKey == NULL || origPrivateKey == NULL )
			PALISADE_THROW( type_error, "Null Keys");
		if( publicKey->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Key was not created in this CryptoContextImpl");
		if( publicKey->GetCryptoContext() != origPrivateKey->GetCryptoContext() )
			PALISADE_THROW( type_error, "Keys were not created in the same CryptoContextImpl");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalAutomorphismKeyGen(publicKey, origPrivateKey, indexList);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAutomorphismKeyGen, currentDateTime() - start) );
		}
		return rv;
	}



	/**
	* Function for evaluating automorphism of ciphertext at index i
	*
	* @param ciphertext the input ciphertext.
	* @param i automorphism index
	* @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalAutomorphism(const Ciphertext<Element> ciphertext, usint i,
		const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

		auto mf = evalKeys.begin();
		if( mf == evalKeys.end() )
			PALISADE_THROW( type_error, "Empty key map");
		auto tk = mf->second;
		if( ciphertext == NULL || tk == NULL )
			PALISADE_THROW( type_error, "Null inputs");
		if( ciphertext->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Ciphertext was not created in this CryptoContextImpl");
		if( ciphertext->GetCryptoContext() != tk->GetCryptoContext() )
			PALISADE_THROW( type_error, "Items were not created in the same CryptoContextImpl");
		if( ciphertext->GetKeyTag() != tk->GetKeyTag() )
			PALISADE_THROW( type_error, "Items were not encrypted with same keys" );

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalAutomorphism(ciphertext, i, evalKeys);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAutomorphismI, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* Generate automophism keys for a given private key; Uses the private key for encryption
	*
	* @param privateKey private key.
	* @param indexList list of automorphism indices to be computed
	* @return returns the evaluation keys
	*/
	shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<usint> &indexList) const {

		if( privateKey == NULL )
			PALISADE_THROW( type_error, "Null input");
		if( privateKey->GetCryptoContext().get() != this )
			PALISADE_THROW( type_error, "Key was not created in this CryptoContextImpl");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalAutomorphismKeyGen(privateKey, indexList);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAutomorphismK, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* EvalSumKeyGen Generates the key map to be used by evalsum
	*
	* @param privateKey private key.
	* @param publicKey public key (used in NTRU schemes).
	*/
	void EvalSumKeyGen(
		const LPPrivateKey<Element> privateKey, 
		const LPPublicKey<Element> publicKey = nullptr);

	/**
	 * GetEvalSumKey  returns the map
	 *
	 * @return the EvalSum key map
	 */
	static const std::map<usint, LPEvalKey<Element>>& GetEvalSumKeyMap(const string& id);

	static const std::map<string,shared_ptr<std::map<usint, LPEvalKey<Element>>>>& GetAllEvalSumKeys();

	/**
	* Function for evaluating a sum of all components
	*
	* @param ciphertext the input ciphertext.
	* @param batchSize size of the batch
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalSum(const Ciphertext<Element> ciphertext, usint batchSize) const;

	/**
	* Evaluates inner product in batched encoding
	*
	* @param ciphertext1 first vector.
	* @param ciphertext2 second vector.
	* @param batchSize size of the batch to be summed up
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalInnerProduct(const Ciphertext<Element> ciphertext1, const Ciphertext<Element> ciphertext2, usint batchSize) const;

	/**
	* Evaluates inner product in batched encoding
	*
	* @param ciphertext1 first vector.
	* @param ciphertext2 second vector.
	* @param batchSize size of the batch to be summed up
	* @return resulting ciphertext
	*/
	Ciphertext<Element> EvalInnerProduct(const Ciphertext<Element> ciphertext1, const Plaintext ciphertext2, usint batchSize) const;

	/**
	* EvalCrossCorrelation - Computes the sliding sum of inner products (known as
	* as cross-correlation, sliding inner product, or sliding dot product in
	* image processing
	* @param x - first vector of row vectors
	* @param y - second vector of row vectors
	* @param batchSize - batch size for packed encoding
	* @param indexStart - starting index in the vectors of row vectors
	* @param length - length of the slice in the vectors of row vectors; default is 0 meaning to use the full length of the vector
	* @return sum(x_i*y_i), i.e., a sum of inner products
	*/
	Ciphertext<Element>
		EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
			const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
			usint indexStart = 0, usint length = 0) const;

	/**
	* EvalLinRegressBatched- Computes the parameter vector for linear regression using the least squares method
	* Supported only in batched mode; currently works only for two regressors
	* @param x - matrix of regressors
	* @param y - vector of dependent variables
	* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>>
		EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
			const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize) const;

	/**
	* EvalLinRegression - Computes the parameter vector for linear regression using the least squares method
	* @param x - matrix of regressors
	* @param y - vector of dependent variables
	* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>>
		EvalLinRegression(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
			const shared_ptr<Matrix<RationalCiphertext<Element>>> y) const
	{
		TypeCheck((*x)(0,0), (*y)(0,0)); // TODO only checking one; when Matrix is refactored, this should be revisited

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalLinRegression(x, y);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpLinRegression, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* KeySwitch - PALISADE KeySwitch method
	* @param keySwitchHint - reference to KeySwitchHint
	* @param ciphertext - vector of ciphertext
	* @return new CiphertextImpl after applying key switch
	*/
	Ciphertext<Element> KeySwitch(
		const LPEvalKey<Element> keySwitchHint,
		const Ciphertext<Element> ciphertext) const
	{
		if( keySwitchHint == NULL || Mismatched(keySwitchHint->GetCryptoContext()) )
			throw std::logic_error("Key passed to KeySwitch was not generated with this crypto context");

		if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
			throw std::logic_error("Ciphertext passed to KeySwitch was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->KeySwitch(keySwitchHint, ciphertext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpKeySwitch, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * ModReduce - PALISADE ModReduce method
	 * @param ciphertext - vector of ciphertext
	 * @return vector of mod reduced ciphertext
	 */
	Ciphertext<Element> ModReduce(Ciphertext<Element> ciphertext) const {
		if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
			throw std::logic_error("Information passed to ModReduce was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->ModReduce(ciphertext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpModReduce, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * ModReduce - PALISADE ModReduce method
	 * @param ciphertext - vector of ciphertext
	 * @return vector of mod reduced ciphertext
	 */
	RationalCiphertext<Element> ModReduceRational(RationalCiphertext<Element> ciphertext) const {

		double start = 0;
		if( doTiming ) start = currentDateTime();
		Ciphertext<Element> n = GetEncryptionAlgorithm()->ModReduce(ciphertext.GetNumerator());
		Ciphertext<Element> d = GetEncryptionAlgorithm()->ModReduce(ciphertext.GetDenominator());
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpModReduce, currentDateTime() - start) );
		}
		return RationalCiphertext<Element>(n,d);
	}

	/**
	 * ModReduce - PALISADE ModReduce method
	 * @param ciphertext - vector of ciphertext
	 * @return vector of mod reduced ciphertext
	 */
	shared_ptr<Matrix<RationalCiphertext<Element>>> ModReduceMatrix(shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext) const {
		// needs context check

		double start = 0;
		if( doTiming ) start = currentDateTime();
		shared_ptr<Matrix<RationalCiphertext<Element>>> m(
				new Matrix<RationalCiphertext<Element>>(ciphertext->GetAllocator(), ciphertext->GetRows(), ciphertext->GetCols()));
		for( size_t r = 0; r < m->GetRows(); r++ )
			for( size_t c = 0; c < m->GetCols(); c++ )
				(*m)(r,c) = ModReduceRational((*ciphertext)(r,c));
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpModReduceMatrix, currentDateTime() - start) );
		}
		return m;
	}

	/**
	* LevelReduce - PALISADE LevelReduce method
	* @param cipherText1
	* @param linearKeySwitchHint
	* @return vector of level reduced ciphertext
	*/
	Ciphertext<Element> LevelReduce(const Ciphertext<Element> cipherText1,
		const LPEvalKeyNTRU<Element> linearKeySwitchHint) const {

		if( cipherText1 == NULL || linearKeySwitchHint == NULL ||
				Mismatched(cipherText1->GetCryptoContext()) ||
				Mismatched(linearKeySwitchHint->GetCryptoContext()) ) {
			throw std::logic_error("Information passed to LevelReduce was not generated with this crypto context");
		}

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->LevelReduce(cipherText1, linearKeySwitchHint);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpLevelReduce, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* RingReduce - PALISADE RingReduce method
	* @param ciphertext - vector of ciphertext
	* @param keySwitchHint - the keySwitchHint from original private key to sparse private key
	* @return vector of ring-reduced ciphertexts
	*/

	Ciphertext<Element> RingReduce(
		Ciphertext<Element> ciphertext,
		const LPEvalKey<Element> keySwitchHint) const
	{
		if( keySwitchHint == NULL ||
				Mismatched(keySwitchHint->GetCryptoContext()) )
			throw std::logic_error("Key passed to RingReduce was not generated with this crypto context");

		if( ciphertext == NULL || Mismatched(ciphertext->GetCryptoContext()) )
			throw std::logic_error("Ciphertext passed to RingReduce was not generated with this crypto context");

		Ciphertext<Element> newCiphertext;

		double start = 0;
		if( doTiming ) start = currentDateTime();

		newCiphertext = GetEncryptionAlgorithm()->RingReduce(ciphertext, keySwitchHint);

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpRingReduce, currentDateTime() - start) );
		}
		return newCiphertext;
	}

	/**
	* ComposedEvalMult - PALISADE composed evalmult
	* @param ciphertext1 - vector for first cipher text
	* @param ciphertext2 - vector for second cipher text
	* @param quadKeySwitchHint - is the quadratic key switch hint from original private key to the quadratic key
	* return vector of resulting ciphertext
	*/
	Ciphertext<Element> ComposedEvalMult(
		const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2) const
	{
		if( ciphertext1 == NULL || ciphertext2 == NULL || ciphertext1->GetKeyTag() != ciphertext2->GetKeyTag() ||
				Mismatched(ciphertext1->GetCryptoContext()) )
			throw std::logic_error("Ciphertexts passed to ComposedEvalMult were not generated with this crypto context");

		auto ek = GetEvalMultKeyVector(ciphertext1->GetKeyTag());

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->ComposedEvalMult(ciphertext1, ciphertext2, ek[0]);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpComposedEvalMult, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* Deserialize into a Public Key
	* @param serObj
	* @return deserialized object
	*/
	static LPPublicKey<Element>	deserializePublicKey(const Serialized& serObj);

	/**
	* Deserialize into a Private Key
	* @param serObj
	* @return deserialized object
	*/
	static LPPrivateKey<Element>	deserializeSecretKey(const Serialized& serObj);

	/**
	* Deserialize into a Ciphertext
	* @param serObj
	* @return deserialized object
	*/
	static Ciphertext<Element>		deserializeCiphertext(const Serialized& serObj);

	/**
	* Deserialize into an Eval Key in a given context
	* @param serObj
	* @return deserialized object
	*/
	static LPEvalKey<Element>		deserializeEvalKey(const Serialized& serObj);

	/**
	* Deserialize into an Eval Key
	* @param serObj
	* @return deserialized object
	*/
	static LPEvalKey<Element>		deserializeEvalKeyInContext(const Serialized& serObj, CryptoContext<Element> cc);
};

/**
 * @brief CryptoObject
 *
 * A class to aid in referring to the crypto context that an object belongs to
 */
template<typename Element>
class CryptoObject {
protected:
	CryptoContext<Element>	context;		/*!< crypto context this object belongs to */
	string					keyTag;		/*!< tag used to find the evaluation key needed for SHE/FHE operations */

public:
	CryptoObject(CryptoContext<Element> cc = 0, const string& tag = "") : context(cc), keyTag(tag) {}

	CryptoObject(const CryptoObject& rhs) {
		context = rhs.context;
		keyTag = rhs.keyTag;
	}

	CryptoObject(const CryptoObject&& rhs) {
		context = std::move(rhs.context);
		keyTag = std::move(rhs.keyTag);
	}

	virtual ~CryptoObject() {}

	const CryptoObject& operator=(const CryptoObject& rhs) {
		this->context = rhs.context;
		this->keyTag = rhs.keyTag;
		return *this;
	}

	const CryptoObject& operator=(const CryptoObject&& rhs) {
		this->context = std::move(rhs.context);
		this->keyTag = std::move(rhs.keyTag);
		return *this;
	}

	bool operator==(const CryptoObject& rhs) const {
		return context.get() == rhs.context.get() &&
				keyTag == rhs.keyTag;
	}

	CryptoContext<Element> GetCryptoContext() const { return context; }

	const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return context->GetCryptoParameters(); }

	const EncodingParams GetEncodingParameters() const { return context->GetCryptoParameters()->GetEncodingParams(); }

	const string GetKeyTag() const { return keyTag; }

	void SetKeyTag(const string& tag) { keyTag = tag; }

	/**
	* SerializeCryptoObject serializes this header into a Serialized
	* @param serObj is used to store the serialized result.
	* @return true if successfully serialized
	*/
	bool SerializeCryptoObject(Serialized* serObj, bool includeContext = true) const;

	/**
	* DeserializeCryptoObject Populates this header from the deserialization of the Serialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	bool DeserializeCryptoObject(const Serialized& serObj, bool includesContext = true);
};

/**
* @brief CryptoContextFactory
*
* A class that contains static methods to generate new crypto contexts from user parameters
*
*/
template<typename Element>
class CryptoContextFactory {
	static vector<CryptoContext<Element>>		AllContexts;

public:
	static void ReleaseAllContexts();

	static int GetContextCount();

	static CryptoContext<Element> GetSingleContext();

	static CryptoContext<Element> GetContext(
			shared_ptr<LPCryptoParameters<Element>> params,
			shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme);

	static CryptoContext<Element> GetContextForPointer(
			CryptoContextImpl<Element>* cc);

	static const vector<CryptoContext<Element>>& GetAllContexts() { return AllContexts; }

	/**
	* construct a PALISADE CryptoContextImpl for the LTV Scheme
	* @param plaintextmodulus
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param depth
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextLTV(shared_ptr<typename Element::Params> params,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContextImpl for the LTV Scheme
	* @param encodingParams
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param depth
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextLTV(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		usint relinWindow, float stDev, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContextImpl for the LTV Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus
	* @param securityLevel
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextLTV(
		const PlaintextModulus plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches);

	/**
	* construct a PALISADE CryptoContextImpl for the LTV Scheme using the scheme's ParamsGen methods
	* @param encodingParams
	* @param securityLevel
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextLTV(
		EncodingParams encodingParams, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme
	* @param plaintextmodulus
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param delta
	* @param mode
	* @param bigmodulus
	* @param bigrootofunity
	* @param depth
	* @param assuranceMeasure
	* @param securityLevel
	* @param bigmodulusarb
	* @param bigrootofunityarb
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(shared_ptr<typename Element::Params> params,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
		int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
		const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0", int maxDepth = 2);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme
	* @param encodingParams
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param delta
	* @param mode
	* @param bigmodulus
	* @param bigrootofunity
	* @param depth
	* @param assuranceMeasure
	* @param securityLevel
	* @param bigmodulusarb
	* @param bigrootofunityarb
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
		int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
		const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0", int maxDepth = 2);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus
	* @param securityLevel
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(
		const PlaintextModulus plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2);

	/**
	* construct a PALISADE CryptoContextImpl for the BFV Scheme using the scheme's ParamsGen methods
	* @param encodingParams
	* @param securityLevel
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFV(
		EncodingParams encodingParams, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus
	* @param securityLevel
	* @param distribution parameter
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrns(
		const PlaintextModulus plaintextModulus, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2);

	/**
	* construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the scheme's ParamsGen methods
	* @param encodingParams
	* @param securityLevel
	* @param distribution parameter
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBFVrns(
		EncodingParams encodingParams, float securityLevel, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2);

	/**
	* construct a PALISADE CryptoContextImpl for the BGV Scheme
	* @param plaintextmodulus
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param mode
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBGV(shared_ptr<typename Element::Params> params,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode = RLWE, int depth = 1);

	/**
	* construct a PALISADE CryptoContextImpl for the BGV Scheme
	* @param encodingParams
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param mode
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextBGV(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		usint relinWindow, float stDev,
		MODE mode = RLWE, int depth = 1);

	/**
	* construct a PALISADE CryptoContextImpl for the StehleSteinfeld Scheme
	* @param plaintextmodulus
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param stDevStSt
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextStehleSteinfeld(shared_ptr<typename Element::Params> params,
		const PlaintextModulus plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContextImpl for the StehleSteinfeld Scheme
	* @param encodingParams
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param stDevStSt
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextStehleSteinfeld(shared_ptr<typename Element::Params> params,
		EncodingParams encodingParams,
		usint relinWindow, float stDev, float stDevStSt, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContextImpl for the Null Scheme
	* @param plaintext modulus
	* @return
	*/
	static CryptoContext<Element> genCryptoContextNull(unsigned int m, const PlaintextModulus ptModulus);

	/**
	* construct a PALISADE CryptoContextImpl for the Null Scheme
	* @param encodingParams
	* @return
	*/
	static CryptoContext<Element> genCryptoContextNull(unsigned int m, EncodingParams encodingParams);

	/**
	* Create a PALISADE CryptoContextImpl from a serialization
	* @param serObj
	* @return new context
	*/
	static CryptoContext<Element> DeserializeAndCreateContext(const Serialized& serObj);
};


}

#endif /* SRC_DEMO_PRE_CRYPTOCONTEXT_H_ */
