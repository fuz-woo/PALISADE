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
#include "encoding/plaintext.h"
#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"
#include "cryptocontexthelper.h"
#include "cryptotiming.h"

namespace lbcrypto {

template<typename Element>
class CryptoContextFactory;

/**
 * @brief CryptoContext
 *
 * A CryptoContext is the object used to access the PALISADE library
 *
 * All PALISADE functionality is accessed by way of an instance of a CryptoContext; we say that various objects are
 * "created in" a context, and can only be used in the context in which they were created
 *
 * All PALISADE methods are accessed through CryptoContext methods. Guards are implemented to make certain that
 * only valid objects that have been created in the context are used
 *
 * Contexts are created using the CryptoContextFactory, and can be serialized and recovered from a serialization
 */
template<typename Element>
class CryptoContext : public Serializable {
	friend class CryptoContextFactory<Element>;

private:
	shared_ptr<LPCryptoParameters<Element>>					params;			/*!< crypto parameters used for this context */
	shared_ptr<LPPublicKeyEncryptionScheme<Element>>		scheme;			/*!< algorithm used; accesses all crypto methods */
	vector<shared_ptr<LPEvalKey<Element>>>					evalMultKeys;	/*!< cached evalmult keys */
	std::map<usint, shared_ptr<LPEvalKey<Element>>>			evalSumKeys;	/*!< cached evalsum keys */

	bool doTiming;
	vector<TimingInfo>* timeSamples;

	/**
	 * Private methods to compare two contexts; this is only used internally and is not generally available
	 * @param a - shared pointer in the object
	 * @param b - this object, usually
	 * @return true if the shared pointer is a pointer to "this"
	 */
	friend bool operator==(const CryptoContext<Element>& a, const CryptoContext<Element>& b) {
		if( a.params.get() != b.params.get() ) return false;

		if( a.evalMultKeys.size() != b.evalMultKeys.size() ) return false;
		for( size_t i=0; i<a.evalMultKeys.size(); i++ )
			if( a.evalMultKeys[i].get() != b.evalMultKeys[i].get() )
				return false;

		if( a.evalSumKeys.size() != b.evalSumKeys.size() ) return false;
		for (const auto& kp : a.evalSumKeys) {
			const auto& vb = b.evalSumKeys.find(kp.first);
			if( vb == b.evalSumKeys.end() ) return false; // key in a not in b
			if( *kp.second != *vb->second )
				return false; // mismatch
		}
		return true;
	}

	friend bool operator!=(const CryptoContext<Element>& a, const CryptoContext<Element>& b) {
		return !( a == b );
	}

public:
	/**
	 * CryptoContext constructor from pointers to parameters and scheme
	 * @param params - pointer to CryptoParameters
	 * @param scheme - pointer to Crypto Scheme
	 */
	CryptoContext(LPCryptoParameters<Element> *params = 0, LPPublicKeyEncryptionScheme<Element> *scheme = 0) {
		this->params.reset(params);
		this->scheme.reset(scheme);
		this->doTiming = false;
		this->timeSamples = 0;
	}

	/**
	 * CryptoContext constructor from shared pointers to parameters and scheme
	 * @param params - shared pointer to CryptoParameters
	 * @param scheme - sharedpointer to Crypto Scheme
	 */
	CryptoContext(shared_ptr<LPCryptoParameters<Element>> params, shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme) {
		this->params = params;
		this->scheme = scheme;
		this->doTiming = false;
		this->timeSamples = 0;
	}

	/**
	 * Copy constructor
	 * @param c - source
	 */
	CryptoContext(const CryptoContext<Element>& c) {
		params = c.params;
		scheme = c.scheme;
		doTiming = c.doTiming;
		timeSamples = c.timeSamples;
		evalMultKeys = c.evalMultKeys;
		evalSumKeys = c.evalSumKeys;
	}

	/**
	 * Assignment
	 * @param rhs - assigning from
	 * @return this
	 */
	CryptoContext<Element>& operator=(const CryptoContext<Element>& rhs) {
		params = rhs.params;
		scheme = rhs.scheme;
		doTiming = rhs.doTiming;
		timeSamples = rhs.timeSamples;
		evalMultKeys = rhs.evalMultKeys;
		evalSumKeys = rhs.evalSumKeys;
		return *this;
	}

	/**
	 * A CryptoContext is only valid if the shared pointers are both valid
	 */
	operator bool() const { return bool(params) && bool(scheme); }

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

	/**
	 * Serialize the CryptoContext
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
	 * Enable a particular feature for use with this CryptoContext
	 * @param feature - the feature that should be enabled
	 */
	void Enable(PKESchemeFeature feature) { scheme->Enable(feature); }

	/**
	 * Enable several features at once
	 * @param featureMask - bitwise or of several PKESchemeFeatures
	 */
	void Enable(usint featureMask) { scheme->Enable(featureMask); }

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
	const BigInteger& GetModulus() const { return params->GetElementParams()->GetModulus(); }

	/**
	 * Get the ciphertext modulus used for this context
	 *
	 * @return
	 */
	const BigInteger& GetRootOfUnity() const { return params->GetElementParams()->GetRootOfUnity(); }

	/**
	* KeyGen generates a key pair using this algorithm's KeyGen method
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> KeyGen() {
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->KeyGen(this, false);
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
		const shared_ptr<LPPublicKey<Element>> pk) {
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->MultipartyKeyGen(this, pk, false);
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
		const vector<shared_ptr<LPPrivateKey<Element>>>& secretKeys) {
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r =  GetEncryptionAlgorithm()->MultipartyKeyGen(this, secretKeys, false);
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
	std::vector<shared_ptr<Ciphertext<Element>>> MultipartyDecryptLead(
		const shared_ptr<LPPrivateKey<Element>> privateKey,
		const std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext) const
	{
		if( privateKey == NULL || privateKey->GetCryptoContext() != this )
			throw std::logic_error("Information passed to MultipartyDecryptLead was not generated with this crypto context");

		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext;

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for( size_t i=0; i < ciphertext.size(); i++ ) {
			if( ciphertext[i] == NULL || ciphertext[i]->GetCryptoContext() != this )
				throw std::logic_error("One of the ciphertexts passed to MultipartyDecryptLead was not generated with this crypto context");
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
	std::vector<shared_ptr<Ciphertext<Element>>> MultipartyDecryptMain(
		const shared_ptr<LPPrivateKey<Element>> privateKey,
		const std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext) const
	{
		if( privateKey == NULL || privateKey->GetCryptoContext() != this )
			throw std::logic_error("Information passed to MultipartyDecryptMain was not generated with this crypto context");

		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext;

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for( size_t i=0; i < ciphertext.size(); i++ ) {
			if( ciphertext[i] == NULL || ciphertext[i]->GetCryptoContext() != this )
				throw std::logic_error("One of the ciphertexts passed to MultipartyDecryptMain was not generated with this crypto context");
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
		const std::vector<vector<shared_ptr<Ciphertext<Element>>>>& partialCiphertextVec,
		Plaintext *plaintext,
		bool doPadding = true) const
	{

		//Make sure we're processing ciphertexts.
		size_t last_ciphertext = partialCiphertextVec.size();
		if (last_ciphertext < 1 )
			return DecryptResult();

		//Make sure ciphertexts are of non-zero length and that they'r eof the same length/
		size_t ciphertext_size = partialCiphertextVec[0].size();
		for( size_t i = 0; i < last_ciphertext; i++ ) {
			std::vector<shared_ptr<Ciphertext<Element>>> ciphertext = partialCiphertextVec[i];
			// edge case
			if (ciphertext.size() == 0 || ciphertext.size() != ciphertext_size)
				return DecryptResult();
		}

		double start = 0;
		if( doTiming ) start = currentDateTime();
		size_t lastone = partialCiphertextVec[0].size() - 1;
		for( size_t ch = 0; ch < ciphertext_size; ch++ ) {

			vector<shared_ptr<Ciphertext<Element>>> ciphertextVec;

			for( size_t i = 0; i < last_ciphertext; i++ ) {
				std::vector<shared_ptr<Ciphertext<Element>>> ciphertext = partialCiphertextVec[i];
				// edge case
				if (ciphertext[ch] == NULL || ciphertext[ch]->GetCryptoContext() != this)
					throw std::logic_error("A ciphertext passed to MultipartyDecryptFusion was not generated with this crypto context");
				ciphertextVec.push_back(ciphertext[ch]);
			}

			Poly decrypted;
			DecryptResult result = GetEncryptionAlgorithm()->MultipartyDecryptFusion(ciphertextVec, &decrypted);

			if (result.isValid == false) return result;
			plaintext->Decode(ciphertextVec[0]->GetCryptoParameters()->GetPlaintextModulus(), &decrypted);
			if (ch == lastone && doPadding) {
				plaintext->Unpad(ciphertextVec[0]->GetCryptoParameters()->GetPlaintextModulus());
			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpMultiPartyDecryptFusion, currentDateTime() - start) );
		}
		return DecryptResult(plaintext->GetLength());
	}


	/**
	* SparseKeyGen generates a key pair with special structure, and without full entropy,
	* for use in special cases like Ring Reduction
	* @return a public/secret key pair
	*/
	LPKeyPair<Element> SparseKeyGen() {
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto r = GetEncryptionAlgorithm()->KeyGen(this, true);
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
	shared_ptr<LPEvalKey<Element>> ReKeyGen(
		const shared_ptr<LPPublicKey<Element>> newKey,
		const shared_ptr<LPPrivateKey<Element>> oldKey) const {

		if( newKey == NULL || oldKey == NULL || newKey->GetCryptoContext() != this || oldKey->GetCryptoContext() != this )
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
	shared_ptr<LPEvalKey<Element>> ReKeyGen(
		const shared_ptr<LPPrivateKey<Element>> newKey,
		const shared_ptr<LPPrivateKey<Element>> oldKey) const {

		if (newKey == NULL || oldKey == NULL || newKey->GetCryptoContext() != this || oldKey->GetCryptoContext() != this)
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
	void EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> key);

	/**
	 * GetEvalMultKey fetches the cached eval mult keys
	 *
	 * @return the key to use
	 */
	const shared_ptr<LPEvalKey<Element>> GetEvalMultKey() const {
		if( evalMultKeys.size() != 1 )
			throw std::logic_error("You need to use EvalMultKeyGen so that you have an EvalMultKey available");
		return evalMultKeys[0];
	}

	/**
	 * SetEvalMultKeys is used by the deserializer to initialize the keyset for EvalSum
	 * FIXME should be private?
	 * @param evalMultKeys - new key map
	 */
	void SetEvalMultKeys(vector<shared_ptr<LPEvalKey<Element>>>& evalMultKeysNew) {
		evalMultKeys.clear();
		this->evalMultKeys = evalMultKeysNew;
	}

	/**
	* KeySwitchGen creates a key that can be used with the PALISADE KeySwitch operation
	* @param key1
	* @param key2
	* @return new evaluation key
	*/
	shared_ptr<LPEvalKey<Element>> KeySwitchGen(
		const shared_ptr<LPPrivateKey<Element>> key1, const shared_ptr<LPPrivateKey<Element>> key2) const {

		if( key1 == NULL || key2 == NULL || key1->GetCryptoContext() != this || key2->GetCryptoContext() != this )
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
	* Encrypt method for PALISADE
	* @param publicKey - for encryption
	* @param plaintext - to encrypt
	* @param doPadding - if true, pad the input out to fill the encrypted chunk
	* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	* @return a vector of pointers to Ciphertexts created by encrypting the plaintext
	*/
	std::vector<shared_ptr<Ciphertext<Element>>> Encrypt(
		const shared_ptr<LPPublicKey<Element>> publicKey,
		const Plaintext& plaintext,
		bool doPadding = true, bool doEncryption = true) const
	{
		std::vector<shared_ptr<Ciphertext<Element>>> cipherResults;

		if( publicKey == NULL || publicKey->GetCryptoContext() != this )
			throw std::logic_error("key passed to Encrypt was not generated with this crypto context");

		const BigInteger& ptm = publicKey->GetCryptoParameters()->GetPlaintextModulus();
		size_t chunkSize = plaintext.GetChunksize(publicKey->GetCryptoContext()->GetRingDimension(), ptm);
		size_t ptSize = plaintext.GetLength();
		size_t rounds = ptSize / chunkSize;

		if (doPadding == false && ptSize%chunkSize != 0
			&& typeid(plaintext) == typeid(BytePlaintextEncoding)) {
			throw std::logic_error("Cannot Encrypt without padding with chunksize " + std::to_string(chunkSize) + " and plaintext size " + std::to_string(ptSize));
		}

		// if there is a partial chunk OR if there isn't but we need to pad
		if (ptSize%chunkSize != 0 || doPadding == true)
			rounds += 1;

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for (size_t bytes = 0, i = 0; i < rounds; bytes += chunkSize, i++) {

			Poly pt(publicKey->GetCryptoParameters()->GetElementParams());
			plaintext.Encode(ptm, &pt, bytes, chunkSize);

			shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, pt, doEncryption);

			if (!ciphertext) {
				cipherResults.clear();
				break;
			}

			cipherResults.push_back(ciphertext);

		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncrypt, currentDateTime() - start) );
		}
		return cipherResults;
	}

	/**
	* Encrypt a matrix of plaintexts (integer encoding)
	* @param publicKey - for encryption
	* @param plaintext - to encrypt
	* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	* @return a vector of pointers to Ciphertexts created by encrypting the plaintext
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>> EncryptMatrix(
		const shared_ptr<LPPublicKey<Element>> publicKey,
		const Matrix<IntPlaintextEncoding> &plaintext,
		bool doEncryption = true)
	{

		auto zeroAlloc = [=]() { return make_unique<RationalCiphertext<Element>>(this, true); };

		shared_ptr<Matrix<RationalCiphertext<Element>>> cipherResults(new Matrix<RationalCiphertext<Element>>
			(zeroAlloc, plaintext.GetRows(), plaintext.GetCols()));

		if (publicKey == NULL || publicKey->GetCryptoContext() != this)
			throw std::logic_error("key passed to EncryptMatrix was not generated with this crypto context");

		const BigInteger& ptm = publicKey->GetCryptoParameters()->GetPlaintextModulus();

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for (size_t row = 0; row < plaintext.GetRows(); row++)
		{
			for (size_t col = 0; col < plaintext.GetCols(); col++)
			{
				Poly pt(publicKey->GetCryptoParameters()->GetElementParams());
				plaintext(row,col).Encode(ptm, &pt);

				shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, pt, doEncryption);

				(*cipherResults)(row, col).SetNumerator(*ciphertext);
			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptMatrixPlain, currentDateTime() - start) );
		}
		return cipherResults;

	}

	/**
	* Encrypt a matrix of plaintexts (packed encoding)
	* @param publicKey - for encryption
	* @param plaintext - to encrypt
	* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
	* @return a vector of pointers to Ciphertexts created by encrypting the plaintext
	*/
	shared_ptr<Matrix<RationalCiphertext<Element>>> EncryptMatrix(
		const shared_ptr<LPPublicKey<Element>> publicKey,
		const Matrix<PackedIntPlaintextEncoding> &plaintext,
		bool doEncryption = true)
	{

		auto zeroAlloc = [=]() { return make_unique<RationalCiphertext<Element>>(this, true); };

		shared_ptr<Matrix<RationalCiphertext<Element>>> cipherResults(new Matrix<RationalCiphertext<Element>>
			(zeroAlloc, plaintext.GetRows(), plaintext.GetCols()));

		if (publicKey == NULL || publicKey->GetCryptoContext() != this)
			throw std::logic_error("key passed to EncryptMatrix was not generated with this crypto context");

		const BigInteger& ptm = publicKey->GetCryptoParameters()->GetPlaintextModulus();

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for (size_t row = 0; row < plaintext.GetRows(); row++)
		{
			for (size_t col = 0; col < plaintext.GetCols(); col++)
			{
				Poly pt(publicKey->GetCryptoParameters()->GetElementParams());
				plaintext(row, col).Encode(ptm, &pt);

				shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, pt, doEncryption);

				(*cipherResults)(row, col).SetNumerator(*ciphertext);
			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEncryptMatrixPacked, currentDateTime() - start) );
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
		const shared_ptr<LPPublicKey<Element>> publicKey,
		std::istream& instream,
		std::ostream& outstream,
		bool doEncryption = true) const
	{
		// NOTE timing this operation is not supported

		if( publicKey == NULL || publicKey->GetCryptoContext() != this )
			throw std::logic_error("key passed to EncryptStream was not generated with this crypto context");

		bool padded = false;
		BytePlaintextEncoding px;
		const BigInteger& ptm = publicKey->GetCryptoContext()->GetCryptoParameters()->GetPlaintextModulus();
		size_t chunkSize = px.GetChunksize(publicKey->GetCryptoContext()->GetRingDimension(), ptm);
		char *ptxt = new char[chunkSize];

		while (instream.good()) {
			instream.read(ptxt, chunkSize);
			size_t nRead = instream.gcount();

			if (nRead <= 0 && padded)
				break;

			BytePlaintextEncoding px(ptxt, nRead);

			if (nRead < chunkSize) {
				padded = true;
			}

			Poly pt(publicKey->GetCryptoParameters()->GetElementParams());
			px.Encode(publicKey->GetCryptoParameters()->GetPlaintextModulus(), &pt, 0, chunkSize);

			shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, pt, doEncryption);
			if (!ciphertext) {
				delete [] ptxt;
				return;
			}

			Serialized cS;

			if (ciphertext->Serialize(&cS)) {
				if (!SerializableHelper::SerializationToStream(cS, outstream)) {
					delete [] ptxt;
					return;
				}
			}
			else {
				delete [] ptxt;
				return;
			}
		}

		delete [] ptxt;
		return;
	}

	/**
	* Decrypt method for PALISADE
	* @param privateKey - for decryption
	* @param ciphertext - vector of encrypted ciphertext
	* @param plaintext - pointer to destination for the result of decryption
	* @param doPadding - true if input plaintext was padded; causes unpadding on last piece of ciphertext
	* @return size of plaintext
	*/
	DecryptResult Decrypt(
		const shared_ptr<LPPrivateKey<Element>> privateKey,
		const std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext,
		Plaintext *plaintext,
		bool doPadding = true) const
	{
		// edge case
		if (ciphertext.size() == 0)
			return DecryptResult();

		if( privateKey == NULL || privateKey->GetCryptoContext() != this )
			throw std::logic_error("Information passed to Decrypt was not generated with this crypto context");

		size_t lastone = ciphertext.size() - 1;
		double start = 0;
		if( doTiming ) start = currentDateTime();
		for( size_t ch = 0; ch < ciphertext.size(); ch++ ) {
			if( ciphertext[ch] == NULL || ciphertext[ch]->GetCryptoContext() != this )
				throw std::logic_error("A ciphertext passed to Decrypt was not generated with this crypto context");

			Poly decrypted;
			DecryptResult result = GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext[ch], &decrypted);

			if (result.isValid == false) return result;
			plaintext->Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decrypted);
			if (ch == lastone && doPadding) {
				plaintext->Unpad(privateKey->GetCryptoParameters()->GetPlaintextModulus());
			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpDecrypt, currentDateTime() - start) );
		}
		return DecryptResult(plaintext->GetLength());
	}

	/**
	* Decrypt method for a matrix of ciphertexts (integer encoding)
	* @param privateKey - for decryption
	* @param ciphertext - matrix of encrypted ciphertexts
	* @param plaintext - pointer to the destination martrix of plaintexts
	* @return size of plaintext
	*/
	DecryptResult DecryptMatrix(
		const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext,
		Matrix<IntPlaintextEncoding> *numerator,
		Matrix<IntPlaintextEncoding> *denominator) const
	{

		// edge case
		if ((ciphertext->GetCols()== 0) && (ciphertext->GetRows() == 0))
			return DecryptResult();

		if ((ciphertext->GetCols() != numerator->GetCols())|| (ciphertext->GetRows() != numerator->GetRows()) || 
			(ciphertext->GetCols() != denominator->GetCols()) || (ciphertext->GetRows() != denominator->GetRows()))
			throw std::runtime_error("Ciphertext and plaintext matrices have different dimensions");

		if (privateKey == NULL || privateKey->GetCryptoContext() != this)
			throw std::runtime_error("Information passed to DecryptMatrix was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for (size_t row = 0; row < ciphertext->GetRows(); row++)
		{
			for (size_t col = 0; col < ciphertext->GetCols(); col++)
			{
				if ((*ciphertext)(row, col).GetCryptoContext() != this)
					throw std::runtime_error("A ciphertext passed to DecryptMatrix was not generated with this crypto context");

				const shared_ptr<Ciphertext<Element>> ctN = (*ciphertext)(row, col).GetNumerator();

				Poly decryptedNumerator;
				DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator);

				if (resultN.isValid == false) return resultN;

				(*numerator)(row,col).Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decryptedNumerator);

				Poly decryptedDenominator;
				if( (*ciphertext)(row,col).GetIntegerFlag() == true ) {
					decryptedDenominator = decryptedNumerator.CloneParametersOnly();
					decryptedDenominator.SetValuesToZero();
					decryptedDenominator.SetValAtIndex(0,1);
				}
				else {

					const shared_ptr<Ciphertext<Element>> ctD = (*ciphertext)(row, col).GetDenominator();

					DecryptResult resultD = GetEncryptionAlgorithm()->Decrypt(privateKey, ctD, &decryptedDenominator);

					if (resultD.isValid == false) return resultD;

				}

				(*denominator)(row, col).Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decryptedDenominator);

			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpDecryptMatrixPlain, currentDateTime() - start) );
		}
		return DecryptResult((*numerator)(numerator->GetRows()-1,numerator->GetCols()-1).GetLength());

	}

	/**
	* Decrypt method for a matrix of ciphertexts (packed encoding)
	* @param privateKey - for decryption
	* @param ciphertext - matrix of encrypted ciphertexts
	* @param plaintext - pointer to the destination martrix of plaintexts
	* @return size of plaintext
	*/
	DecryptResult DecryptMatrix(
		const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext,
		Matrix<PackedIntPlaintextEncoding> *numerator,
		Matrix<PackedIntPlaintextEncoding> *denominator) const
	{

		// edge case
		if ((ciphertext->GetCols() == 0) && (ciphertext->GetRows() == 0))
			return DecryptResult();

		if ((ciphertext->GetCols() != numerator->GetCols()) || (ciphertext->GetRows() != numerator->GetRows()) ||
			(ciphertext->GetCols() != denominator->GetCols()) || (ciphertext->GetRows() != denominator->GetRows()))
			throw std::runtime_error("Ciphertext and plaintext matrices have different dimensions");

		if (privateKey == NULL || privateKey->GetCryptoContext() != this)
			throw std::runtime_error("Information passed to DecryptMatrix was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for (size_t row = 0; row < ciphertext->GetRows(); row++)
		{
			for (size_t col = 0; col < ciphertext->GetCols(); col++)
			{
				if ((*ciphertext)(row, col).GetCryptoContext() != this)
					throw std::runtime_error("A ciphertext passed to DecryptMatrix was not generated with this crypto context");

				const shared_ptr<Ciphertext<Element>> ctN = (*ciphertext)(row, col).GetNumerator();

				Poly decryptedNumerator;
				DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator);

				if (resultN.isValid == false) return resultN;

				(*numerator)(row, col).Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decryptedNumerator);

				const shared_ptr<Ciphertext<Element>> ctD = (*ciphertext)(row, col).GetDenominator();

				Poly decryptedDenominator;
				DecryptResult resultD = GetEncryptionAlgorithm()->Decrypt(privateKey, ctD, &decryptedDenominator);

				if (resultD.isValid == false) return resultD;

				(*denominator)(row, col).Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decryptedDenominator);

			}
		}

		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpDecryptMatrixPacked, currentDateTime() - start) );
		}
		return DecryptResult((*numerator)(numerator->GetRows() - 1, numerator->GetCols() - 1).GetLength());

	}

	/**
	* Decrypt method for numerators in a matrix of ciphertexts (packed encoding)
	* @param privateKey - for decryption
	* @param ciphertext - matrix of encrypted ciphertexts
	* @param plaintext - pointer to the destination martrix of plaintexts
	* @return size of plaintext
	*/
	DecryptResult DecryptMatrixNumerator(
		const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> ciphertext,
		Matrix<PackedIntPlaintextEncoding> *numerator) const
	{

		// edge case
		if ((ciphertext->GetCols() == 0) && (ciphertext->GetRows() == 0))
			return DecryptResult();

		if ((ciphertext->GetCols() != numerator->GetCols()) || (ciphertext->GetRows() != numerator->GetRows()))
			throw std::runtime_error("Ciphertext and plaintext matrices have different dimensions");

		if (privateKey == NULL || privateKey->GetCryptoContext() != this)
			throw std::runtime_error("Information passed to DecryptMatrix was not generated with this crypto context");

		double start = 0;
		if (doTiming) start = currentDateTime();


		//force all precomputations to take place in advance
		if ((*ciphertext)(0, 0).GetCryptoContext() != this)
			throw std::runtime_error("A ciphertext passed to DecryptMatrix was not generated with this crypto context");

		const shared_ptr<Ciphertext<Element>> ctN = (*ciphertext)(0, 0).GetNumerator();

		Poly decryptedNumerator;
		//DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator);
		GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator);

		//if (resultN.isValid == false) return resultN;

		(*numerator)(0, 0).Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decryptedNumerator);


		for (size_t row = 0; row < ciphertext->GetRows(); row++)
		{
#pragma omp parallel for
			for (size_t col = 0; col < ciphertext->GetCols(); col++)
			{

				if (row + col > 0)
				{
					if ((*ciphertext)(row, col).GetCryptoContext() != this)
						throw std::runtime_error("A ciphertext passed to DecryptMatrix was not generated with this crypto context");

					const shared_ptr<Ciphertext<Element>> ctN = (*ciphertext)(row, col).GetNumerator();

					Poly decryptedNumerator;
					//DecryptResult resultN = GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator);
					GetEncryptionAlgorithm()->Decrypt(privateKey, ctN, &decryptedNumerator);

					//if (resultN.isValid == false) return resultN;

					(*numerator)(row, col).Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decryptedNumerator);
				}

			}
		}

		if (doTiming) {
			timeSamples->push_back(TimingInfo(OpDecryptMatrixPacked, currentDateTime() - start));
		}
		return DecryptResult((*numerator)(numerator->GetRows() - 1, numerator->GetCols() - 1).GetLength());

	}

	/**
	* read instream for a sequence of serialized ciphertext; deserialize it, decrypt it, and write it to outstream
	* @param privateKey - reference to the decryption key
	* @param instream - input stream with sequence of serialized ciphertexts
	* @param outstream - output stream for plaintext
	* @return
	*/
	void DecryptStream(
		const shared_ptr<LPPrivateKey<Element>> privateKey,
		std::istream& instream,
		std::ostream& outstream)
	{
		// NOTE timing this operation is not supported

		if( privateKey == NULL || privateKey->GetCryptoContext() != this )
			throw std::logic_error("Information passed to DecryptStream was not generated with this crypto context");

		Serialized serObj;
		size_t tot = 0;

		bool firstTime = true;
		BytePlaintextEncoding pte[2];
		bool whichArray = false;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			shared_ptr<Ciphertext<Element>> ct;
			if( (ct = deserializeCiphertext(serObj)) != NULL ) {
				Poly decrypted;
				DecryptResult res = GetEncryptionAlgorithm()->Decrypt(privateKey, ct, &decrypted);
				if( !res.isValid )
					return;
				tot += res.messageLength;

				pte[whichArray].Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decrypted);

				if( !firstTime ) {
					outstream << pte[!whichArray];
					pte[!whichArray].clear();
				}
				firstTime = false;
				whichArray = !whichArray;
			}
			else
				return;
		}

		// unpad and write the last one
		pte[!whichArray].Unpad(privateKey->GetCryptoParameters()->GetPlaintextModulus());
		outstream << pte[!whichArray];

		return;
	}

	/**
	* ReEncrypt - Proxy Re Encryption mechanism for PALISADE
	* @param evalKey - evaluation key from the PRE keygen method
	* @param ciphertext - vector of shared pointers to encrypted Ciphertext
	* @return vector of shared pointers to re-encrypted ciphertexts
	*/
	std::vector<shared_ptr<Ciphertext<Element>>> ReEncrypt(
		shared_ptr<LPEvalKey<Element>> evalKey,
		std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext) const
	{
		if( evalKey == NULL || evalKey->GetCryptoContext() != this )
			throw std::logic_error("Information passed to ReEncrypt was not generated with this crypto context");

		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext;
		double start = 0;
		if( doTiming ) start = currentDateTime();
		for( size_t i=0; i < ciphertext.size(); i++ ) {
			if( ciphertext[i] == NULL || ciphertext[i]->GetCryptoContext() != this )
				throw std::logic_error("One of the ciphertexts passed to ReEncrypt was not generated with this crypto context");
			newCiphertext.push_back( GetEncryptionAlgorithm()->ReEncrypt(evalKey, ciphertext[i]) );
		}

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
		const shared_ptr<LPEvalKey<Element>> evalKey,
		std::istream& instream,
		std::ostream& outstream)
	{
		// NOTE timing this operation is not supported

		if( evalKey == NULL || evalKey->GetCryptoContext() != this )
			throw std::logic_error("Information passed to ReEncryptStream was not generated with this crypto context");

		Serialized serObj;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			shared_ptr<Ciphertext<Element>> ct;
			ct = deserializeCiphertext(serObj);
			if( ct ) {
				std::vector<shared_ptr<Ciphertext<Element>>> allCt;
				allCt.push_back(ct);
				std::vector<shared_ptr<Ciphertext<Element>>> reCt = ReEncrypt(evalKey, allCt);

				Serialized serReObj;
				if( reCt[0]->Serialize(&serReObj) ) {
					SerializableHelper::SerializationToStream(serReObj, outstream);
				}
				else {
					return;
				}
				allCt.clear();
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
	shared_ptr<Ciphertext<Element>>
	EvalAdd(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2) const
	{
		if( ct1 == NULL || ct2 == NULL || ct1->GetCryptoContext() != this || ct2->GetCryptoContext() != this )
			throw std::logic_error("Information passed to EvalAdd was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalAdd(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalAdd, currentDateTime() - start) );
		}
		return rv;
	}

	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalAddMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		// tests needed for context

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
	shared_ptr<Ciphertext<Element>>
	EvalSub(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2) const
	{
		if( ct1 == NULL || ct2 == NULL || ct1->GetCryptoContext() != this || ct2->GetCryptoContext() != this )
			throw std::logic_error("Information passed to EvalSub was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalSub(ct1, ct2);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSub, currentDateTime() - start) );
		}
		return rv;
	}

	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalSubMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		// tests needed for context

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
	* EvalAddPLain - PALISADE EvalAdd method for a ciphertext and plaintext
	* @param ciphertext
	* @param plaintext
	* @return new ciphertext for ciphertext + plaintext 
	*/
	shared_ptr<Ciphertext<Element>>
		EvalAddPlain(const shared_ptr<Ciphertext<Element>> ciphertext, const shared_ptr<Ciphertext<Element>> plaintext) const
	{
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = EvalAdd(ciphertext, plaintext);
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
	shared_ptr<Ciphertext<Element>>
		EvalSubPlain(const shared_ptr<Ciphertext<Element>> ciphertext, const shared_ptr<Ciphertext<Element>> plaintext) const
	{
		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = EvalSub(ciphertext, plaintext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalSubPlain, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 * ct2
	 */
	shared_ptr<Ciphertext<Element>>
	EvalMult(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2) const
	{
		if( ct1 == NULL || ct2 == NULL || ct1->GetCryptoContext() != this || ct2->GetCryptoContext() != this )
			throw std::logic_error("Information passed to EvalMult was not generated with this crypto context");

		auto ek = GetEvalMultKey();

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, ct2, ek);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMult, currentDateTime() - start) );
		}
		return rv;
	}

	shared_ptr<Matrix<RationalCiphertext<Element>>>
	EvalMultMatrix(const shared_ptr<Matrix<RationalCiphertext<Element>>> ct1, const shared_ptr<Matrix<RationalCiphertext<Element>>> ct2) const
	{
		// tests needed for context

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
	* EvalMult - PALISADE EvalMult method for a a multiplication of ciphertext by plaintext
	* @param ct1
	* @param ct2
	* @return new ciphertext for ct1 * ct2
	*/
	shared_ptr<Ciphertext<Element>>
		EvalMultPlain(const shared_ptr<Ciphertext<Element>> ciphertext, const shared_ptr<Ciphertext<Element>> plaintext) const
	{
		if (ciphertext == NULL || plaintext == NULL || ciphertext->GetCryptoContext() != this || plaintext->GetCryptoContext() != this)
			throw std::logic_error("Information passed to EvalMult was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalMultPlain(ciphertext, plaintext);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMultPlain, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts, followed by recrypt with given key
	 * @param ct1
	 * @param ct2
	 * @param ek
	 * @return new ciphertext for ct1 * ct2, recrypted with ek
	 */
	shared_ptr<Ciphertext<Element>>
	EvalMult(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2, const shared_ptr<LPEvalKey<Element>> ek) const
	{
		if( ct1 == NULL || ct2 == NULL || ek == NULL || ct1->GetCryptoContext() != this || ct2->GetCryptoContext() != this || ek->GetCryptoContext() != this )
			throw std::logic_error("Information passed to EvalMult was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, ct2, ek);
		if( doTiming ) {
			timeSamples->push_back( TimingInfo(OpEvalMultKey, currentDateTime() - start) );
		}
		return rv;
	}

	/**
	* EvalSub - PALISADE Negate method for a ciphertext
	* @param ct
	* @return new ciphertext -ct
	*/
	shared_ptr<Ciphertext<Element>>
	EvalNegate(const shared_ptr<Ciphertext<Element>> ct) const
	{
		if (ct == NULL || ct->GetCryptoContext() != this)
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
	shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey, const std::vector<usint> &indexList) const {

		//need to add exception handling

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
	shared_ptr<Ciphertext<Element>> EvalAutomorphism(const shared_ptr<Ciphertext<Element>> ciphertext, usint i,
		const std::map<usint, shared_ptr<LPEvalKey<Element>>> &evalKeys) const {

		//need to add exception handling

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
	shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> EvalAutomorphismKeyGen(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const std::vector<usint> &indexList) const {

		//need to add exception handling

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
		const shared_ptr<LPPrivateKey<Element>> privateKey, 
		const shared_ptr<LPPublicKey<Element>> publicKey = nullptr);

	/**
	 * GetEvalSumKey  returns the map
	 *
	 * @return the EvalSum key map
	 */
	const std::map<usint, shared_ptr<LPEvalKey<Element>>>& GetEvalSumKey() const;

	/**
	 * SetEvalSumKeys - used by deserializer to set the keys for EvalSum
	 * FIXME should be private?
	 * @param evalSumKeys - new key map
	 */
	void SetEvalSumKeys(std::map<usint, shared_ptr<LPEvalKey<Element>>>& evalSumKeys) {
		this->evalSumKeys.clear();
		this->evalSumKeys = evalSumKeys;
	}

	/**
	* Function for evaluating a sum of all components
	*
	* @param ciphertext the input ciphertext.
	* @param batchSize size of the batch
	* @return resulting ciphertext
	*/
	shared_ptr<Ciphertext<Element>> EvalSum(const shared_ptr<Ciphertext<Element>> ciphertext, usint batchSize) const;

	/**
	* Evaluates inner product in batched encoding
	*
	* @param ciphertext1 first vector.
	* @param ciphertext2 second vector.
	* @param batchSize size of the batch to be summed up
	* @return resulting ciphertext
	*/
	shared_ptr<Ciphertext<Element>> EvalInnerProduct(const shared_ptr<Ciphertext<Element>> ciphertext1, const shared_ptr<Ciphertext<Element>> ciphertext2, usint batchSize) const;

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
	shared_ptr<Ciphertext<Element>>
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
		//if (ct1 == NULL || ct2 == NULL || ct1->GetCryptoContext() != this || ct2->GetCryptoContext() != this)
		//	throw std::logic_error("Information passed to EvalMult was not generated with this crypto context");

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
	* @return new Ciphertext after applying key switch
	*/
	shared_ptr<Ciphertext<Element>> KeySwitch(
		const shared_ptr<LPEvalKey<Element>> keySwitchHint,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
	{
		if( keySwitchHint == NULL || keySwitchHint->GetCryptoContext() != this )
			throw std::logic_error("Key passed to KeySwitch was not generated with this crypto context");

		if( ciphertext == NULL || ciphertext->GetCryptoContext() != this )
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
	shared_ptr<Ciphertext<Element>> ModReduce(shared_ptr<Ciphertext<Element>> ciphertext) const {
		if( ciphertext == NULL || ciphertext->GetCryptoContext() != this )
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
		shared_ptr<Ciphertext<Element>> n = GetEncryptionAlgorithm()->ModReduce(ciphertext.GetNumerator());
		shared_ptr<Ciphertext<Element>> d = GetEncryptionAlgorithm()->ModReduce(ciphertext.GetDenominator());
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
	shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<LPEvalKeyNTRU<Element>> linearKeySwitchHint) const {

		if( cipherText1 == NULL || linearKeySwitchHint == NULL || cipherText1->GetCryptoContext() != this || linearKeySwitchHint->GetCryptoContext() != this) {
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

	std::vector<shared_ptr<Ciphertext<Element>>> RingReduce(
		std::vector<shared_ptr<Ciphertext<Element>>> ciphertext,
		const shared_ptr<LPEvalKey<Element>> keySwitchHint) const
	{
		if( keySwitchHint == NULL || keySwitchHint->GetCryptoContext() != this )
			throw std::logic_error("Key passed to RingReduce was not generated with this crypto context");

		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext(ciphertext.size());

		double start = 0;
		if( doTiming ) start = currentDateTime();
		for (size_t i = 0; i < ciphertext.size(); i++) {
			if( ciphertext[i] == NULL || ciphertext[i]->GetCryptoContext() != this )
				throw std::logic_error("Ciphertext passed to RingReduce was not generated with this crypto context");

			newCiphertext[i] = GetEncryptionAlgorithm()->RingReduce(ciphertext[i], keySwitchHint);
		}

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
	shared_ptr<Ciphertext<Element>> ComposedEvalMult(
		const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const
	{
		if( ciphertext1 == NULL || ciphertext2 == NULL || ciphertext1->GetCryptoContext() != this || ciphertext2->GetCryptoContext() != this )
			throw std::logic_error("Ciphertexts passed to ComposedEvalMult was not generated with this crypto context");

		double start = 0;
		if( doTiming ) start = currentDateTime();
		auto rv = GetEncryptionAlgorithm()->ComposedEvalMult(ciphertext1, ciphertext2, GetEvalMultKey());
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
	shared_ptr<LPPublicKey<Element>>	deserializePublicKey(const Serialized& serObj);

	/**
	* Deserialize into a Private Key
	* @param serObj
	* @return deserialized object
	*/
	shared_ptr<LPPrivateKey<Element>>	deserializeSecretKey(const Serialized& serObj);

	/**
	* Deserialize into a Ciphertext
	* @param serObj
	* @return deserialized object
	*/
	shared_ptr<Ciphertext<Element>>		deserializeCiphertext(const Serialized& serObj);

	/**
	* Deserialize into an Eval Key
	* @param serObj
	* @return deserialized object
	*/
	shared_ptr<LPEvalKey<Element>>		deserializeEvalKey(const Serialized& serObj);
};

/**
 * @brief CryptoObject
 *
 * A class to aid in referring to the crypto context that an object belongs to
 */
template<typename Element>
class CryptoObject {
protected:
	CryptoContext<Element>	*context;

public:
	CryptoObject(CryptoContext<Element> *cc = 0) : context(cc) {}
	virtual ~CryptoObject() {}

	CryptoContext<Element> *GetCryptoContext() const { return context; }
	const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return context->GetCryptoParameters(); }
};

/**
* @brief CryptoContextFactory
*
* A class that contains static methods to generate new crypto contexts from user parameters
*
*/
template<typename Element>
class CryptoContextFactory {
public:
	/**
	* construct a PALISADE CryptoContext for the LTV Scheme
	* @param plaintextmodulus
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param depth
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextLTV(shared_ptr<typename Element::Params> params,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContext for the LTV Scheme
	* @param encodingParams
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param depth
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextLTV(shared_ptr<typename Element::Params> params,
		shared_ptr<EncodingParams> encodingParams,
		usint relinWindow, float stDev, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContext for the LTV Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus
	* @param securityLevel
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextLTV(
		const usint plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches);

	/**
	* construct a PALISADE CryptoContext for the LTV Scheme using the scheme's ParamsGen methods
	* @param encodingParams
	* @param securityLevel
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static CryptoContext<Element> genCryptoContextLTV(
		shared_ptr<EncodingParams> encodingParams, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches);

	/**
	* construct a PALISADE CryptoContext for the FV Scheme
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
	static shared_ptr<CryptoContext<Element>> genCryptoContextFV(shared_ptr<typename Element::Params> params,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
		int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
		const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0");

	/**
	* construct a PALISADE CryptoContext for the FV Scheme
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
	static shared_ptr<CryptoContext<Element>> genCryptoContextFV(shared_ptr<typename Element::Params> params,
		shared_ptr<EncodingParams> encodingParams,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
		int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
		const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0");

	/**
	* construct a PALISADE CryptoContext for the FV Scheme using the scheme's ParamsGen methods
	* @param plaintextModulus
	* @param securityLevel
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextFV(
		const usint plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED);

	/**
	* construct a PALISADE CryptoContext for the FV Scheme using the scheme's ParamsGen methods
	* @param encodingParams
	* @param securityLevel
	* @param numAdds
	* @param numMults
	* @param numKeyswitches
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextFV(
		shared_ptr<EncodingParams> encodingParams, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED);

	/**
	* construct a PALISADE CryptoContext for the BV Scheme
	* @param plaintextmodulus
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param mode
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextBV(shared_ptr<typename Element::Params> params,
		const usint plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode = RLWE, int depth = 1);

	/**
	* construct a PALISADE CryptoContext for the BV Scheme
	* @param encodingParams
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param mode
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextBV(shared_ptr<typename Element::Params> params,
		shared_ptr<EncodingParams> encodingParams,
		usint relinWindow, float stDev,
		MODE mode = RLWE, int depth = 1);

	/**
	* construct a PALISADE CryptoContext for the StehleSteinfeld Scheme
	* @param plaintextmodulus
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param stDevStSt
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextStehleSteinfeld(shared_ptr<typename Element::Params> params,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContext for the StehleSteinfeld Scheme
	* @param encodingParams
	* @param ringdim
	* @param modulus
	* @param rootOfUnity
	* @param relinWindow
	* @param stDev
	* @param stDevStSt
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextStehleSteinfeld(shared_ptr<typename Element::Params> params,
		shared_ptr<EncodingParams> encodingParams,
		usint relinWindow, float stDev, float stDevStSt, int depth = 1, int assuranceMeasure = 9, float securityLevel = 1.006);

	/**
	* construct a PALISADE CryptoContext for the Null Scheme
	* @param modulus
	* @return
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextNull(shared_ptr<typename Element::Params> ep, const usint ptModulus);

	/**
	* construct a PALISADE CryptoContext for the Null Scheme
	* @param modulus
	* @return
	*/
	static shared_ptr<CryptoContext<Element>> genCryptoContextNull(shared_ptr<typename Element::Params> ep, shared_ptr<EncodingParams> encodingParams);

	/**
	* Create a PALISADE CryptoContext from a serialization
	* @param serObj
	* @return new context
	*/
	static shared_ptr<CryptoContext<Element>> DeserializeAndCreateContext(const Serialized& serObj, bool noKeys = false);
};


}

#endif /* SRC_DEMO_PRE_CRYPTOCONTEXT_H_ */
