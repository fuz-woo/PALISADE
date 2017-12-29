/**
 * @file pubkeylp.h -- Public key type for lattice crypto operations.
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

#ifndef LBCRYPTO_CRYPTO_PUBKEYLP_H
#define LBCRYPTO_CRYPTO_PUBKEYLP_H

//Includes Section
#include <vector>
#include <iomanip>
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "utils/inttypes.h"
#include "utils/hashutil.h"
#include "math/distrgen.h"
#include "utils/serializablehelper.h"
#include "encoding/encodingparams.h"


/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	//forward declarations, used to resolve circular header dependencies
	template<typename Element>
	class CiphertextImpl;

	template<typename Element>
	using Ciphertext = shared_ptr<CiphertextImpl<Element>>;

	template<typename Element>
	class RationalCiphertext;

	template<typename Element>
	class LPCryptoParameters;

	template<typename Element>
	class LPCryptoParametersLTV;

	template<typename Element>
	class LPCryptoParametersBGV;

	template<typename Element>
	class LPCryptoParametersBFV;

	template<typename Element>
	class LPCryptoParametersStehleSteinfeld;

	template<typename Element>
	class CryptoObject;

	struct EncryptResult {

		explicit EncryptResult() : isValid(false), numBytesEncrypted(0) {}

		explicit EncryptResult(size_t len) : isValid(true), numBytesEncrypted(len) {}

		bool isValid;				/**< whether the encryption was successful */
		usint	numBytesEncrypted;	/**< count of the number of plaintext bytes that were encrypted */
	};

	/** 
	 * @brief Decryption result.  This represents whether the decryption of a cipheretext was performed correctly.
	 *
     * This is intended to eventually incorporate information about the amount of padding in a decoded ciphertext,
     * to ensure that the correct amount of padding is stripped away.
	 * It is intended to provided a very simple kind of checksum eventually.
	 * This notion of a decoding output is inherited from the crypto++ library.
	 * It is also intended to be used in a recover and restart robust functionality if not all ciphertext is recieved over a lossy channel, so that if all information is eventually recieved, decoding/decryption can be performed eventually.
	 * This is intended to be returned with the output of a decryption operation.
	 */
	struct DecryptResult {
		/**
		 * Constructor that initializes all message lengths to 0.
		 */
		explicit DecryptResult() : isValid(false), messageLength(0) {}

		/**
		 * Constructor that initializes all message lengths.
		 * @param len the new length.
		 */
		explicit DecryptResult(size_t len) : isValid(true), messageLength(len) {}

		bool isValid;			/**< whether the decryption was successful */
		usint messageLength;	/**< the length of the decrypted plaintext message */
	};

	/**
	 * @brief Abstract interface class for LP Keys
	 *
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPKey : public CryptoObject<Element>, public Serializable {
	public:
		LPKey(CryptoContext<Element> cc, const string& id = "") : CryptoObject<Element>(cc, id) {}

		LPKey(shared_ptr<CryptoObject<Element>> co) : CryptoObject<Element>(co) {}

		virtual ~LPKey() {}
	};

	template<typename Element>
	class LPPublicKeyImpl;

	template<typename Element>
	using LPPublicKey = shared_ptr<LPPublicKeyImpl<Element>>;

	/**
	 * @brief Concrete class for LP public keys
	 * @tparam Element a ring element.
	 */
	template <typename Element>
	class LPPublicKeyImpl : public LPKey<Element> {
		public:

			/**
			* Basic constructor for setting crypto params
			*
			* @param &cryptoParams is the reference to cryptoParams
			*/
			LPPublicKeyImpl(CryptoContext<Element> cc, const string& id = "") : LPKey<Element>(cc, id) {}

			/**
			* Copy constructor
			*
			*@param &rhs LPPublicKeyImpl to copy from
			*/
			explicit LPPublicKeyImpl(const LPPublicKeyImpl<Element> &rhs) : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
				m_h = rhs.m_h;
			}

			/**
			* Move constructor
			*
			*@param &rhs LPPublicKeyImpl to move from
			*/
			explicit LPPublicKeyImpl(LPPublicKeyImpl<Element> &&rhs) : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
				m_h = std::move(rhs.m_h);
			}

			/**
			* Assignment Operator.
			*
			* @param &rhs LPPublicKeyImpl to copy from
			*/
			const LPPublicKeyImpl<Element>& operator=(const LPPublicKeyImpl<Element> &rhs) {
				this->context = rhs.context;
				this->m_h = rhs.m_h;
				return *this;
			}

			/**
			* Move Assignment Operator.
			*
			* @param &rhs LPPublicKeyImpl to copy from
			*/
			const LPPublicKeyImpl<Element>& operator=(LPPublicKeyImpl<Element> &&rhs) {
				this->context = rhs.context;
				rhs.context = 0;
				m_h = std::move(rhs.m_h);
				return *this;
			}

			//@Get Properties

			/**
			 * Gets the computed public key 
			 * @return the public key element.
			 */
			const std::vector<Element> &GetPublicElements() const {
				return this->m_h;
			}
			
			//@Set Properties

			/**
			 * Sets the public key vector of Element.
			 * @param &element is the public key Element vector to be copied.
			 */
			void SetPublicElements(const std::vector<Element> &element) {
				m_h = element;
			}

			/**
			* Sets the public key vector of Element.
			* @param &&element is the public key Element vector to be moved.
			*/
			void SetPublicElements(std::vector<Element> &&element) {
				m_h = std::move(element);
			}

			/**
			* Sets the public key Element at index idx.
			* @param &element is the public key Element to be copied.
			*/
			void SetPublicElementAtIndex(usint idx, const Element &element) {
				m_h.insert(m_h.begin() + idx, element);
			}

			/**
			* Sets the public key Element at index idx.
			* @param &&element is the public key Element to be moved.
			*/
			void SetPublicElementAtIndex(usint idx, Element &&element) {
				m_h.insert(m_h.begin() + idx, std::move(element));
			}
			
			/**
			* Serialize the object into a Serialized
			* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @param fileFlag is an object-specific parameter for the serialization
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized *serObj) const;

			/**
			* Populate the object from the deserialization of the Serialized
			* @param &serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized &serObj);

			bool operator==(const LPPublicKeyImpl& other) const {
				if( !CryptoObject<Element>::operator ==(other) )
					return false;

				if( m_h.size() != other.m_h.size() )
					return false;

				for( size_t i = 0; i < m_h.size(); i++ )
					if( m_h[i] != other.m_h[i] )
						return false;

				return true;
			}

			bool operator!=(const LPPublicKeyImpl& other) const { return ! (*this == other); }

	private:
		std::vector<Element> m_h;
	};

	template<typename Element>
	class LPEvalKeyImpl;

	template<typename Element>
	using LPEvalKey = shared_ptr<LPEvalKeyImpl<Element>>;

	/**
	* @brief Abstract interface for LP evaluation/proxy keys
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyImpl : public LPKey<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyImpl(CryptoContext<Element> cc) : LPKey<Element>(cc) {}

		virtual ~LPEvalKeyImpl() {}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @param &a is the Element vector to be copied.
		*/

		virtual void SetAVector(const std::vector<Element> &a) {
			throw std::runtime_error("SetAVector copy operation not supported");
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&a is the Element vector to be moved.
		*/

		virtual void SetAVector(std::vector<Element> &&a) {
			throw std::runtime_error("SetAVector move operation not supported");
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @return Element vector A.
		*/

		virtual const std::vector<Element> &GetAVector() const {
			throw std::runtime_error("GetAVector operation not supported");
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @param &b is the Element vector to be copied.
		*/

		virtual void SetBVector(const std::vector<Element> &b) {
			throw std::runtime_error("SetBVector copy operation not supported");
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&b is the Element vector to be moved.
		*/

		virtual void SetBVector(std::vector<Element> &&b) {
			throw std::runtime_error("SetBVector move operation not supported");
		}

		/**
		* Getter function to access Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element vector B.
		*/

		virtual const std::vector<Element> &GetBVector() const {
			throw std::runtime_error("GetBVector operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &a is the Element to be copied.
		*/

		virtual void SetA(const Element &a) {
			throw std::runtime_error("SetA copy operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&a is the Element to be moved.
		*/
		virtual void SetA(Element &&a) {
			throw std::runtime_error("SetA move operation not supported");
		}

		/**
		* Getter function to access key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element.
		*/

		virtual const Element &GetA() const {
			throw std::runtime_error("GetA operation not supported");
		}

		friend bool operator==(const LPEvalKeyImpl& a, const LPEvalKeyImpl& b) {
			return a.key_compare(b);
		}

		friend bool operator!=(const LPEvalKeyImpl& a, LPEvalKeyImpl& b) { return ! (a == b); }

		virtual bool key_compare(const LPEvalKeyImpl& other) const = 0;
	};

	template<typename Element>
	class LPEvalKeyRelinImpl;

	template<typename Element>
	using LPEvalKeyRelin = shared_ptr<LPEvalKeyRelinImpl<Element>>;

	/**
	* @brief Concrete class for Relinearization keys of RLWE scheme
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyRelinImpl : public LPEvalKeyImpl<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/
		LPEvalKeyRelinImpl(CryptoContext<Element> cc) : LPEvalKeyImpl<Element>(cc) {}

		virtual ~LPEvalKeyRelinImpl() {}

		/**
		* Copy constructor
		*
		*@param &rhs key to copy from
		*/
		explicit LPEvalKeyRelinImpl(const LPEvalKeyRelinImpl<Element> &rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_rKey = rhs.m_rKey;
		}

		/**
		* Move constructor
		*
		*@param &rhs key to move from
		*/
		explicit LPEvalKeyRelinImpl(LPEvalKeyRelinImpl<Element> &&rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_rKey = std::move(rhs.m_rKey);
		}

		/**
		* Assignment Operator.
		*
		* @param &rhs key to copy from
		*/
		const LPEvalKeyRelinImpl<Element>& operator=(const LPEvalKeyRelinImpl<Element> &rhs) {
			this->context = rhs.context;
			this->m_rKey = rhs.m_rKey;
			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs key to move from
		*/
		const LPEvalKeyRelinImpl<Element>& operator=(LPEvalKeyRelinImpl<Element> &&rhs) {
			this->context = rhs.context;
			rhs.context = 0;
			m_rKey = std::move(rhs.m_rKey);
			return *this;
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &a is the Element vector to be copied.
		*/
		virtual void SetAVector(const std::vector<Element> &a) {
			m_rKey.insert(m_rKey.begin() + 0, a);
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &&a is the Element vector to be moved.
		*/
		virtual void SetAVector(std::vector<Element> &&a) {
			m_rKey.insert(m_rKey.begin() + 0, std::move(a));
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @return Element vector A.
		*/
		virtual const std::vector<Element> &GetAVector() const {
			return m_rKey.at(0);
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @param &b is the Element vector to be copied.
		*/
		virtual void SetBVector(const std::vector<Element> &b) {
			m_rKey.insert(m_rKey.begin() + 1, b);
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @param &&b is the Element vector to be moved.
		*/
		virtual void SetBVector(std::vector<Element> &&b) {
			m_rKey.insert(m_rKey.begin() + 1, std::move(b));
		}

		/**
		* Getter function to access Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @return Element vector B.
		*/
		virtual const std::vector<Element> &GetBVector() const {
			return m_rKey.at(1);
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj) const;

		/**
		* SerializeWithoutContext - serializes the object into a Serialized, withut the cryptocontext
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool SerializeWithoutContext(Serialized *serObj) const;

		/**
		 * Deserialize from the serialization
		 * @param serObj - contains the serialization
		 * @return true on success
		 */
		bool Deserialize(const Serialized &serObj);

		bool key_compare(const LPEvalKeyImpl<Element>& other) const {
			const LPEvalKeyRelinImpl<Element> &oth = dynamic_cast<const LPEvalKeyRelinImpl<Element> &>(other);

			if( !CryptoObject<Element>::operator==(other) )
				return false;

			if( this->m_rKey.size() != oth.m_rKey.size() ) return false;
			for( size_t i=0; i<this->m_rKey.size(); i++ ) {
				if( this->m_rKey[i].size() != oth.m_rKey[i].size() ) return false;
				for( size_t j=0; j<this->m_rKey[i].size(); j++ ) {
					if( this->m_rKey[i][j] != oth.m_rKey[i][j] )
						return false;
				}
			}
			return true;
		}

	private:
		//private member to store vector of vector of Element.
		std::vector< std::vector<Element> > m_rKey;
	};

	template<typename Element>
	class LPEvalKeyNTRURelinImpl;

	template<typename Element>
	using LPEvalKeyNTRURelin = shared_ptr<LPEvalKeyNTRURelinImpl<Element>>;

	/**
	* @brief Evaluation Relinearization keys for NTRU scheme.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyNTRURelinImpl : public LPEvalKeyImpl<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyNTRURelinImpl(CryptoContext<Element> cc) : LPEvalKeyImpl<Element>(cc) {}

		virtual ~LPEvalKeyNTRURelinImpl() {}

		/**
		* Copy constructor
		*
		*@param &rhs key to copy from
		*/
		explicit LPEvalKeyNTRURelinImpl(const LPEvalKeyNTRURelinImpl<Element> &rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_rKey = rhs.m_rKey;
		}

		/**
		* Move constructor
		*
		*@param &rhs key to move from
		*/
		explicit LPEvalKeyNTRURelinImpl(LPEvalKeyNTRURelinImpl<Element> &&rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_rKey = std::move(rhs.m_rKey);
		}

		/**
		* Assignment Operator.
		*
		* @param &rhs key to copy from
		*/
		const LPEvalKeyNTRURelinImpl<Element>& operator=(const LPEvalKeyNTRURelinImpl<Element> &rhs) {
			this->context = rhs.context;
			this->m_rKey = rhs.m_rKey;
			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs key to move from
		*/
		const LPEvalKeyNTRURelinImpl<Element>& operator=(LPEvalKeyNTRURelinImpl<Element> &&rhs) {
			this->context = rhs.context;
			rhs.context = 0;
			m_rKey = std::move(rhs.m_rKey);
			return *this;
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &a is the Element vector to be copied.
		*/
		virtual void SetAVector(const std::vector<Element> &a) {
			for (usint i = 0; i < a.size(); i++) {
				m_rKey.insert(m_rKey.begin() + i, a.at(i));
			}
		}


		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &&a is the Element vector to be moved.
		*/
		virtual void SetAVector(std::vector<Element> &&a) {
			m_rKey = std::move(a);
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @return Element vector A.
		*/
		virtual const std::vector<Element> &GetAVector() const {
			return m_rKey;
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj) const;

		/**
		* SerializeWithoutContext - serializes the object into a Serialized, withut the cryptocontext
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool SerializeWithoutContext(Serialized *serObj) const;

		/**
		 * Deserialize from the serialization
		 * @param serObj - contains the serialization
		 * @return true on success
		 */
		bool Deserialize(const Serialized &serObj);
		
		bool key_compare(const LPEvalKeyImpl<Element>& other) const {
			const LPEvalKeyNTRURelinImpl<Element> &oth = dynamic_cast<const LPEvalKeyNTRURelinImpl<Element> &>(other);

			if( !CryptoObject<Element>::operator ==(other) )
				return false;

			if( this->m_rKey.size() != oth.m_rKey.size() ) return false;
			for( size_t i=0; i<this->m_rKey.size(); i++ ) {
				if( this->m_rKey[i] != oth.m_rKey[i] )
					return false;
			}
			return true;
		}

	private:
		//private member to store vector of Element.
		std::vector<Element>  m_rKey;
	};

	template<typename Element>
	class LPEvalKeyNTRUImpl;

	template<typename Element>
	using LPEvalKeyNTRU = shared_ptr<LPEvalKeyNTRUImpl<Element>>;

	/**
	* @brief Concrete class for facilitating NTRU key switch.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyNTRUImpl : public LPEvalKeyImpl<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyNTRUImpl(CryptoContext<Element> cc) : LPEvalKeyImpl<Element>(cc) {}

		virtual ~LPEvalKeyNTRUImpl() {}

		/**
		* Copy constructor
		*
		*@param &rhs key to copy from
		*/
		explicit LPEvalKeyNTRUImpl(const LPEvalKeyNTRUImpl<Element> &rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_Key = rhs.m_Key;
		}

		/**
		* Move constructor
		*
		*@param &rhs key to move from
		*/
		explicit LPEvalKeyNTRUImpl(LPEvalKeyNTRUImpl<Element> &&rhs) : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
			m_Key = std::move(rhs.m_Key);
		}

		/**
		* Assignment Operator.
		*
		* @param &rhs key to copy from
		*/
		const LPEvalKeyNTRUImpl<Element>& operator=(const LPEvalKeyNTRUImpl<Element> &rhs) {
			this->context = rhs.context;
			this->m_Key = rhs.m_Key;
			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs key to move from
		*/
		const LPEvalKeyNTRUImpl<Element>& operator=(LPEvalKeyNTRUImpl<Element> &&rhs) {
			this->context = rhs.context;
			rhs.context = 0;
			m_Key = std::move(rhs.m_Key);
			return *this;
		}

		/**
		* Setter function to store NTRU key switch element.
		* Function copies the key.
		* Overrides the virtual function from base class LPEvalKeyImpl.
		*
		* @param &a is the key switch element to be copied.
		*/

		virtual void SetA(const Element &a) {
			m_Key = a;
		}

		/**
		* Setter function to store NTRU key switch Element.
		* Function moves the key.
		* Overrides the virtual function from base class LPEvalKeyImpl.
		*
		* @param &&a is the key switch Element to be moved.
		*/
		virtual void SetA(Element &&a) {
			m_Key = std::move(a);
		}

		/**
		* Getter function to access NTRU key switch Element.
		* Overrides the virtual function from base class LPEvalKeyImpl.
		*
		* @return NTRU key switch Element.
		*/

		virtual const Element& GetA() const {
			return m_Key;
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj) const;

		/**
		* SerializeWithoutContext - serializes the object into a Serialized, withut the cryptocontext
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool SerializeWithoutContext(Serialized *serObj) const;

		/**
		 * Deserialize from the serialization
		 * @param serObj - contains the serialization
		 * @return true on success
		 */
		bool Deserialize(const Serialized &serObj);

		bool key_compare(const LPEvalKeyImpl<Element>& other) const {
			const LPEvalKeyNTRUImpl<Element> &oth = dynamic_cast<const LPEvalKeyNTRUImpl<Element> &>(other);

			if( !CryptoObject<Element>::operator ==(other) )
				return false;

			if( this->m_Key != oth.m_Key )
				return false;

			return true;
		}

	private:

		/**
		* private member Element to store key.
		*/
		Element m_Key;
	};
	
	template<typename Element>
	class LPPrivateKeyImpl;

	template<typename Element>
	using LPPrivateKey = shared_ptr<LPPrivateKeyImpl<Element>>;

	/**
	* @brief Private key implementation template for Ring-LWE, NTRU-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPrivateKeyImpl : public LPKey<Element> {
	public:

		/**
		* Construct in context
		*/

		LPPrivateKeyImpl(CryptoContext<Element> cc) : LPKey<Element>(cc, GenerateUniqueKeyID()) {}

		/**
		* Copy constructor
		*@param &rhs the LPPrivateKeyImpl to copy from
		*/
		explicit LPPrivateKeyImpl(const LPPrivateKeyImpl<Element> &rhs) : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
			this->m_sk = rhs.m_sk;
		}

		/**
		* Move constructor
		*@param &rhs the LPPrivateKeyImpl to move from
		*/
		explicit LPPrivateKeyImpl(LPPrivateKeyImpl<Element> &&rhs) : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
			this->m_sk = std::move(rhs.m_sk);
		}

		/**
		* Assignment Operator.
		*
		* @param &rhs LPPrivateKeyto assign from.
		* @return the resulting LPPrivateKeyImpl
		*/
		const LPPrivateKeyImpl<Element>& operator=(const LPPrivateKeyImpl<Element> &rhs) {
			CryptoObject<Element>::operator=(rhs);
			this->m_sk = rhs.m_sk;
			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs LPPrivateKeyImpl to assign from.
		* @return the resulting LPPrivateKeyImpl
		*/
		const LPPrivateKeyImpl<Element>& operator=(LPPrivateKeyImpl<Element> &&rhs) {
			CryptoObject<Element>::operator=(rhs);
			this->m_sk = std::move(rhs.m_sk);
			return *this;
		}

		/**
		* Implementation of the Get accessor for private element.
		* @return the private element.
		*/
		const Element & GetPrivateElement() const { return m_sk; }

		/**
		* Set accessor for private element.
		* @private &x private element to set to.
		*/
		void SetPrivateElement(const Element &x) {
			m_sk = x;
		}

		/**
		* Set accessor for private element.
		* @private &x private element to set to.
		*/
		void SetPrivateElement(Element &&x) {
			m_sk = std::move(x);
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj) const;

		/**
		* Populate the object from the deserialization of the Setialized
		* @param &serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized &serObj);

		bool operator==(const LPPrivateKeyImpl& other) const {
			return CryptoObject<Element>::operator ==(other) &&
					m_sk == other.m_sk;
		}

		bool operator!=(const LPPrivateKeyImpl& other) const { return ! (*this == other); }

	private:

		static const size_t intsInID = 128 / (sizeof(uint32_t) * 8);

		static string GenerateUniqueKeyID() {
			std::uniform_int_distribution<uint32_t> distribution(0, std::numeric_limits<uint32_t>::max());
			std::stringstream s;
			s.fill('0');
			s << std::hex;
			for( size_t i = 0; i < intsInID; i++ )
				s << std::setw(8) << distribution(PseudoRandomNumberGenerator::GetPRNG());
			return s.str();
		}

		Element m_sk;
	};

	template <class Element>
	class LPKeyPair {
	public:
		LPPublicKey<Element>		publicKey;
		LPPrivateKey<Element>	secretKey;

		LPKeyPair(LPPublicKeyImpl<Element>* a=0, LPPrivateKeyImpl<Element>* b=0): publicKey(a), secretKey(b) {}

		bool good() { return publicKey && secretKey; }
		
	};

	/**
	* @brief Abstract interface for parameter generation algorithm
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPParameterGenerationAlgorithm {
	public:
		virtual ~LPParameterGenerationAlgorithm() {}

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param *cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		*/
		virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const = 0;

	};

	/**
	 * @brief Abstract interface for encryption algorithm
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPEncryptionAlgorithm {
		public:
			virtual ~LPEncryptionAlgorithm() {}

			/**
			 * Method for encrypting plaintext using LBC
			 *
			 * @param&publicKey public key used for encryption.
			 * @param plaintext copy of the plaintext element. NOTE a copy is passed! That is NOT an error!
			 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			virtual Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey, Element plaintext) const = 0;

			/**
			 * Method for encrypting plaintex using LBC
			 *
			 * @param privateKey private key used for encryption.
			 * @param plaintext copy of the plaintext input. NOTE a copy is passed! That is NOT an error!
			 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			virtual Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey, Element plaintext) const = 0;

			/**
			 * Method for decrypting plaintext using LBC
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
				const Ciphertext<Element> ciphertext,
				NativePoly *plaintext) const = 0;

			/**
			 * Function to generate public and private keys
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @return function ran correctly.
			 */
			virtual LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse=false) = 0;

	};


	/**
	 * @brief Abstract interface for Leveled SHE operations
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPLeveledSHEAlgorithm {
		public:
		virtual ~LPLeveledSHEAlgorithm() {}

			/**
			 * Method for Modulus Reduction.
			 *
			 * @param &cipherText Ciphertext to perform mod reduce on.
			 */
			virtual Ciphertext<Element> ModReduce(Ciphertext<Element> cipherText) const = 0;

			/**
			 * Method for Ring Reduction.
			 *
			 * @param &cipherText Ciphertext to perform ring reduce on.
			 * @param &privateKey Private key used to encrypt the first argument.
			 */
			virtual Ciphertext<Element> RingReduce(Ciphertext<Element> cipherText, const LPEvalKey<Element> keySwitchHint) const = 0;

			/**
			 * Method for Composed EvalMult
			 *
			 * @param &cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
			 * @param &cipherText2 cipherText2, second input ciphertext to perform multiplication on.
			 * @param &quadKeySwitchHint is for resultant quadratic secret key after multiplication to the secret key of the particular level.
			 * @param &cipherTextResult is the resulting ciphertext that can be decrypted with the secret key of the particular level.
			 */
			virtual Ciphertext<Element> ComposedEvalMult(
					const Ciphertext<Element> cipherText1,
					const Ciphertext<Element> cipherText2,
					const LPEvalKey<Element> quadKeySwitchHint) const = 0;

			/**
			 * Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
			 *
			 * @param &cipherText1 is the original ciphertext to be key switched and mod reduced.
			 * @param &linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
			 * @param &cipherTextResult is the resulting ciphertext.
			 */
			virtual Ciphertext<Element> LevelReduce(const Ciphertext<Element> cipherText1,
					const LPEvalKey<Element> linearKeySwitchHint) const = 0;

			/**
			* Function that determines if security requirements are met if ring dimension is reduced by half.
			*
			* @param ringDimension is the original ringDimension
			* @param &moduli is the vector of moduli that is used
			* @param rootHermiteFactor is the security threshold
			*/
			virtual bool CanRingReduce(usint ringDimension, const std::vector<BigInteger> &moduli, const double rootHermiteFactor) const = 0;
	};

	/**
	 * @brief Abstract interface class for LBC PRE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPREAlgorithm {
		public:
			virtual ~LPPREAlgorithm() {}

			/**
			 * Virtual function to generate 1..log(q) encryptions for each bit of the original private key.
			 * Variant that uses the new secret key directly.
			 *
			 * @param &newKey new private key for the new ciphertext.
			 * @param &origPrivateKey original private key used for decryption.
			 * @param *evalKey the evaluation key.
			 * @return the re-encryption key.
			 */
			virtual LPEvalKey<Element> ReKeyGen(const LPPrivateKey<Element> newKey,
				const LPPrivateKey<Element> origPrivateKey) const = 0;

			/**
			* Virtual function to generate 1..log(q) encryptions for each bit of the original private key
			* Variant that uses the public key for the new secret key.
			*
			* @param &newKey public key for the new secret key.
			* @param &origPrivateKey original private key used for decryption.
			* @param *evalKey the evaluation key.
			* @return the re-encryption key.
			*/
			virtual LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
				const LPPrivateKey<Element> origPrivateKey) const = 0;
						
			/**
			 * Virtual function to define the interface for re-encypting ciphertext using the array generated by ProxyGen
			 *
			 * @param &evalKey proxy re-encryption key.
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual Ciphertext<Element> ReEncrypt(const LPEvalKey<Element> evalKey,
				const Ciphertext<Element> ciphertext) const = 0;

	};

	/**
	 * @brief Abstract interface class for LBC Multiparty algorithms.  A version of this multiparty scheme built on the BGV scheme is seen here:
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
	class LPMultipartyAlgorithm {
		public:
			virtual ~LPMultipartyAlgorithm() {}

			/**
			* Function to generate public and private keys for multiparty homomrophic encryption in coordination with a leading client that generated a first public key.
			*
			* @param cc cryptocontext for the keys to be generated.
			* @param pk1 private key used for decryption to be fused.
			* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
			* @param pre set to true if proxy re-encryption is used in multi-party protocol
			* @return key pair including the private and public key
			*/
			virtual LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
				const LPPublicKey<Element> pk1,
				bool makeSparse=false, bool pre=false) = 0;

			/**
			* Function to generate public and private keys for multiparty homomrophic encryption server key pair in coordination with secret keys of clients.
			*
			* @param cc cryptocontext for the keys to be generated.
			* @param secretkeys private keys used for decryption to be fused.
			* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
			* @return key pair including the private and public key
			*/
			virtual LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
				const vector<LPPrivateKey<Element>>& secretKeys,
				bool makeSparse=false) = 0;

			/**
			 * Method for main decryption operation run by most decryption clients for multiparty homomorphic encryption
			 *
			 * @param privateKey private key used for decryption.
			 * @param ciphertext ciphertext id decrypted.
			 */
			virtual Ciphertext<Element> MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
				const Ciphertext<Element> ciphertext) const = 0;

			/**
			 * Method for decryption operation run by the lead decryption client for multiparty homomorphic encryption
			 *
			 * @param privateKey private key used for decryption.
			 * @param ciphertext ciphertext id decrypted.
			 */
			virtual Ciphertext<Element> MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
				const Ciphertext<Element> ciphertext) const = 0;


			/**
			 * Method for fusing the partially decrypted ciphertext.
			 *
			 * @param &ciphertextVec ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
				NativePoly *plaintext) const = 0;

	};

	/**
	 * @brief Abstract interface class for LBC SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPSHEAlgorithm {
		public:
			virtual ~LPSHEAlgorithm() {}

			/**
			* Virtual function to define the interface for homomorphic addition of ciphertexts.
			*
			* @param ciphertext1 the input ciphertext.
			* @param ciphertext2 the input ciphertext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalAdd(const Ciphertext<Element> ciphertext1,
				const Ciphertext<Element> ciphertext2) const = 0;

			/**
			* Virtual function to define the interface for homomorphic addition of ciphertexts.
			*
			* @param ciphertext the input ciphertext.
			* @param plaintext the input plaintext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalAdd(const Ciphertext<Element> ciphertext,
				const Plaintext plaintext) const = 0;

			/**
			* Virtual function to define the interface for homomorphic subtraction of ciphertexts.
			*
			* @param ciphertext1 the input ciphertext.
			* @param ciphertext2 the input ciphertext.
			* @return the new ciphertext.
			*/
			virtual Ciphertext<Element> EvalSub(const Ciphertext<Element> ciphertext1,
				const Ciphertext<Element> ciphertext2) const = 0;

			/**
			 * Virtual function to define the interface for homomorphic subtraction of ciphertexts.
			 *
			 * @param ciphertext the input ciphertext.
			 * @param plaintext the input plaintext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalSub(const Ciphertext<Element> ciphertext,
					const Plaintext plaintext) const = 0;

			/**
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext.
			 *
			 * @param ciphertext1 the input ciphertext.
			 * @param ciphertext2 the input ciphertext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext1,
					const Ciphertext<Element> ciphertext2) const = 0;

			/**
			 * Virtual function to define the interface for multiplication of ciphertext by plaintext.
			 *
			 * @param ciphertext the input ciphertext.
			 * @param plaintext the input plaintext.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext,
					const Plaintext plaintext) const = 0;

			/**
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext using the evaluation key.
			 *
			 * @param &ciphertext1 first input ciphertext.
			 * @param &ciphertext2 second input ciphertext.
			 * @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
			 * @return the new ciphertext.
			 */
			virtual Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext1,
					const Ciphertext<Element> ciphertext2, const LPEvalKey<Element> ek) const = 0;

		/**
		* Virtual function for evaluating multiplication of a ciphertext list which each multiplication is followed by relinearization operation.
		*
		* @param cipherTextList  is the ciphertext list.
		* @param evalKeys is the evaluation key to make the newCiphertext
		*  decryptable by the same secret key as that of ciphertext list.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		virtual Ciphertext<Element> EvalMultMany(const vector<Ciphertext<Element>>& cipherTextList,
				const vector<LPEvalKey<Element>> &evalKeys) const = 0;

		/**
		* Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext using the evaluation key.
		*
		* @param ct1 first input ciphertext.
		* @param ct2 second input ciphertext.
		* @param ek is the evaluation key to make the newCiphertext
		*  decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		virtual Ciphertext<Element> EvalMultAndRelinearize(const Ciphertext<Element> ct1,
			const Ciphertext<Element> ct2, const vector<LPEvalKey<Element>> &ek) const = 0;

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
			// multiplication is done in reverse order to minimize the number of inner products
			Matrix<RationalCiphertext<Element>> xTransposed = x->Transpose();
			shared_ptr<Matrix<RationalCiphertext<Element>>> result(new Matrix<RationalCiphertext<Element>>(xTransposed * (*y)));

			Matrix<RationalCiphertext<Element>> xCovariance = xTransposed * (*x);

			Matrix<RationalCiphertext<Element>> cofactorMatrix = xCovariance.CofactorMatrix();

			Matrix<RationalCiphertext<Element>> adjugateMatrix = cofactorMatrix.Transpose();

			*result = adjugateMatrix * (*result);

			RationalCiphertext<Element> determinant;
			xCovariance.Determinant(&determinant);

				for (size_t row = 0; row < result->GetRows(); row++)
					for (size_t col = 0; col < result->GetCols(); col++)
						(*result)(row, col).SetDenominator(determinant.GetNumerator());

			return result;
		}

		/**
		* Virtual function to define the interface for homomorphic negation of ciphertext.
		*
		* @param &ciphertext the input ciphertext.
		* @param *newCiphertext the new ciphertext.
		*/
		virtual Ciphertext<Element> EvalNegate(const Ciphertext<Element> ciphertext) const = 0;

		/**
		* Function to add random noise to all plaintext slots except for the first one; used in EvalInnerProduct
		*
		* @param &ciphertext the input ciphertext.
		* @return modified ciphertext
		*/
		Ciphertext<Element> AddRandomNoise(const Ciphertext<Element> ciphertext) const {

			string kID = ciphertext->GetKeyTag();
			const auto cryptoParams = ciphertext->GetCryptoParameters();
			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint n = elementParams->GetRingDimension();

			auto cc = ciphertext->GetCryptoContext();

			DiscreteUniformGenerator dug;
			dug.SetModulus(encodingParams->GetPlaintextModulus());
			BigVector randomVector = dug.GenerateVector(n - 1);

			std::vector<uint64_t> randomIntVector(n);

			//first plaintext slot does not need to change
			randomIntVector[0] = 0;

			for (usint i = 0; i < n - 1; i++)
			{
				randomIntVector[i + 1] = randomVector[i].ConvertToInt();
			}

			Plaintext plaintext = cc->MakePackedPlaintext(randomIntVector);

			plaintext->Encode();
			plaintext->GetElement<Element>().SetFormat(EVALUATION);

			auto ans = EvalAdd(ciphertext, plaintext);

			return ans;
		};

		/**
		* Method for KeySwitchGen
		*
		* @param &originalPrivateKey Original private key used for encryption.
		* @param &newPrivateKey New private key to generate the keyswitch hint.
		* @param *KeySwitchHint is where the resulting keySwitchHint will be placed.
		*/
		virtual LPEvalKey<Element> KeySwitchGen(
			const LPPrivateKey<Element> originalPrivateKey,
			const LPPrivateKey<Element> newPrivateKey) const = 0;

		/**
		* Method for KeySwitch
		*
		* @param &keySwitchHint Hint required to perform the ciphertext switching.
		* @param &cipherText Original ciphertext to perform switching on.
		*/
		virtual Ciphertext<Element> KeySwitch(
			const LPEvalKey<Element> keySwitchHint,
			const Ciphertext<Element> cipherText) const = 0;

		/**
		* Method for KeySwitching based on RLWE relinearization (used only for the LTV scheme).
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		*
		* @param &newPublicKey encryption key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		*/
		virtual LPEvalKey<Element> KeySwitchRelinGen(const LPPublicKey<Element> newPublicKey,
			const LPPrivateKey<Element> origPrivateKey) const = 0;

		/**
		* Method for KeySwitching based on RLWE relinearization (used only for the LTV scheme).
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return the resulting Ciphertext
		*/
		virtual Ciphertext<Element> KeySwitchRelin(const LPEvalKey<Element> evalKey,
			const Ciphertext<Element> ciphertext) const = 0;

		/**
		* Virtual function to define the interface for generating a evaluation key which is used after each multiplication.
		*
		* @param &ciphertext1 first input ciphertext.
		* @param &ciphertext2 second input ciphertext.
		* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		virtual	LPEvalKey<Element> EvalMultKeyGen(
			const LPPrivateKey<Element> originalPrivateKey) const = 0;

		/**
		* Virtual function to define the interface for generating a evaluation key which is used after each multiplication for depth more than 2.
		*
		* @param &originalPrivateKey Original private key used for encryption.
		* @param *evalMultKeys the resulting evalution key vector list.
		*/
		virtual	vector<LPEvalKey<Element>> EvalMultKeysGen(
			const LPPrivateKey<Element> originalPrivateKey) const = 0;

		/**
		 * Virtual function to generate all isomorphism keys for a given private key
		 *
		 * @param publicKey encryption key for the new ciphertext.
		 * @param origPrivateKey original private key used for decryption.
		 * @param indexList list of automorphism indices to be computed
		 * @return returns the evaluation keys
		 */
		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
			const LPPrivateKey<Element> origPrivateKey,
			const std::vector<usint> &indexList) const = 0;

		/**
		* Virtual function for evaluating automorphism of ciphertext at index i
		*
		* @param ciphertext the input ciphertext.
		* @param i automorphism index
		* @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		virtual Ciphertext<Element> EvalAutomorphism(const Ciphertext<Element> ciphertext, usint i,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const = 0;


		/**
		* Virtual function to generate automophism keys for a given private key; Uses the private key for encryption
		*
		* @param privateKey private key.
		* @param indexList list of automorphism indices to be computed
		* @return returns the evaluation keys
		*/
		virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
			const std::vector<usint> &indexList) const = 0;

		/**
		* Virtual function to generate the automorphism keys for EvalSum; works only for packed encoding
		*
		* @param privateKey private key.
		* @return returns the evaluation keys
		*/
		shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumKeyGen(const LPPrivateKey<Element> privateKey,
			const LPPublicKey<Element> publicKey) const
		{

			const auto cryptoParams = privateKey->GetCryptoParameters();
			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint batchSize = encodingParams->GetBatchSize();
			usint m = elementParams->GetCyclotomicOrder();

			// stores automorphism indices needed for EvalSum
			std::vector<usint> indices;

			if (!(m & (m-1))){ // Check if m is a power of 2

				indices = GenerateIndices_2n(batchSize, m);

			} else { // Arbitray cyclotomics

				usint g = encodingParams->GetPlaintextGenerator();
				for (int i = 0; i < floor(log2(batchSize)); i++)
				{
					indices.push_back(g);
					g = (g * g) % m;
				}
			}

			if (publicKey)
				// NTRU-based scheme
				return EvalAutomorphismKeyGen(publicKey, privateKey, indices);
			else
				// Regular RLWE scheme
				return EvalAutomorphismKeyGen(privateKey, indices);

		}

		/**
		* Sums all elements in log (batch size) time - works only with packed encoding
		*
		* @param ciphertext the input ciphertext.
		* @param batchSize size of the batch to be summed up
		* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @return resulting ciphertext
		*/
		Ciphertext<Element> EvalSum(const Ciphertext<Element> ciphertext, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertext->GetCryptoParameters();
			Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

			const auto encodingParams = cryptoParams->GetEncodingParams();
			const auto elementParams = cryptoParams->GetElementParams();

			usint m = elementParams->GetCyclotomicOrder();

			if ((encodingParams->GetBatchSize() == 0))
				throw std::runtime_error("EvalSum: Packed encoding parameters 'batch size' is not set; Please check the EncodingParams passed to the crypto context.");
			else
			{

				if (!(m & (m-1))){ // Check if m is a power of 2

					newCiphertext = EvalSum_2n(batchSize, m, evalKeys,newCiphertext);

				} else { // Arbitray cyclotomics

					if (encodingParams->GetPlaintextGenerator() == 0)
						throw std::runtime_error("EvalSum: Packed encoding parameters 'plaintext generator' is not set; Please check the EncodingParams passed to the crypto context.");
					else
					{
						usint g = encodingParams->GetPlaintextGenerator();
						for (int i = 0; i < floor(log2(batchSize)); i++)
						{
							auto ea = EvalAutomorphism(newCiphertext, g, evalKeys);
							newCiphertext = EvalAdd(newCiphertext, ea);
							g = (g * g) % m;
						}
					}
				}
			}


			return newCiphertext;

		}

		/**
		* Evaluates inner product in batched encoding
		*
		* @param ciphertext1 first vector.
		* @param ciphertext2 second vector.
		* @param batchSize size of the batch to be summed up
		* @param &evalSumKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @param &evalMultKey - reference to the evaluation key generated by EvalMultKeyGen.
		* @return resulting ciphertext
		*/
		Ciphertext<Element> EvalInnerProduct(const Ciphertext<Element> ciphertext1,
			const Ciphertext<Element> ciphertext2, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
			const LPEvalKey<Element> evalMultKey) const {

			Ciphertext<Element> result = EvalMult(ciphertext1, ciphertext2, evalMultKey);

			result = EvalSum(result, batchSize, evalSumKeys);

			// add a random number to all slots except for the first one so that no information is leaked
			result = AddRandomNoise(result);

			return result;
		}

		/**
		* Evaluates inner product in batched encoding
		*
		* @param ciphertext1 first vector.
		* @param ciphertext2 plaintext.
		* @param batchSize size of the batch to be summed up
		* @param &evalSumKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
		* @param &evalMultKey - reference to the evaluation key generated by EvalMultKeyGen.
		* @return resulting ciphertext
		*/
		Ciphertext<Element> EvalInnerProduct(const Ciphertext<Element> ciphertext1,
			const Plaintext ciphertext2, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalSumKeys) const {

			Ciphertext<Element> result = EvalMult(ciphertext1, ciphertext2);

			result = EvalSum(result, batchSize, evalSumKeys);

			// add a random number to all slots except for the first one so that no information is leaked
			return AddRandomNoise(result);
		}

		/**
		* EvalLinRegressBatched - Computes the parameter vector for linear regression using the least squares method
		* Currently supports only two regressors
		* @param x - matrix of regressors
		* @param y - vector of dependent variables
		* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
		*/
		shared_ptr<Matrix<RationalCiphertext<Element>>>
			EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
				const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
				const LPEvalKey<Element> evalMultKey) const
		{

			Matrix<RationalCiphertext<Element>> covarianceMatrix(x->GetAllocator(), 2, 2);

			Ciphertext<Element> x0 = (*x)(0, 0).GetNumerator();
			Ciphertext<Element> x1 = (*x)(0, 1).GetNumerator();
			Ciphertext<Element> y0 = (*y)(0, 0).GetNumerator();

			//Compute the covariance matrix for X
			covarianceMatrix(0, 0).SetNumerator(EvalInnerProduct(x0, x0, batchSize, evalSumKeys, evalMultKey));
			covarianceMatrix(0, 1).SetNumerator(EvalInnerProduct(x0, x1, batchSize, evalSumKeys, evalMultKey));
			covarianceMatrix(1, 0) = covarianceMatrix(0, 1);
			covarianceMatrix(1, 1).SetNumerator(EvalInnerProduct(x1, x1, batchSize, evalSumKeys, evalMultKey));

			Matrix<RationalCiphertext<Element>> cofactorMatrix = covarianceMatrix.CofactorMatrix();

			Matrix<RationalCiphertext<Element>> adjugateMatrix = cofactorMatrix.Transpose();

			shared_ptr<Matrix<RationalCiphertext<Element>>> result(new Matrix<RationalCiphertext<Element>>(x->GetAllocator(), 2, 1));

			(*result)(0, 0).SetNumerator(EvalInnerProduct(x0, y0, batchSize, evalSumKeys, evalMultKey));
			(*result)(1, 0).SetNumerator(EvalInnerProduct(x1, y0, batchSize, evalSumKeys, evalMultKey));

			*result = adjugateMatrix * (*result);

			RationalCiphertext<Element> determinant;
			covarianceMatrix.Determinant(&determinant);

			for (size_t row = 0; row < result->GetRows(); row++)
				for (size_t col = 0; col < result->GetCols(); col++)
					(*result)(row, col).SetDenominator(determinant.GetNumerator());

			return result;
		}


		/**
		* EvalCrossCorrelation - Computes the sliding sum of inner products (known as
		* as cross-correlation, sliding inner product, or sliding dot product in
		* image processing
		* @param x - first vector of row vectors
		* @param y - second vector of row vectors
		* @param batchSize - batch size for packed encoding
		* @param indexStart - starting index in the vectors of row vectors
		* @param length - length of the slice in the vectors of row vectors
		* @param evalSumKeys - evaluation keys used for the automorphism operation
		* @param evalMultKey - the evaluation key used for multiplication
		* @return sum(x_i*y_i), i.e., a sum of inner products
		*/
		Ciphertext<Element>
			EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize, 
				usint indexStart, usint length,
				const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
				const LPEvalKey<Element> evalMultKey) const
		{

			if (length == 0)
				length = x->GetRows();
			
			if (length - indexStart > x->GetRows())
				throw std::runtime_error("The number of rows exceeds the dimension of the vector");

			//additional error checking can be added here

			Ciphertext<Element> result;

			Ciphertext<Element> x0 = (*x)(indexStart, 0).GetNumerator();
			Ciphertext<Element> y0 = (*y)(indexStart, 0).GetNumerator();

			result = EvalInnerProduct(x0, y0, batchSize, evalSumKeys, evalMultKey);

			#pragma omp parallel for ordered schedule(dynamic)
			for (usint i = indexStart + 1; i < indexStart + length; i++)
			{
				Ciphertext<Element> xi = (*x)(i, 0).GetNumerator();
				Ciphertext<Element> yi = (*y)(i, 0).GetNumerator();

				auto product = EvalInnerProduct(xi, yi, batchSize, evalSumKeys, evalMultKey);
				
				#pragma omp ordered
				{
					result = EvalAdd(result,product);
				}
			}

			return result;

		}

		private:

			std::vector<usint> GenerateIndices_2n(usint batchSize, usint m) const {
				// stores automorphism indices needed for EvalSum
				std::vector<usint> indices;

				usint g = 5;
				for (int i = 0; i < floor(log2(batchSize)) - 1; i++)
				{
					indices.push_back(g);
					g = (g * g) % m;
				}
				if (2*batchSize<m)
					indices.push_back(g);
				indices.push_back(3);

				return indices;
			}

			Ciphertext<Element> EvalSum_2n(usint batchSize, usint m, const std::map<usint, LPEvalKey<Element>> &evalKeys,
				const Ciphertext<Element> ciphertext) const{

				Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext));

				usint g = 5;
				for (int i = 0; i < floor(log2(batchSize)) - 1; i++)
				{
					newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, g, evalKeys));
					g = (g * g) % m;
				}
				if (2*batchSize<m)
					newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, g, evalKeys));
				newCiphertext = EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, 3, evalKeys));

				return newCiphertext;

			}

	};


	/**
	 * @brief Abstract interface class for LBC SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPFHEAlgorithm {
		public:
			virtual ~LPFHEAlgorithm() {}

			/**
			 * Virtual function to define the interface for bootstrapping evaluation of ciphertext
			 *
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void Bootstrap(const Ciphertext<Element> &ciphertext,
				Ciphertext<Element> *newCiphertext) const = 0;
	};

	/**
	 * @brief main implementation class to capture essential cryptoparameters of any LBC system
	 * @tparam Element a ring element.
	 */
	template <typename Element>
	class LPCryptoParameters : public Serializable
	{		
	public:
		virtual ~LPCryptoParameters() {}

		/**
			* Returns the value of plaintext modulus p
			*
			* @return the plaintext modulus.
			*/
		const PlaintextModulus &GetPlaintextModulus() const { return  m_encodingParams->GetPlaintextModulus(); }

		/**
			* Returns the reference to IL params
			*
			* @return the ring element parameters.
			*/
		const shared_ptr<typename Element::Params> GetElementParams() const { return m_params; }

		/**
		* Returns the reference to encoding params
		*
		* @return the encoding parameters.
		*/
		const EncodingParams GetEncodingParams() const { return m_encodingParams; }

		/**
		* Sets the value of plaintext modulus p
		*/
		void SetPlaintextModulus(const PlaintextModulus &plaintextModulus) {
			m_encodingParams->SetPlaintextModulus(plaintextModulus);
		}

		virtual bool operator==(const LPCryptoParameters<Element>& cmp) const = 0;
		bool operator!=(const LPCryptoParameters<Element>& cmp) const { return !(*this == cmp); }

		/**
		 * Overload to allow printing of parameters to an iostream
		 * NOTE that the implementation relies on calling the virtual PrintParameters method
		 * @param out - the stream to print to
		 * @param item - reference to the item to print
		 * @return the stream
		 */
		friend std::ostream& operator<<(std::ostream& out, const LPCryptoParameters& item) {
			item.PrintParameters(out);
			return out;
		}

		virtual usint GetRelinWindow() const { return 0; }

		virtual const typename Element::DggType &GetDiscreteGaussianGenerator() const {
			throw std::logic_error("No DGG Available for this parameter set");
		}

		/**
		 * Sets the reference to element params
		 */
		void SetElementParams(shared_ptr<typename Element::Params> params) {
			m_params = params;
		}

        /**
         * Sets the reference to encoding params
         */
		void SetEncodingParams(EncodingParams encodingParams) {
			m_encodingParams = encodingParams;
		}


	protected:
		LPCryptoParameters(const PlaintextModulus &plaintextModulus = 2) {
			m_encodingParams.reset( new EncodingParamsImpl(plaintextModulus) );
		}

		LPCryptoParameters(shared_ptr<typename Element::Params> params, const PlaintextModulus &plaintextModulus) {
			m_params = params;
			m_encodingParams.reset( new EncodingParamsImpl(plaintextModulus) );
		}

		LPCryptoParameters(shared_ptr<typename Element::Params> params, EncodingParams encodingParams) {
			m_params = params;
			m_encodingParams = encodingParams;
		}

		LPCryptoParameters(LPCryptoParameters<Element> *from, shared_ptr<typename Element::Params> newElemParms) {
			*this = *from;
			m_params = newElemParms;
		}

		virtual void PrintParameters(std::ostream& out) const {
			out << "Element Parameters: " << *m_params << std::endl;
			out << "Encoding Parameters: " << *m_encodingParams << std::endl;
		}

	private:
		//element-specific parameters
		shared_ptr<typename Element::Params>		m_params;

		//encoding-specific parameters
		EncodingParams								m_encodingParams;
	};

	
	/**
	 * @brief Abstract interface for public key encryption schemes
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyEncryptionScheme {

	public:
		LPPublicKeyEncryptionScheme() :
			m_algorithmParamsGen(0), m_algorithmEncryption(0), m_algorithmPRE(0), m_algorithmMultiparty(0),
			m_algorithmSHE(0), m_algorithmFHE(0), m_algorithmLeveledSHE(0) {}

		virtual ~LPPublicKeyEncryptionScheme() {
			if (this->m_algorithmParamsGen != NULL)
				delete this->m_algorithmParamsGen;
			if (this->m_algorithmEncryption != NULL)
				delete this->m_algorithmEncryption;
			if (this->m_algorithmPRE != NULL)
				delete this->m_algorithmPRE;
			if (this->m_algorithmMultiparty != NULL)
				delete this->m_algorithmMultiparty;
			if (this->m_algorithmSHE != NULL)
				delete this->m_algorithmSHE;
			if (this->m_algorithmFHE != NULL)
				delete this->m_algorithmFHE;
			if (this->m_algorithmLeveledSHE != NULL)
				delete this->m_algorithmLeveledSHE;
		}
		
		virtual bool operator==(const LPPublicKeyEncryptionScheme& sch) const = 0;

		bool operator!=(const LPPublicKeyEncryptionScheme& sch) const {
			return !(*this == sch);
		}

		/**
		 * Enable features with a bit mast of PKESchemeFeature codes
		 * @param mask
		 */
		void Enable(usint mask) {

			if (mask&ENCRYPTION) Enable(ENCRYPTION);

			if (mask&PRE) Enable(PRE);

			if (mask&SHE) Enable(SHE);

			if (mask&LEVELEDSHE) Enable(LEVELEDSHE);

			if (mask&MULTIPARTY) Enable(MULTIPARTY);

			if (mask&FHE) Enable(FHE);
		}

		usint GetEnabled() const {
			usint flag = 0;

			if (m_algorithmEncryption != NULL)
				flag |= ENCRYPTION;
			if (m_algorithmPRE != NULL)
				flag |= PRE;
			if (m_algorithmSHE != NULL)
				flag |= SHE;
			if (m_algorithmFHE != NULL)
				flag |= FHE;
			if (m_algorithmLeveledSHE != NULL)
				flag |= LEVELEDSHE;
			if (m_algorithmMultiparty != NULL)
				flag |= MULTIPARTY;

			return flag;
		}

		//instantiated in the scheme implementation class
		virtual void Enable(PKESchemeFeature feature) = 0;

		/////////////////////////////////////////
		// wrapper for LPParameterSelectionAlgorithm
		//

		bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const {
			if (this->m_algorithmParamsGen) {
				return this->m_algorithmParamsGen->ParamsGen(cryptoParams, evalAddCount, evalMultCount, keySwitchCount);
			}
			else {
				throw std::logic_error("Parameter generation operation has not been implemented");
			}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPEncryptionAlgorithm (ENCRYPT)
		//

		Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
			const Element &plaintext) const {
				if(this->m_algorithmEncryption) {
					return this->m_algorithmEncryption->Encrypt(publicKey,plaintext);
				}
				else {
					throw std::logic_error("Encrypt operation has not been enabled");
				}
		}

		Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
			const Element &plaintext) const {
				if(this->m_algorithmEncryption) {
					return this->m_algorithmEncryption->Encrypt(privateKey,plaintext);
				}
				else {
					throw std::logic_error("Encrypt operation has not been enabled");
				}
		}

		DecryptResult Decrypt(const LPPrivateKey<Element> privateKey, const Ciphertext<Element> ciphertext,
				NativePoly *plaintext) const {
				if(this->m_algorithmEncryption)
					return this->m_algorithmEncryption->Decrypt(privateKey,ciphertext,plaintext);
				else {
					throw std::logic_error("Decrypt operation has not been enabled");
				}
		}

		LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse) {
				if(this->m_algorithmEncryption) {
					auto kp = this->m_algorithmEncryption->KeyGen(cc, makeSparse);
					kp.publicKey->SetKeyTag( kp.secretKey->GetKeyTag() );
					return kp;
				}
				else {
					throw std::logic_error("KeyGen operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPPREAlgorithm (PRE)
		//

		LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
				const LPPrivateKey<Element> origPrivateKey) const {
			if(this->m_algorithmPRE) {
				auto rk = this->m_algorithmPRE->ReKeyGen(newKey,origPrivateKey);
				rk->SetKeyTag( newKey->GetKeyTag() );
				return rk;
			} else {
				throw std::logic_error("ReKeyGen operation has not been enabled");
			}
		}

		LPEvalKey<Element> ReKeyGen(const LPPrivateKey<Element> newKey,
				const LPPrivateKey<Element> origPrivateKey) const {
			if (this->m_algorithmPRE) {
				auto rk = this->m_algorithmPRE->ReKeyGen(newKey,origPrivateKey);
				rk->SetKeyTag( newKey->GetKeyTag() );
				return rk;
			} else {
				throw std::logic_error("ReKeyGen operation has not been enabled");
			}
		}

		Ciphertext<Element> ReEncrypt(const LPEvalKey<Element> evalKey,
				const Ciphertext<Element> ciphertext) const {
			if(this->m_algorithmPRE) {
				auto ct = this->m_algorithmPRE->ReEncrypt(evalKey,ciphertext);
				ct->SetKeyTag( evalKey->GetKeyTag() );
				return ct;
			} else {
				throw std::logic_error("ReEncrypt operation has not been enabled");
			}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPMultipartyAlgorithm (Multiparty)
		//

		// Wrapper for Multiparty Key Gen
		// FIXME check key ID for multiparty
		LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
				const LPPublicKey<Element> pk1,
				bool makeSparse, bool PRE) {
			if(this->m_algorithmMultiparty) {
				auto k = this->m_algorithmMultiparty->MultipartyKeyGen(cc, pk1, makeSparse, PRE);
				k.publicKey->SetKeyTag( k.secretKey->GetKeyTag() );
				return k;
			} else {
				throw std::logic_error("MultipartyKeyGen operation has not been enabled");
			}
		}

		// Wrapper for Multiparty Key Gen
		// FIXME key IDs for multiparty
		LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
			const vector<LPPrivateKey<Element>>& secretKeys,
			bool makeSparse) {
				if(this->m_algorithmMultiparty) {
					auto k = this->m_algorithmMultiparty->MultipartyKeyGen(cc, secretKeys, makeSparse);
					k.publicKey->SetKeyTag( k.secretKey->GetKeyTag() );
					return k;
				} else {
					throw std::logic_error("MultipartyKeyGen operation has not been enabled");
				}
		}

		// FIXME key IDs for multiparty
		Ciphertext<Element> MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
				const Ciphertext<Element> ciphertext) const {
				if(this->m_algorithmMultiparty) {
					auto ct = this->m_algorithmMultiparty->MultipartyDecryptMain(privateKey,ciphertext);
					ct->SetKeyTag( privateKey->GetKeyTag() );
					return ct;
				} else {
					throw std::logic_error("MultipartyDecryptMain operation has not been enabled");
				}
		}

		// FIXME key IDs for multiparty
		Ciphertext<Element> MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
				const Ciphertext<Element> ciphertext) const {
				if(this->m_algorithmMultiparty) {
					auto ct = this->m_algorithmMultiparty->MultipartyDecryptLead(privateKey,ciphertext);
					ct->SetKeyTag( privateKey->GetKeyTag() );
					return ct;
				} else {
					throw std::logic_error("MultipartyDecryptLead operation has not been enabled");
				}
		}

		DecryptResult MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
				NativePoly *plaintext) const {
				if(this->m_algorithmMultiparty) {
					return this->m_algorithmMultiparty->MultipartyDecryptFusion(ciphertextVec,plaintext);
				} else {
					throw std::logic_error("MultipartyDecrypt operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPSHEAlgorithm (SHE)
		//

		Ciphertext<Element> AddRandomNoise(const Ciphertext<Element> ciphertext) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->AddRandomNoise(ciphertext);
			else {
				throw std::logic_error("AddRandomNoise operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalAdd(const Ciphertext<Element> ciphertext1,
			const Ciphertext<Element> ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAdd(ciphertext1, ciphertext2);
				return ct;
			} else {
				throw std::logic_error("EvalAdd operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalAdd(const Ciphertext<Element> ciphertext1,
			const Plaintext plaintext) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAdd(ciphertext1, plaintext);
				return ct;
			} else {
				throw std::logic_error("EvalAdd operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalSub(const Ciphertext<Element> ciphertext1,
			const Ciphertext<Element> ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSub(ciphertext1, ciphertext2);
				return ct;
			} else {
				throw std::logic_error("EvalSub operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalSub(const Ciphertext<Element> ciphertext1,
				const Plaintext plaintext) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSub(ciphertext1, plaintext);
				return ct;
			} else {
				throw std::logic_error("EvalSub operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext1,
			const Ciphertext<Element> ciphertext2) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMult(ciphertext1, ciphertext2);
				return ct;
			} else {
				throw std::logic_error("EvalMult operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext,
			const Plaintext plaintext) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalMult(ciphertext, plaintext);
			else {
				throw std::logic_error("EvalMult operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalMult(const Ciphertext<Element> ciphertext1,
				const Ciphertext<Element> ciphertext2,
				const LPEvalKey<Element> evalKey) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalMult(ciphertext1, ciphertext2, evalKey);
				return ct;
			} else {
				throw std::logic_error("EvalMult operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalMultMany(const vector<Ciphertext<Element>>& ciphertext, const vector<LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE){
				return this->m_algorithmSHE->EvalMultMany(ciphertext, evalKeys);
			}
			else {
				throw std::logic_error("EvalMultMany operation has not been enabled");
			}
		}

		Ciphertext<Element> EvalNegate(const Ciphertext<Element> ciphertext) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalNegate(ciphertext);
				return ct;
			} else {
				throw std::logic_error("EvalNegate operation has not been enabled");
			}
		}

		shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
			const LPPrivateKey<Element> origPrivateKey,
			const std::vector<usint> &indexList) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalAutomorphismKeyGen(publicKey,origPrivateKey,indexList);
				for( auto& k : *km )
					k.second->SetKeyTag( publicKey->GetKeyTag() );
				return km;
			} else
				throw std::logic_error("EvalAutomorphismKeyGen operation has not been enabled");
		}

		Ciphertext<Element> EvalAutomorphism(const Ciphertext<Element> ciphertext, usint i,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalAutomorphism(ciphertext, i, evalKeys);
				return ct;
			} else
				throw std::logic_error("EvalAutomorphism operation has not been enabled");
		}

		shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
			const std::vector<usint> &indexList) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalAutomorphismKeyGen(privateKey, indexList);
				for( auto& k : *km )
					k.second->SetKeyTag( privateKey->GetKeyTag() );
				return km;
			} else
				throw std::logic_error("EvalAutomorphismKeyGen operation has not been enabled");
		}

		shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumKeyGen(
			const LPPrivateKey<Element> privateKey,
			const LPPublicKey<Element> publicKey) const {

			if (this->m_algorithmSHE) {
				auto km = this->m_algorithmSHE->EvalSumKeyGen(privateKey,publicKey);
				for( auto& k : *km ) {
					k.second->SetKeyTag( privateKey->GetKeyTag() );
				}
				return km;
			} else
				throw std::logic_error("EvalSumKeyGen operation has not been enabled");
		}

		Ciphertext<Element> EvalSum(const Ciphertext<Element> ciphertext, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalKeys) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalSum(ciphertext, batchSize, evalKeys);
				return ct;
			} else
				throw std::logic_error("EvalSum operation has not been enabled");

		}

		Ciphertext<Element> EvalInnerProduct(const Ciphertext<Element> ciphertext1,
			const Ciphertext<Element> ciphertext2, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
			const LPEvalKey<Element> evalMultKey) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalInnerProduct(ciphertext1, ciphertext2, batchSize, evalSumKeys, evalMultKey);
				ct->SetKeyTag( evalSumKeys.begin()->second->GetKeyTag() );
				return ct;
			} else
				throw std::logic_error("EvalInnerProduct operation has not been enabled");

		}

		Ciphertext<Element> EvalInnerProduct(const Ciphertext<Element> ciphertext1,
			const Plaintext ciphertext2, usint batchSize,
			const std::map<usint, LPEvalKey<Element>> &evalSumKeys) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalInnerProduct(ciphertext1, ciphertext2, batchSize, evalSumKeys);
			else
				throw std::logic_error("EvalInnerProduct operation has not been enabled");

		}

		shared_ptr<Matrix<RationalCiphertext<Element>>>
			EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
				const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
				const LPEvalKey<Element> evalMultKey) const {

			if (this->m_algorithmSHE) {
				string kID = evalMultKey->GetKeyTag();
				auto ctm = this->m_algorithmSHE->EvalLinRegressBatched(x, y, batchSize, evalSumKeys, evalMultKey);
				for( size_t r = 0; r < ctm->GetRows(); r++ )
					for( size_t c = 0; c < ctm->GetCols(); c++ )
						(*ctm)(r,c).SetKeyTag(kID);
				return ctm;
			} else
				throw std::logic_error("EvalLinRegressionBatched operation has not been enabled");
		}


		Ciphertext<Element>
			EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
				usint indexStart, usint length,
				const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
				const LPEvalKey<Element> evalMultKey) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->EvalCrossCorrelation(x, y, batchSize, indexStart, length, evalSumKeys, evalMultKey);
				// FIXME: mark with which key?
				return ct;
			} else
				throw std::logic_error("EvalCrossCorrelation operation has not been enabled");
		}


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

			if (this->m_algorithmSHE) {
				auto ctm = this->m_algorithmSHE->EvalLinRegression(x, y);
				// FIXME mark with which key??
				return ctm;
			} else {
				throw std::logic_error("EvalLinRegression operation has not been enabled");
			}

		}

		LPEvalKey<Element> KeySwitchGen(
			const LPPrivateKey<Element> originalPrivateKey,
			const LPPrivateKey<Element> newPrivateKey) const {
			if (this->m_algorithmSHE) {
				auto kp = this->m_algorithmSHE->KeySwitchGen(originalPrivateKey, newPrivateKey);
				kp->SetKeyTag( newPrivateKey->GetKeyTag() );
				return kp;

			} else {
				throw std::logic_error("KeySwitchGen operation has not been enabled");
			}
		}

		Ciphertext<Element> KeySwitch(
			const LPEvalKey<Element> keySwitchHint,
			const Ciphertext<Element> cipherText) const {

			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->KeySwitch(keySwitchHint, cipherText);
				return ct;

			}
			else {
				throw std::logic_error("KeySwitch operation has not been enabled");
			}
		}

		LPEvalKey<Element> KeySwitchRelinGen(const LPPublicKey<Element> newKey, const LPPrivateKey<Element> origPrivateKey) const {
			if (this->m_algorithmSHE) {
				auto kp = this->m_algorithmSHE->KeySwitchRelinGen(newKey, origPrivateKey);
				kp->SetKeyTag( newKey->GetKeyTag() );
				return kp;
			} else {
				throw std::logic_error("KeySwitchRelinGen operation has not been enabled");
			}
		}

		Ciphertext<Element> KeySwitchRelin(const LPEvalKey<Element> evalKey,
			const Ciphertext<Element> ciphertext) const {
			if (this->m_algorithmSHE) {
				auto ct = this->m_algorithmSHE->KeySwitchRelin(evalKey, ciphertext);
				ct->SetKeyTag( evalKey->GetKeyTag() );
				return ct;
			} else {
				throw std::logic_error("KeySwitchRelin operation has not been enabled");
			}
		}

		LPEvalKey<Element> EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const {
				if(this->m_algorithmSHE) {
					auto ek = this->m_algorithmSHE->EvalMultKeyGen(originalPrivateKey);
					ek->SetKeyTag( originalPrivateKey->GetKeyTag() );
					return ek;
				} else {
					throw std::logic_error("EvalMultKeyGen operation has not been enabled");
				}
		}
		
		vector<LPEvalKey<Element>> EvalMultKeysGen(const LPPrivateKey<Element> originalPrivateKey) const {
				if(this->m_algorithmSHE){
					auto ek = this->m_algorithmSHE->EvalMultKeysGen(originalPrivateKey);
					for(size_t i=0; i<ek.size(); i++)
						ek[i]->SetKeyTag( originalPrivateKey->GetKeyTag() );
					return ek;
				}
				else {
					throw std::logic_error("EvalMultKeysGen operation has not been enabled");
				}
		}

		Ciphertext<Element> EvalMultAndRelinearize(const Ciphertext<Element> ct1,
			const Ciphertext<Element> ct2, const vector<LPEvalKey<Element>> &ek) const {
				if(this->m_algorithmSHE)
					return this->m_algorithmSHE->EvalMultAndRelinearize(ct1, ct2, ek);
				else {
					throw std::logic_error("EvalMultAndRelinearize operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the functions below are wrappers for things in LPFHEAlgorithm (FHE)
		//
		// TODO: Add Bootstrap and any other FHE methods

		/////////////////////////////////////////
		// the functions below are wrappers for things in LPSHEAlgorithm (SHE)
		//

		Ciphertext<Element> ModReduce(Ciphertext<Element> cipherText) const {
			if(this->m_algorithmLeveledSHE) {
				auto ct = this->m_algorithmLeveledSHE->ModReduce(cipherText);
				ct->SetKeyTag( cipherText->GetKeyTag() );
				return ct;
			}
			else{
				throw std::logic_error("ModReduce operation has not been enabled");
			}
		}

		Ciphertext<Element> RingReduce(Ciphertext<Element> cipherText, const LPEvalKey<Element> keySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				auto ct = this->m_algorithmLeveledSHE->RingReduce(cipherText,keySwitchHint);
				ct->SetKeyTag( keySwitchHint->GetKeyTag() );
				return ct;
			}
			else{
				throw std::logic_error("RingReduce operation has not been enabled");
			}
		}

		bool CanRingReduce(usint ringDimension, const std::vector<BigInteger> &moduli, const double rootHermiteFactor) const {
			if (this->m_algorithmLeveledSHE) {
				return this->m_algorithmLeveledSHE->CanRingReduce(ringDimension, moduli, rootHermiteFactor);
			}
			else {
				throw std::logic_error("CanRingReduce operation has not been enabled");
			}
		}

		Ciphertext<Element> ComposedEvalMult(
							const Ciphertext<Element> cipherText1,
							const Ciphertext<Element> cipherText2,
							const LPEvalKey<Element> quadKeySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				auto ct = this->m_algorithmLeveledSHE->ComposedEvalMult(cipherText1,cipherText2,quadKeySwitchHint);
				ct->SetKeyTag( quadKeySwitchHint->GetKeyTag() );
				return ct;
			}
			else{
				throw std::logic_error("ComposedEvalMult operation has not been enabled");
			}
		}

		Ciphertext<Element> LevelReduce(const Ciphertext<Element> cipherText1,
				const LPEvalKeyNTRU<Element> linearKeySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				auto ct = this->m_algorithmLeveledSHE->LevelReduce(cipherText1,linearKeySwitchHint);
				ct->SetKeyTag( linearKeySwitchHint->GetKeyTag() );
				return ct;
			}
			else{
				throw std::logic_error("LevelReduce operation has not been enabled");
			}
		}

		const LPEncryptionAlgorithm<Element>& getAlgorithm() const { return *m_algorithmEncryption; }

	protected:
		LPParameterGenerationAlgorithm<Element> *m_algorithmParamsGen;
		LPEncryptionAlgorithm<Element> *m_algorithmEncryption;
		LPPREAlgorithm<Element> *m_algorithmPRE;
		LPMultipartyAlgorithm<Element> *m_algorithmMultiparty;
		LPSHEAlgorithm<Element> *m_algorithmSHE;
		LPFHEAlgorithm<Element> *m_algorithmFHE;
		LPLeveledSHEAlgorithm<Element> *m_algorithmLeveledSHE;
	};

} // namespace lbcrypto ends
#endif
