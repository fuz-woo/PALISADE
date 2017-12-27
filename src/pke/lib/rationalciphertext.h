/**
* @file	rationalciphertext.h -- PALISADE.
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

#ifndef LBCRYPTO_CRYPTO_RATIONALCIPHERTEXT_H
#define LBCRYPTO_CRYPTO_RATIONALCIPHERTEXT_H

//Includes Section
#include "palisade.h"
#include "ciphertext.h"

namespace lbcrypto {

	/**
	* @brief RationalCiphertext
	*
	* The RationalCiphertext object is used to contain rational ciphertext data (with numerator and denominator)
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class RationalCiphertext : public CryptoObject<Element> {
	public:

		/**
		* Default constructor
		*/
		RationalCiphertext() : CryptoObject<Element>(), m_integerFlag(false) {}

		/**
		 * Construct a new ciphertext in the given context
		 *
		 * @param cc
		 */
		RationalCiphertext(CryptoContext<Element> cc, bool integerFlag = false) : CryptoObject<Element>(cc) {
			m_numerator = Ciphertext<Element>(new CiphertextImpl<Element>(cc));
			if (!integerFlag)
				m_denominator = Ciphertext<Element>(new CiphertextImpl<Element>(cc));
			m_integerFlag = integerFlag;
		}

		/**
		* Construct a new rational ciphertext from one ciphertext (integer case)
		*
		* @param cc
		*/
		RationalCiphertext(Ciphertext<Element> &numerator) : CryptoObject<Element>(numerator->GetCryptoContext(), numerator->GetKeyTag()) {
			m_numerator = numerator;
			m_integerFlag = true;
		}

		/**
		* Construct a new rational ciphertext from two ciphertextpointers
		*
		* @param &numerator numerator ciphertext
		* @param &denominator denominator ciphertext
		*/
		RationalCiphertext(const Ciphertext<Element> numerator, const Ciphertext<Element> denominator)
			: CryptoObject<Element>(numerator->GetCryptoContext(), numerator->GetKeyTag()) {
			if( numerator->GetCryptoContext() != denominator->GetCryptoContext() )
				throw std::logic_error("Numerator and denominator ciphertexts are from different crypto contexts");
			m_numerator = numerator;
			m_denominator = denominator;
			m_integerFlag = false;
		}
		/**
		* Copy constructor
		*/
		RationalCiphertext(const RationalCiphertext<Element> &ciphertext)
			: CryptoObject<Element>(ciphertext.GetNumerator()->GetCryptoContext(), ciphertext.GetNumerator()->GetKeyTag()) {
			this->context = ciphertext.context;
			m_numerator = Ciphertext<Element>(new CiphertextImpl<Element>(ciphertext.m_numerator));
			if (ciphertext.m_denominator != nullptr)
				m_denominator = Ciphertext<Element>(new CiphertextImpl<Element>(ciphertext.m_denominator));
			m_integerFlag = ciphertext.m_integerFlag;
		}

		/**
		* Move constructor
		*/
		RationalCiphertext(RationalCiphertext<Element> &&ciphertext) {
			this->context = ciphertext.context;
			ciphertext.context = 0;
			m_numerator = ciphertext.m_numerator;
			m_denominator = ciphertext.m_denominator;
			m_integerFlag = ciphertext.m_integerFlag;
		}

		/**
		* Destructor
		*/
		~RationalCiphertext() {}

		string GetKeyTag() const {
			if( m_numerator ) return m_numerator->GetKeyTag();
			return "";
		}

		void SetKeyTag(const string& id) {
			if( m_numerator ) m_numerator->SetKeyTag( id );
			if( m_denominator ) m_denominator->SetKeyTag( id );
		}

		/**
		* Assignment Operator.
		*
		* @param &rhs the Ciphertext to assign from
		* @return this Ciphertext
		*/
		RationalCiphertext<Element>& operator=(const RationalCiphertext<Element> &rhs) {
			this->context = rhs.context;
			if (this != &rhs) {
				*this->m_numerator = *rhs.m_numerator;
				if (rhs.m_denominator != nullptr)
					*this->m_denominator = *rhs.m_denominator;
				this->m_integerFlag = rhs.m_integerFlag;
			}

			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs the Ciphertext to move from
		* @return this Ciphertext
		*/
		RationalCiphertext<Element>& operator=(RationalCiphertext<Element> &&rhs) {
			if (this != &rhs) {
				this->context = rhs.context;
				rhs.context = 0;
				this->m_numerator = rhs.m_numerator;
				this->m_denominator = rhs.m_denominator;
				this->m_integerFlag = rhs.m_integerFlag;
			}

			return *this;
		}

		/**
		 * GetNumerator - get the numerator ciphertext element
		 * @return the numerator
		 */
		const Ciphertext<Element> GetNumerator() const { return m_numerator; }

		/**
		* GetDenominator - get the denominator ciphertext element
		* @return the denominator
		*/
		const Ciphertext<Element> GetDenominator() const { return m_denominator; }

		/**
		* GetIntegerFlag - gets the value of the Integer flag
		* @return the boolean value for the flag
		*/
		bool GetIntegerFlag() const { return m_integerFlag; }

		/**
		* Sets the numerator element
		* @param &element ciphertext element.
		*/
		void SetNumerator(Ciphertext<Element> element) {
			m_numerator = element;
		}

		/**
		* Sets the denominator element
		* @param &element ciphertext element.
		*/
		void SetDenominator(Ciphertext<Element> element) {
			m_denominator = element;
			m_integerFlag = false;
		}

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
		* Performs an addition operation and returns the result.
		*
		* @param &other is the ciphertext to add with.
		* @return the result of the addition.
		*/
		const RationalCiphertext<Element>& operator+=(const RationalCiphertext<Element> &other) {
			// ciphertext object has no data yet, i.e., it is zero-initialized
			if (m_numerator->GetElements().size() == 0)
			{
				if (other.m_numerator != nullptr)
					*m_numerator = *other.m_numerator;
				if (other.m_denominator != nullptr)
					*m_denominator = *other.m_denominator;
				m_integerFlag = other.m_integerFlag;
			}
			else
			{
				this->m_numerator = this->GetCryptoContext()->EvalAdd(m_numerator, other.m_numerator);
				//denominator is assumed to be the same in this initial implementation
			}
			return *this;
		}

		const RationalCiphertext<Element>& operator-=(const RationalCiphertext<Element> &other) {
			throw std::logic_error("operator-= not implemented for RationalCiphertext");
		}

		/**
		* Unary negation operator.
		*
		* @param &other is the ciphertext to add with.
		* @return the result of the addition.
		*/
		const RationalCiphertext<Element> operator-() {
			if (m_numerator->GetElements().size() == 0)
				throw std::logic_error("No elements in the ciphertext to be negated");
			else
			{
				RationalCiphertext<Element> a = RationalCiphertext<Element>(*this);
				a.m_numerator = this->GetCryptoContext()->EvalNegate(this->m_numerator);
				return a;
			}
		}

		bool operator==(const RationalCiphertext<Element>& rhs) const {
			bool topPart = this->GetIntegerFlag() == rhs.GetIntegerFlag() &&
				*this->GetNumerator() == *rhs.GetNumerator();
			if( !topPart || this->GetIntegerFlag() == true )
				return topPart;

			return *this->GetDenominator() == *rhs.GetDenominator();
		}

		bool operator!=(const RationalCiphertext<Element>& rhs) const {
			return ! ( *this == rhs );
		}

	private:

		Ciphertext<Element> m_numerator;
		Ciphertext<Element> m_denominator;

		// if m_integerFlag is set to true, the denominator is ignored
		bool m_integerFlag;

	};

	/**
	* Addition operator overload.  Performs EvalAdd.
	*
	* @tparam Element a ring element.
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition.
	*/
	template <class Element>
	inline RationalCiphertext<Element> operator+(const RationalCiphertext<Element> &a, const RationalCiphertext<Element> &b) { 
		RationalCiphertext<Element> result(b);
		if (a.GetIntegerFlag() && b.GetIntegerFlag() && (a.GetNumerator()!= nullptr))
			result.SetNumerator(b.GetCryptoContext()->EvalAdd(a.GetNumerator(), b.GetNumerator()));
		return result;
	}

	/**
	* Subtraction operator overload.  Performs EvalSub.
	*
	* @tparam Element a ring element.
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction.
	*/
	template <class Element>
	inline RationalCiphertext<Element> operator-(const RationalCiphertext<Element> &a, const RationalCiphertext<Element> &b) {
		RationalCiphertext<Element> result(b);
		if (a.GetIntegerFlag() && b.GetIntegerFlag() && (a.GetNumerator() != nullptr))
			result.SetNumerator(b.GetCryptoContext()->EvalSub(a.GetNumerator(), b.GetNumerator()));
		return result;
	}

	/**
	* Multiplication operator overload.  Performs EvalMult.
	*
	* @tparam Element a ring element.
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication.
	*/
	template <class Element>
	inline RationalCiphertext<Element> operator*(const RationalCiphertext<Element> &a, const RationalCiphertext<Element> &b) {
		RationalCiphertext<Element> result(b);
		if (a.GetIntegerFlag() && b.GetIntegerFlag() && (a.GetNumerator() != nullptr))
			result.SetNumerator(b.GetCryptoContext()->EvalMult(a.GetNumerator(), b.GetNumerator()));
		return result;
	}
} // namespace lbcrypto ends
#endif
