/**
 * @file ildcrtparams.h Wraps parameters for integer lattice operations using double-CRT representation.  Inherits from ElemParams.
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

#ifndef LBCRYPTO_LATTICE_ILDCRTELEMENT_H
#define LBCRYPTO_LATTICE_ILDCRTELEMENT_H

#include "../lattice/elemparams.h"
#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"
#include "../lattice/ilparams.h"

namespace lbcrypto
{
template<typename ModType, typename IntType, typename VecType, typename ParmType> class PolyImpl;
}

namespace lbcrypto
{

/**
 * @brief Parameters for array of ideal lattices (used for Double-CRT).
 *
 * The double-CRT representation of polynomials is a common optimization for lattice encryption operations.
 * Basically, it allows large-modulus polynamials to be represented as multiple smaller-modulus polynomials.
 * The double-CRT representations are discussed theoretically here:
 *   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology – CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin, Heidelberg
 */
template<typename IntType>
class ILDCRTParams : public ElemParams<IntType>
{
public:
	typedef IntType Integer;

	/**
	 * @brief Constructor with basic parameter set.
	 *
	 * @param order the order of the ciphertext.
	 * @param depth is the modulus for the entire tower.
	 * @param bits is the number of bits of each moduli.
	 */
	ILDCRTParams(usint order=0, usint depth=1, usint bits=20);

	/**
	 * @brief Constructor with basic parameters
	 *
	 * @param cyclotomic_order the order of the ciphertext
	 * @param &modulus is the modulus for the primary ciphertext.
	 * @param rootsOfUnity is unused
	 */
	ILDCRTParams(const usint cyclotomic_order, const IntType &modulus, const IntType& rootOfUnity)
		: ElemParams<IntType>(cyclotomic_order, modulus, 0, 0, 0) {
		// note this does not create a tower of native params
	}

	/**
	 * @brief Constructor with some pre-computed parameters provided as input.
	 * @param cyclotomic_order the order of the ciphertext
	 * @param moduli the list of the smaller moduli of the component polynomials.
	 * @param rootsOfUnity the list of the smaller roots of unity of the component polynomials.
	 * @param moduliBig the list of the big moduli of the component polynomials (arbitrary cyclotomics).
	 * @param rootsOfUnityBig the list of the roots of unity of the component polynomials for big moduli (arbitrary cyclotomics).
	 * @return
	 */
	ILDCRTParams(const usint cyclotomic_order, 
		const std::vector<NativeInteger> &moduli, const std::vector<NativeInteger>& rootsOfUnity,
		const std::vector<NativeInteger> &moduliBig = {}, const std::vector<NativeInteger>& rootsOfUnityBig = {})
		: ElemParams<IntType>(cyclotomic_order, 0, 0, 0, 0) {
		if( moduli.size() != rootsOfUnity.size() )
			throw std::logic_error("sizes of moduli and roots of unity do not match");

		if(moduliBig.size() == moduli.size())
		{ 
			for (size_t i = 0; i < moduli.size(); i++) {
				m_parms.push_back(std::shared_ptr<ILNativeParams>(new ILNativeParams(cyclotomic_order, moduli[i], rootsOfUnity[i], moduliBig[i], rootsOfUnityBig[i])));
			}
			RecalculateBigModulus();
		}
		else
		{
			for (size_t i = 0; i < moduli.size(); i++) {
				m_parms.push_back(std::shared_ptr<ILNativeParams>(new ILNativeParams(cyclotomic_order, moduli[i], rootsOfUnity[i])));
			}
		}
		RecalculateModulus();
	}

	/**
	 * @brief Constructor with only cylotomic order and chain of moduli. Multiplied values of the chain of moduli is automatically calculated. Root of unity of the modulus is also calculated.
	 *
	 * @param cyclotomic_order the order of the ciphertext
	 * @param &moduli is the tower of moduli
	 */
	ILDCRTParams(const usint cyclotomic_order, const std::vector<NativeInteger> &moduli)
		: ElemParams<IntType>(cyclotomic_order, 0, 0, 0, 0) {
		for( size_t i=0; i<moduli.size(); i++ ) {
			m_parms.push_back( std::shared_ptr<ILNativeParams>( new ILNativeParams(cyclotomic_order, moduli[i], 0, 0, 0) ) );
		}
		RecalculateModulus();
	}

	/**
	 * @brief Constructor that takes in the cyclotomic order and the component parameters of the component moduli.
	 * @param cyclotomic_order the primary cyclotomic order.  This is not checked against the component moduli.
	 * @param parms the componet parameters.
	 * @return
	 */
	ILDCRTParams(const usint cyclotomic_order, std::vector<std::shared_ptr<ILNativeParams>>& parms)
		: ElemParams<IntType>(cyclotomic_order, 0, 0, 0, 0), m_parms(parms) {
		RecalculateModulus();
	}


	/**
	 * Assignment Operator.
	 *
	 * @param &rhs the copied ILDCRTParams.
	 * @return the resulting ILDCRTParams.
	 */
	const ILDCRTParams& operator=(const ILDCRTParams &rhs) {
		ElemParams<IntType>::operator=(rhs);
		m_parms = rhs.m_parms;

		return *this;
	}

	// ACCESSORS
	/**
	 * @brief Getter method for the component parameters.
	 * @return A vector of the component polynomial parameters.
	 */
	const std::vector<std::shared_ptr<ILNativeParams>> &GetParams() const {
		return m_parms;
	}

	/**
	 * @brief Getter method for the comp19onent parameters of a specific index.
	 * @param i the index of the parameters to return.  Note this this call is unguarded if the index is out of bounds.
	 * @return the parameters at index i.
	 */
	std::shared_ptr<ILNativeParams>& operator[](const usint i) {
		return m_parms[i];
	}

	/**
	 * @brief Removes the last parameter set and adjust the multiplied moduli.
	 *
	 */
	void PopLastParam() {
		this->ciphertextModulus = this->ciphertextModulus / IntType(m_parms.back()->GetModulus().ConvertToInt());
		m_parms.pop_back();
	}

	/**
	 * Destructor.
	 */
	~ILDCRTParams() {}

	/**
	 * @brief Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const;

	bool Deserialize(const Serialized& serObj);

	/**
	 * @brief Equality operator checks if the ElemParams are the same.
	 *
	 * @param &other ElemParams to compare against.
	 * @return the equality check results.
	 */
	bool operator==(const ElemParams<IntType> &other) const {

		const ILDCRTParams *dcrtParams = dynamic_cast<const ILDCRTParams*>(&other);

		if( dcrtParams == 0 ) return 0;

		if( ElemParams<IntType>::operator==(other) == false )
			return false;

		if (m_parms.size() != dcrtParams->m_parms.size() )
			return false;

		for( size_t i=0; i < m_parms.size(); i++ ) {
			if( *m_parms[i] != *dcrtParams->m_parms[i] )
				return false;
		}

		return true;
	}

	/**
	 * @brief Method to recalculate the composite modulus from the component moduli.
	 */
	void RecalculateModulus() {

		this->ciphertextModulus = 1;

		for(usint i = 0; i < m_parms.size(); i++) {
			this->ciphertextModulus = this->ciphertextModulus * IntType(m_parms[i]->GetModulus().ConvertToInt());
		}
	}

	/**
	* @brief Method to recalculate the big composite modulus from the component moduli.
	*/
	void RecalculateBigModulus() {

		this->bigCiphertextModulus = 1;

		for (usint i = 0; i < m_parms.size(); i++) {
			this->bigCiphertextModulus = this->bigCiphertextModulus * IntType(m_parms[i]->GetBigModulus().ConvertToInt());
		}
	}



private:
	std::ostream& doprint(std::ostream& out) const {
		out << "ILDCRTParams ";
		ElemParams<IntType>::doprint(out);
		out << std::endl << " Parms:" << std::endl;
		for( size_t i=0; i < m_parms.size(); i++ ) {
			out << "   " << i << ":" << *m_parms[i] << std::endl;
		}
		return out;
	}

private:
	// array of smaller ILParams
	std::vector<std::shared_ptr<ILNativeParams>>	m_parms;

};

} // namespace lbcrypto ends

#endif
