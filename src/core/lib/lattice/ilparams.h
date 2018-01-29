/**
 * @file ilparams.h Wraps parameters for integer lattice operations.  Inherits from ElemParams.
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

#ifndef LBCRYPTO_LATTICE_ILPARAMS_H
#define LBCRYPTO_LATTICE_ILPARAMS_H

#include "elemparams.h"
#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"

namespace lbcrypto
{
template<typename IntType> class ILParamsImpl;
typedef ILParamsImpl<BigInteger> ILParams;
typedef ILParamsImpl<NativeInteger> ILNative1Params;
}

namespace lbcrypto
{

/**
 * @class ILParamsImpl
 * @file elemparams.h
 * @brief Wrapper class to hold the parameters for integer lattice operations and their inheritors.
 */
template<typename IntType>
class ILParamsImpl : public ElemParams<IntType>
{
public:
	typedef IntType Integer;

	/**
	 * Constructor that initializes nothing.
	 * All of the private members will be initialized to zero.
	 */
	ILParamsImpl()
		: ElemParams<IntType>(0, 0, 0, 0, 0) {}

	/**
	 * @brief Constructor for the case of partially pre-computed parameters.
	 *
	 * @param &order the order of the ciphertext.
	 * @param &modulus the ciphertext modulus.
	 * @param &rootOfUnity the root of unity used in the ciphertext.
	 * @param bigModulus the big ciphertext modulus.
	 * @param bigRootOfUnity the big ciphertext modulus used for bit packing operations.
	 * @return 
	 */
	ILParamsImpl(const usint order, const IntType & modulus, const IntType & rootOfUnity, const IntType & bigModulus = 0, const IntType & bigRootOfUnity = 0)
		: ElemParams<IntType>(order, modulus, rootOfUnity, bigModulus, bigRootOfUnity) {}

	/**
	 * @brief Constructor for the case of partially pre-computed parameters.
	 *
	 * @param &order the order of the ciphertext.
	 * @param &modulus the ciphertext modulus.
	 */
	ILParamsImpl(const usint order, const IntType &modulus)
		: ElemParams<IntType>(order, modulus) {
		this->rootOfUnity = RootOfUnity<IntType>(order, modulus);
	}

	/**
	 * @brief Copy constructor.
	 *
	 * @param &rhs the input set of parameters which is copied.
	 */
	ILParamsImpl(const ILParamsImpl &rhs) : ElemParams<IntType>(rhs) {}

	/**
	 * @brief Assignment Operator.
	 *
	 * @param &rhs the ILParams to be copied.
	 * @return the resulting ILParams.
	 */
	const ILParamsImpl& operator=(const ILParamsImpl &rhs) {
		ElemParams<IntType>::operator=(rhs);
		return *this;
	}

	/**
	 * @brief Move constructor.
	 *
	 * @param &rhs the input set of parameters which is copied.
	 */
	ILParamsImpl(const ILParamsImpl &&rhs) : ElemParams<IntType>(rhs) {}

	/**
	 * @brief Standard Destructor method.
	 */
	virtual ~ILParamsImpl() {}

	/**
	 * @brief Equality operator compares ElemParams (which will be dynamic casted)
	 *
	 * @param &rhs is the specified Poly to be compared with this Poly.
	 * @return True if this Poly represents the same values as the specified DCRTPoly, False otherwise
	 */
	bool operator==(const ElemParams<IntType>& rhs) const {
		if( dynamic_cast<const ILParamsImpl<IntType> *>(&rhs) == 0 )
			return false;

		return ElemParams<IntType>::operator==(rhs);
	}

private:
	std::ostream& doprint(std::ostream& out) const {
		out << "ILParams ";
		ElemParams<IntType>::doprint(out);
		out << std::endl;
		return out;
	}

public:
	/**
	 * @brief Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const;

	/**
	 * @brief Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj);
};


} // namespace lbcrypto ends

#endif
