/**
 * @file elemparamfactory.h Creates ElemParams objects for PALISADE.
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

#ifndef SRC_CORE_LIB_LATTICE_ELEMPARAMFACTORY_H_
#define SRC_CORE_LIB_LATTICE_ELEMPARAMFACTORY_H_

#include <memory>
using std::shared_ptr;

#include <string>
using std::string;

#include "../math/backend.h"
#include "ilparams.h"
#include "ildcrtparams.h"
#include "utils/parmfactory.h"

namespace lbcrypto {

// predefined values of m are 16, 1024, 2048, 4096, 8192, 16384, 32768 and 65536

// the items in ElementOrder are an index into DefaultSet[]
enum ElementOrder {
	M16 = 0,
	M1024,
	M2048,
	M4096,
	M8192,
	M16384,
	M32768
};

class ElemParamFactory {
public:
	static struct ElemParmSet {
		usint				m;	// cyclotomic order
		usint				n;	// ring dimension
		string				q;	// ciphertext modulus
		string				ru;	// root of unity
	} DefaultSet[];

	static size_t GetNearestIndex(usint m) {
		size_t sIdx = 0;
		if( DefaultSet[0].m < m ) {
			for( sIdx = 1; DefaultSet[sIdx].m != 0; sIdx++ ) {
				if( m <= DefaultSet[sIdx].m )
					break;
			}
		}
		if( DefaultSet[sIdx].m == 0 )
			sIdx--;

		return sIdx;
	}

	/**
	 * GenElemParams for a particular predefined cyclotomic order
	 *
	 * @param o - the order (an ElementOrder)
	 * @return new params
	 */
	template<typename P>
	static shared_ptr<P> GenElemParams(ElementOrder o) {
		return shared_ptr<P>( new P(DefaultSet[o].m, typename P::Integer(DefaultSet[o].q), typename P::Integer(DefaultSet[o].ru)) );
	}

	/**
	 * GenElemParams for a particular cyclotomic order - finds the predefined order that's >= m
	 *
	 * @param m - order
	 * @return new params
	 */
	template<typename P>
	static shared_ptr<P> GenElemParams(usint m) {
		size_t sIdx = GetNearestIndex(m);

		return shared_ptr<P>( new P(DefaultSet[sIdx].m, typename P::Integer(DefaultSet[sIdx].q), typename P::Integer(DefaultSet[sIdx].ru)) );
	}

	/**
	 * GenElemParams for a particular cyclotomic order and bits in q
	 * NOTE this is deprecated and will go away once ParamsGen is fully implemented
	 *
	 * @param m - cyclotomic order
	 * @param bits # of bits in q
	 * @return new params
	 */
	template<typename P>
	static shared_ptr<P> GenElemParams(usint m, usint bits, usint towersize = 0) {
		typename P::Integer q = FirstPrime<typename P::Integer>(bits,m);
		typename P::Integer ru = RootOfUnity<typename P::Integer>(m, q);
		return shared_ptr<P>( new P(m, q, ru) );
	}

	/**
	 * GenElemParams given the three components directly
	 *
	 * @param m - cyclotomic order
	 * @param ctModulus - ciphertext modulus
	 * @param rootUnity - root of unity
	 * @return
	 */
	template<typename P>
	static shared_ptr<P> GenElemParams(usint m, const typename P::Integer& ctModulus, const typename P::Integer& rootUnity) {
		return shared_ptr<P>( new P(m, ctModulus, rootUnity) );
	}
};

template<>
inline shared_ptr<ILDCRTParams<BigInteger>>
ElemParamFactory::GenElemParams<ILDCRTParams<BigInteger>>(usint m, usint bits, usint towersize) {
	return GenerateDCRTParams<BigInteger>(m, towersize, bits);
}

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_LATTICE_ELEMPARAMFACTORY_H_ */
