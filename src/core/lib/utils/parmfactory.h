/**
 * @file parmfactory.h parameter factory.
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

#ifndef SRC_CORE_LIB_UTILS_PARMFACTORY_H_
#define SRC_CORE_LIB_UTILS_PARMFACTORY_H_

// useful for testing

#include "../lattice/dcrtpoly.h"
#include "math/backend.h"
#include "math/distrgen.h"

#include "utils/inttypes.h"

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/poly.h"

using namespace lbcrypto;

template<typename Params, typename Integer>
inline shared_ptr<Params> GenerateTestParams(usint m, const Integer& modulus, const Integer& rootOfUnity) {
	return shared_ptr<Params>(new Params(m, modulus, rootOfUnity));
}


template<typename Params, typename Integer>
inline shared_ptr<Params> GenerateTestParams(usint m, usint nbits) {
	Integer modulus = FirstPrime<Integer>(nbits, m);
	Integer rootOfUnity = RootOfUnity<Integer>(m, modulus);
	return shared_ptr<Params>(new Params(m, modulus, rootOfUnity));
}

/**
 * Generate an ILDCRTParams with a given number of parms, with cyphertext moduli of at least a given size
 * @param m - order
 * @param numOfTower - # of polynomials
 * @param pbits - number of bits in the prime, to start with
 * @return
 */
inline shared_ptr<ILDCRTParams<BigInteger>> GenerateDCRTParams(usint m, usint ptm, usint numOfTower, usint pbits) {

	if( numOfTower == 0 )
		throw std::logic_error("Can't make parms with numOfTower == 0 ");

	std::vector<native_int::BigInteger> moduli(numOfTower);
	std::vector<native_int::BigInteger> rootsOfUnity(numOfTower);

	native_int::BigInteger ptmI( ptm );

	native_int::BigInteger q = FirstPrime<native_int::BigInteger>(pbits, m);
	BigInteger modulus(1);

	usint j = 0;
	for(;;) {
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, q);
		modulus = modulus * BigInteger(q.ConvertToInt());
		if( ++j == numOfTower )
			break;

		q = NextPrime(q, m);
	}

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(m, moduli, rootsOfUnity));

	return params;
}


#endif /* SRC_CORE_LIB_UTILS_PARMFACTORY_H_ */
