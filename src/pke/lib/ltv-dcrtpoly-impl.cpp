/*
* @file ltv-dcrtpoly-impl.cpp - dcrtpoly implementation for the LTV scheme.
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

#include "cryptocontext.h"
#include "ltv.cpp"

namespace lbcrypto {
template class LPCryptoParametersLTV<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeLTV<DCRTPoly>;
template class LPAlgorithmLTV<DCRTPoly>;
template class LPAlgorithmPRELTV<DCRTPoly>;
template class LPAlgorithmSHELTV<DCRTPoly>;
template class LPLeveledSHEAlgorithmLTV<DCRTPoly>;

template<>
bool LPAlgorithmParamsGenLTV<DCRTPoly>::ParamsGen(shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams,
		int32_t evalAddCount, int32_t evalMultCount, int32_t keySwitchCount) const
{
	if (!cryptoParams)
		return false;

	const shared_ptr<LPCryptoParametersLTV<DCRTPoly>> cParams = std::dynamic_pointer_cast<LPCryptoParametersLTV<DCRTPoly>>(cryptoParams);

	double w = cParams->GetAssuranceMeasure();
	double hermiteFactor = cParams->GetSecurityLevel();
	usint depth = cParams->GetDepth();

	double secD = 4 * log2(hermiteFactor);

	double p = cParams->GetPlaintextModulus();
	uint32_t r = cParams->GetRelinWindow();

	double psquared = p * p;
	double rpow5 = pow(r,5);
	double wpow5 = pow(w,5);

	vector<NativeInteger> qvals;

	usint n = 512; // to start
	for(;;) {
		qvals.clear();


		double rootn = sqrt(n);
		double qboundD = 4 * p * r * rootn * w;
		NativeInteger qbound(qboundD);
		double q2boundD = 4 * psquared * rpow5 * pow(rootn, 3) * wpow5;
		NativeInteger q2bound(q2boundD);

		NativeInteger q = FirstPrime<NativeInteger>(static_cast<usint>(ceil(log2(qboundD))),n);
		while( q < qbound )
			q = NextPrime(q, n);

		NativeInteger q2 = FirstPrime<NativeInteger>(static_cast<usint>(ceil(log2(q2boundD))), n);
		while( q2 < q2bound )
			q2 = NextPrime(q2, n);

		qvals.push_back( q );
		qvals.push_back( q2 );

		for( usint i=2; i<depth; i++ ) {
			q2 = NextPrime(q2, n);
			qvals.push_back(q2);
		}

		BigInteger prod(1);
		for( const auto& qv : qvals )
			prod = prod * BigInteger(qv.ConvertToInt());

		// check the correctness constraint
		auto constraint = log2( prod.ConvertToDouble() ) / secD;

		if( n >= constraint ) {
			break;
		}

		n *= 2;
	}

	vector<NativeInteger> roots;

	for( const auto& qv : qvals )
		roots.push_back( RootOfUnity(n, qv) );

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(n, qvals, roots));
	cParams->SetElementParams( params );

	return true;
}

}
