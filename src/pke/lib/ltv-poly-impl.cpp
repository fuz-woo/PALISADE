/*
* @file ltv-poly-impl.cpp - poly implementation for the LTV scheme.
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
template class LPCryptoParametersLTV<Poly>;
template class LPPublicKeyEncryptionSchemeLTV<Poly>;
template class LPAlgorithmLTV<Poly>;
template class LPAlgorithmPRELTV<Poly>;
template class LPAlgorithmSHELTV<Poly>;
template class LPLeveledSHEAlgorithmLTV<Poly>;

template class LPCryptoParametersLTV<NativePoly>;
template class LPPublicKeyEncryptionSchemeLTV<NativePoly>;
template class LPAlgorithmLTV<NativePoly>;
template class LPAlgorithmPRELTV<NativePoly>;
template class LPAlgorithmSHELTV<NativePoly>;
template class LPLeveledSHEAlgorithmLTV<NativePoly>;

template <>
bool LPAlgorithmParamsGenLTV<Poly>::ParamsGen(shared_ptr<LPCryptoParameters<Poly>> cryptoParams,
		int32_t evalAddCount, int32_t evalMultCount, int32_t keySwitchCount) const
{
	return false;
}

template <>
bool LPAlgorithmParamsGenLTV<NativePoly>::ParamsGen(shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams,
		int32_t evalAddCount, int32_t evalMultCount, int32_t keySwitchCount) const
{
	return false;
}

}
