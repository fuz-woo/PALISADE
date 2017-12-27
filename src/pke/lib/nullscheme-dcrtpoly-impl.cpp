/*
 * @file nullscheme-dcrtpoly-impl.cpp - null scheme dcrtpoly implementation
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
#include "nullscheme.h"

namespace lbcrypto {

template<>
Ciphertext<DCRTPoly> LPAlgorithmSHENull<DCRTPoly>::EvalMult(const Ciphertext<DCRTPoly> ciphertext1,
	const Ciphertext<DCRTPoly> ciphertext2) const {

	Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

	const DCRTPoly& c1 = ciphertext1->GetElement();
	const DCRTPoly& c2 = ciphertext2->GetElement();

	const vector<typename DCRTPoly::PolyType>& c1e = c1.GetAllElements();
	const vector<typename DCRTPoly::PolyType>& c2e = c2.GetAllElements();

	const auto ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

	vector<typename DCRTPoly::PolyType> mResults;

	for( size_t i = 0; i < c1.GetNumOfElements(); i++ ) {
		typename DCRTPoly::PolyType v = ElementNullSchemeMultiply(c1e.at(i), c2e.at(i), ptm);
		mResults.push_back(v);
	}

	DCRTPoly	cResult(mResults);

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template<>
Ciphertext<DCRTPoly> LPAlgorithmSHENull<DCRTPoly>::EvalMult(const Ciphertext<DCRTPoly> ciphertext1,
	const Plaintext plaintext) const {

	Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

	const DCRTPoly& c1 = ciphertext1->GetElement();
	const DCRTPoly& c2 = plaintext->GetEncodedElement<DCRTPoly>();

	const vector<typename DCRTPoly::PolyType>& c1e = c1.GetAllElements();
	const vector<typename DCRTPoly::PolyType>& c2e = c2.GetAllElements();

	const auto ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

	vector<typename DCRTPoly::PolyType> mResults;

	for( size_t i = 0; i < c1.GetNumOfElements(); i++ ) {
		typename DCRTPoly::PolyType v = ElementNullSchemeMultiply(c1e.at(i), c2e.at(i), ptm);
		mResults.push_back(v);
	}

	DCRTPoly	cResult(mResults);

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template class LPCryptoParametersNull<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeNull<DCRTPoly>;
template class LPAlgorithmNull<DCRTPoly>;
}
