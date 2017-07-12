/**
 * @file ciphertextgen.h -- Generator for crypto contexts.
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

#ifndef SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_
#define SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_

#include "palisade.h"
#include "cryptocontext.h"
#include "utils/parmfactory.h"

using namespace lbcrypto;

static const usint PrimeBits = 50;

inline shared_ptr<CryptoContext<Poly>> GenCryptoContextElementNull(usint ORDER, usint ptm) {
	shared_ptr<Poly::Params> p( new Poly::Params(ORDER, Poly::Integer(ptm), Poly::Integer::ONE) );
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextNull(p, ptm);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline shared_ptr<CryptoContext<DCRTPoly>> GenCryptoContextElementArrayNull(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<DCRTPoly::Params> p = GenerateDCRTParams(ORDER, ptm, ntowers, bits);

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextNull(p, ptm);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline shared_ptr<CryptoContext<Poly>> GenCryptoContextElementLTV(usint ORDER, usint ptm, usint bits=PrimeBits) {
	shared_ptr<Poly::Params> p = GenerateTestParams<Poly::Params,Poly::Integer>(ORDER, bits);

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(p, ptm, 1, 4);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline shared_ptr<CryptoContext<DCRTPoly>> GenCryptoContextElementArrayLTV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<DCRTPoly::Params> p = GenerateDCRTParams(ORDER, ptm, ntowers, bits);

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(p, ptm, 1, 4, ntowers);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline shared_ptr<CryptoContext<Poly>> GenCryptoContextElementStSt(usint ORDER, usint ptm, usint bits=PrimeBits) {
	shared_ptr<Poly::Params> p = GenerateTestParams<Poly::Params,Poly::Integer>(ORDER, bits);

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline shared_ptr<CryptoContext<DCRTPoly>> GenCryptoContextElementArrayStSt(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<DCRTPoly::Params> p = GenerateDCRTParams(ORDER, ptm, ntowers, bits);

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5, ntowers);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline shared_ptr<CryptoContext<Poly>> GenCryptoContextElementBV(usint ORDER, usint ptm, usint bits=PrimeBits) {
	shared_ptr<Poly::Params> p = GenerateTestParams<Poly::Params,Poly::Integer>(ORDER, bits);

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(p, ptm, 1, 4);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline shared_ptr<CryptoContext<DCRTPoly>> GenCryptoContextElementArrayBV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<DCRTPoly::Params> p = GenerateDCRTParams(ORDER, ptm, ntowers, bits);

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBV(p, ptm, 1, 3, RLWE, ntowers);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}


inline shared_ptr<CryptoContext<Poly>> GenCryptoContextElementFV(usint ORDER, usint ptm, usint bits=PrimeBits) {
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(ptm, 1.006, 1, 4, 0, 2, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);
	return cc;
}

inline shared_ptr<CryptoContext<DCRTPoly>> GenCryptoContextElementArrayFV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextFV(ptm, 1.006, 1, 4, 0, 2, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

#endif /* SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_ */
