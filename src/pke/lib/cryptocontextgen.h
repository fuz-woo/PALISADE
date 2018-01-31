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
#include "lattice/elemparamfactory.h"

using namespace lbcrypto;

static const usint DefaultQbits = 50;
static const usint DefaultT = 3;

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextNull(usint ORDER, PlaintextModulus ptm, usint bits=DefaultQbits, usint towers=DefaultT) {
	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params>(ORDER, bits, towers);

	CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextNull(ORDER, ptm);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextLTV(usint ORDER, PlaintextModulus ptm, usint bits=55, usint towers=DefaultT) {
	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params>(ORDER, bits, towers);

	CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextLTV(p, ptm, 1, 4);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextStSt(usint ORDER, PlaintextModulus ptm, usint bits=DefaultQbits, usint towers=DefaultT) {

	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params,typename Element::Integer>(ORDER, bits, towers);

	CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextBGV(usint ORDER, PlaintextModulus ptm, usint bits=DefaultQbits, usint towers=DefaultT, MODE mode=RLWE) {

	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params,typename Element::Integer>(ORDER, bits, towers);

	CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextBGV(p, ptm, 1, 4, mode);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextBFV(usint ORDER, PlaintextModulus ptm, usint bits=DefaultQbits, usint towers=DefaultT, MODE mode=RLWE);

template<>
inline CryptoContext<Poly>
GenCryptoContextBFV(usint ORDER, PlaintextModulus ptm, usint bits, usint towers, MODE mode) {

	shared_ptr<typename Poly::Params> p = ElemParamFactory::GenElemParams<typename Poly::Params>(ORDER, bits, towers);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(ptm, 1.006, 1, 4, 0, 2, 0, mode);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);
	return cc;
}

template<>
inline CryptoContext<NativePoly>
GenCryptoContextBFV(usint ORDER, PlaintextModulus ptm, usint bits, usint towers, MODE mode) {

	CryptoContext<NativePoly> cc = CryptoContextFactory<NativePoly>::genCryptoContextBFV(ptm, 1.006, 1, 4, 0, 0, 0, mode);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);
	return cc;
}

template<>
inline CryptoContext<DCRTPoly>
GenCryptoContextBFV(usint ORDER, PlaintextModulus ptm, usint bits, usint towers, MODE mode) {

	PALISADE_THROW(not_available_error, "DCRT is not supported for BFV");
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextBFVrns(PlaintextModulus ptm, MODE mode=RLWE);

template<>
inline CryptoContext<Poly>
GenCryptoContextBFVrns(PlaintextModulus ptm, MODE mode) {

	PALISADE_THROW(not_available_error, "Poly is not supported for BFVrns");
}

template<>
inline CryptoContext<NativePoly>
GenCryptoContextBFVrns(PlaintextModulus ptm, MODE mode) {

	PALISADE_THROW(not_available_error, "NativePoly is not supported for BFVrns");
}

template<>
inline CryptoContext<DCRTPoly>
GenCryptoContextBFVrns(PlaintextModulus ptm, MODE mode) {
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(ptm, 1.006, 4, 0, 2, 0, mode);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);
	cc->Enable(MULTIPARTY);
	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenTestCryptoContext(const string& name, usint ORDER, PlaintextModulus ptm, usint bits=DefaultQbits, usint towers=DefaultT) {
	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params>(ORDER, bits, towers);
	CryptoContext<Element> cc;

	if( name == "Null" ) {
		cc = CryptoContextFactory<Element>::genCryptoContextNull(ORDER, ptm);
	}
	else if( name == "LTV" )
		cc = CryptoContextFactory<Element>::genCryptoContextLTV(p, ptm, 1, 4);
	else if( name == "StSt" )
		cc = CryptoContextFactory<Element>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5);
	else if( name == "BGV_rlwe" )
		cc = CryptoContextFactory<Element>::genCryptoContextBGV(p, ptm, 1, 4, RLWE);
	else if( name == "BGV_opt" )
		cc = CryptoContextFactory<Element>::genCryptoContextBGV(p, ptm, 1, 4, OPTIMIZED);
	else if( name == "BFV_rlwe" )
		cc = GenCryptoContextBFV<Element>(ORDER, ptm, bits, towers, RLWE);
	else if( name == "BFV_opt" )
		cc = GenCryptoContextBFV<Element>(ORDER, ptm, bits, towers, OPTIMIZED);
	else if( name == "BFVrns_rlwe" )
		cc = GenCryptoContextBFVrns<Element>(ptm, RLWE);
	else if( name == "BFVrns_opt" )
		cc = GenCryptoContextBFVrns<Element>(ptm, OPTIMIZED);
	else {
		cout << "nothing for " << name << endl;
		PALISADE_THROW(not_available_error, "No generator for " + name);
	}

	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

#endif /* SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_ */
