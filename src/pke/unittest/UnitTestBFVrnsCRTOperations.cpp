/*
 * @file 
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

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "../lib/cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include "utils/parmfactory.h"

using namespace std;
using namespace lbcrypto;

class UTBFVrnsCRTOperations : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

TEST_F(UTBFVrnsCRTOperations, BFVrns_SwitchCRTBasis) {

	usint ptm = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 7, 0, OPTIMIZED,8);

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();

	typename DCRTPoly::DugType dug;

	//Generate the element "a" of the public key
	const DCRTPoly a(dug, params, Format::COEFFICIENT);

	Poly resultA = a.CRTInterpolate();

	const DCRTPoly b = a.SwitchCRTBasis(paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	Poly resultB = b.CRTInterpolate();
	
	BigInteger A0 = resultA.at(0);

	if (A0 > (params->GetModulus()>>1) )
		A0 = params->GetModulus() - A0;

	BigInteger B0 = resultB.at(0);

	if (B0 > (paramsS->GetModulus()>>1) )
		B0 = paramsS->GetModulus() - B0;

	EXPECT_EQ(A0,B0) << "SwitchCRTBasis produced incorrect results";

}

// TESTING POLYNOMIAL MULTIPLICATION - ONE TERM IS CONSTANT POLYNOMIAL
TEST_F(UTBFVrnsCRTOperations, BFVrns_Mult_by_Constant) {

	usint ptm = 1<<15;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED,3);

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();

	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsBFVrns->GetDCRTParamsQS();

	typename DCRTPoly::DugType dug;

	//Generate uninform element
	DCRTPoly a(dug, params, Format::COEFFICIENT);

	//Generate constant element
	DCRTPoly b(params, Format::COEFFICIENT,true);
	b = b + (uint64_t)1976860313128;
	b = b.Negate();

	Poly aPoly = a.CRTInterpolate();

	Poly bPoly = b.CRTInterpolate();

	a.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	b.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	Poly resultExpandedB = b.CRTInterpolate();

	BigInteger A0 = bPoly.at(0);

	if (A0 > (bPoly.GetModulus()>>1) )
		A0 = bPoly.GetModulus() - A0;

	BigInteger B0 = resultExpandedB.at(0);

	if (B0 > (resultExpandedB.GetModulus()>>1) )
		B0 = resultExpandedB.GetModulus() - B0;

	EXPECT_EQ(A0,B0) << "CRT expansion of polynomial b worked incorrectly";

	// a and b are already in evaluation representation after ExpandCRTBasis

	// Polynomial multiplication in Q*S CRT basis
	DCRTPoly c = a*b;

	// Put it back in coefficient representation
	c.SwitchFormat();

	Poly resultC = c.CRTInterpolate();

	//Starting multiprecision polynomial multiplication

	BigInteger modulus("1606938044258990275541962092341162602522202993782792836833281");
	BigInteger root("859703842628303907691187858658134128225754111718143879712783");
	usint m = 8192;

	shared_ptr<ILParams> paramsPoly(new ILParams(m, modulus, root));

	aPoly.SwitchModulus(modulus,root);
	bPoly.SwitchModulus(modulus,root);

	// Convert from coefficient polynomial representation to evaluation one
	aPoly.SwitchFormat();
	bPoly.SwitchFormat();

	// Polynomial multiplication in Q*S CRT basis
	Poly cPoly = aPoly*bPoly;

	// Put it back in coefficient representation
	cPoly.SwitchFormat();

	//Ended multiprecision multiplication

	A0 = cPoly.at(0);

	if (A0 > (cPoly.GetModulus()>>1) )
		A0 = cPoly.GetModulus() - A0;

	B0 = resultC.at(0);

	if (B0 > (resultC.GetModulus()>>1) )
		B0 = resultC.GetModulus() - B0;

	EXPECT_EQ(A0,B0) << "Results of multiprecision and CRT multiplication do not match";

	DCRTPoly rounded = c.ScaleAndRound(paramsS,cryptoParamsBFVrns->GetCRTMultIntTable(),cryptoParamsBFVrns->GetCRTMultFloatTable());

	DCRTPoly roundedQ = rounded.SwitchCRTBasis(params, cryptoParamsBFVrns->GetCRTSInverseTable(),
			cryptoParamsBFVrns->GetCRTsDivsiModqiTable(), cryptoParamsBFVrns->GetCRTsModqiTable());

	Poly resultRoundedQ = roundedQ.CRTInterpolate();

	Poly roundedMP = cPoly.MultiplyAndRound(BigInteger(ptm),roundedQ.GetModulus());

	A0 = roundedMP.at(0);

	if (A0 > (roundedMP.GetModulus()>>1) )
		A0 = roundedMP.GetModulus() - A0;

	B0 = resultRoundedQ.at(0);

	if (B0 > (resultRoundedQ.GetModulus()>>1) )
		B0 = resultRoundedQ.GetModulus() - B0;

	EXPECT_EQ(A0,B0) << "Results of multiprecision and CRT multiplication after scaling + rounding do not match";

}

// TESTING POLYNOMIAL MULTIPLICATION - UNIFORM AND GAUSSIAN RANDOM POLYNOMIALS
TEST_F(UTBFVrnsCRTOperations, BFVrns_Mult_by_Gaussian) {

	usint ptm = 1<<15;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED,3);

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();

	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsBFVrns->GetDCRTParamsQS();

	typename DCRTPoly::DugType dug;

	//Generate uninform element
	DCRTPoly a(dug, params, Format::COEFFICIENT);

	//dgg with distribution parameter 400000
	typename DCRTPoly::DggType dgg(400000);

	//Generate Discrete Gaussian element
	DCRTPoly b(dgg, params, Format::COEFFICIENT);

	Poly aPoly = a.CRTInterpolate();

	Poly bPoly = b.CRTInterpolate();

	a.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	b.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	Poly resultExpandedB = b.CRTInterpolate();

	BigInteger A0 = bPoly.at(0);

	if (A0 > (bPoly.GetModulus()>>1) )
		A0 = bPoly.GetModulus() - A0;

	BigInteger B0 = resultExpandedB.at(0);

	if (B0 > (resultExpandedB.GetModulus()>>1) )
		B0 = resultExpandedB.GetModulus() - B0;

	EXPECT_EQ(A0,B0) << "CRT expansion of polynomial b worked incorrectly";

	// a and b are already in evaluation representation after ExpandCRTBasis

	// Polynomial multiplication in Q*S CRT basis
	DCRTPoly c = a*b;

	// Put it back in coefficient representation
	c.SwitchFormat();

	Poly resultC = c.CRTInterpolate();

	//Starting multiprecision polynomial multiplication

	BigInteger modulus("1606938044258990275541962092341162602522202993782792836833281");
	BigInteger root("859703842628303907691187858658134128225754111718143879712783");
	usint m = 8192;

	shared_ptr<ILParams> paramsPoly(new ILParams(m, modulus, root));

	aPoly.SwitchModulus(modulus,root);
	bPoly.SwitchModulus(modulus,root);

	// Convert from coefficient polynomial representation to evaluation one
	aPoly.SwitchFormat();
	bPoly.SwitchFormat();

	// Polynomial multiplication in Q*S CRT basis
	Poly cPoly = aPoly*bPoly;

	// Put it back in coefficient representation
	cPoly.SwitchFormat();

	//Ended multiprecision multiplication

	A0 = cPoly.at(0);

	if (A0 > (cPoly.GetModulus()>>1) )
		A0 = cPoly.GetModulus() - A0;

	B0 = resultC.at(0);

	if (B0 > (resultC.GetModulus()>>1) )
		B0 = resultC.GetModulus() - B0;

	EXPECT_EQ(A0,B0) << "Results of multiprecision and CRT multiplication do not match";

	DCRTPoly rounded = c.ScaleAndRound(paramsS,cryptoParamsBFVrns->GetCRTMultIntTable(),cryptoParamsBFVrns->GetCRTMultFloatTable());

	DCRTPoly roundedQ = rounded.SwitchCRTBasis(params, cryptoParamsBFVrns->GetCRTSInverseTable(),
			cryptoParamsBFVrns->GetCRTsDivsiModqiTable(), cryptoParamsBFVrns->GetCRTsModqiTable());

	Poly resultRoundedQ = roundedQ.CRTInterpolate();

	Poly roundedMP = cPoly.MultiplyAndRound(BigInteger(ptm),roundedQ.GetModulus());

	A0 = roundedMP.at(0);

	if (A0 > (roundedMP.GetModulus()>>1) )
		A0 = roundedMP.GetModulus() - A0;

	B0 = resultRoundedQ.at(0);

	if (B0 > (resultRoundedQ.GetModulus()>>1) )
		B0 = resultRoundedQ.GetModulus() - B0;

	EXPECT_EQ(A0,B0) << "Results of multiprecision and CRT multiplication after scaling + rounding do not match";

}


