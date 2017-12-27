/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
12/22/2015 2:37PM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Gyana Sahu, grs22@njit.edu
Nishanth Pasham, np386@njit.edu
Description:
This code tests the transform feature of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <random>

#include "../lib/cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UTEvalLR : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

struct rationalInt {
	usint m_numerator;
	usint m_denominator;
	rationalInt():m_numerator(0),m_denominator(0){}
	rationalInt(usint n,usint d) :m_numerator(n), m_denominator(d) {}
};

rationalInt ArbBGVLinearRegressionPackedArray();

rationalInt ArbBFVLinearRegressionPackedArray();

TEST_F(UTEvalLR, Test_BGV_EvalLR) {
	
	rationalInt result = ArbBGVLinearRegressionPackedArray();

	rationalInt expectedResult(300,270);

	EXPECT_EQ(result.m_numerator, expectedResult.m_numerator);
	EXPECT_EQ(result.m_denominator, expectedResult.m_denominator);
}

TEST_F(UTEvalLR, Test_BFV_EvalLR) {
	
	rationalInt result = ArbBFVLinearRegressionPackedArray();

	rationalInt expectedResult(300, 270);

	EXPECT_EQ(result.m_numerator, expectedResult.m_numerator);
	EXPECT_EQ(result.m_denominator, expectedResult.m_denominator);
}

rationalInt ArbBGVLinearRegressionPackedArray() {

	PackedEncoding::Destroy();

	usint m = 22;
	PlaintextModulus p = 2333;
	BigInteger modulusP(p);
	BigInteger modulusQ("1267650600228229401496703214121");
	BigInteger squareRootOfRoot("498618454049802547396506932253");

	BigInteger bigmodulus("1645504557321206042154969182557350504982735865633579863348616321");
	BigInteger bigroot("201473555181182026164891698186176997440470643522932663932844212");
	
	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedEncoding::SetParams(m, p);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 8, stdDev, OPTIMIZED);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	// Compute evaluation keys
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(cc->MakePackedPlaintext({0})); };

	Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 1, 2);

	xP(0, 0) = cc->MakePackedPlaintext({ 0, 2, 1, 3, 2, 2, 1, 2 });
	xP(0, 1) = cc->MakePackedPlaintext({ 1, 1, 2, 1, 1, 1, 3, 2 });

	Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

	yP(0, 0) = cc->MakePackedPlaintext({ 0, 1, 2, 6, 1, 2, 3, 4 });
	
	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<Poly>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	shared_ptr<Matrix<RationalCiphertext<Poly>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegressBatched(x, y, 8);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	rationalInt output((*numerator)(0, 0)->GetPackedValue()[0], (*denominator)(0, 0)->GetPackedValue()[0]);

	return output;

}


rationalInt ArbBFVLinearRegressionPackedArray() {

	ChineseRemainderTransformArb<BigInteger, BigVector>::Reset();

	usint m = 22;

	PlaintextModulus p = 2333; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("1152921504606847009");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("1147559132892757400");

	BigInteger bigmodulus("42535295865117307932921825928971026753");
	BigInteger bigroot("13201431150704581233041184864526870950");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigInteger bigEvalMultModulus("42535295865117307932921825928971026753");
	BigInteger bigEvalMultRootOfUnity("22649103892665819561201725524201801241");
	BigInteger bigEvalMultModulusAlt("115792089237316195423570985008687907853269984665640564039457584007913129642241");
	BigInteger bigEvalMultRootOfUnityAlt("37861550304274465568523443986246841530644847113781666728121717722285667862085");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigVector, BigInteger>(m, bigEvalMultModulus);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedEncoding::SetParams(m, p);

	usint batchSize = 8;

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextBFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(params, encodingParams, 1, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	// Compute evaluation keys
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(cc->MakePackedPlaintext({0})); };

	Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 1, 2);

	xP(0, 0) = cc->MakePackedPlaintext({ 0, 2, 1, 3, 2, 2, 1, 2 });
	xP(0, 1) = cc->MakePackedPlaintext({ 1, 1, 2, 1, 1, 1, 3, 2 });

	Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

	yP(0, 0) = cc->MakePackedPlaintext({ 0, 1, 2, 6, 1, 2, 3, 4 });

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<Poly>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	shared_ptr<Matrix<RationalCiphertext<Poly>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegressBatched(x, y, 8);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	rationalInt output((*numerator)(0, 0)->GetPackedValue()[0], (*denominator)(0, 0)->GetPackedValue()[0]);

	return output;
}
