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

class UTEvalCC : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

usint BGVCrossCorrelation();
usint BFVCrossCorrelation();
usint BFVrnsCrossCorrelation();


TEST_F(UTEvalCC, Test_BGV_EvalCC) {

	usint result = BGVCrossCorrelation();
	usint expectedResult = 11;

	EXPECT_EQ(result, expectedResult);

}


TEST_F(UTEvalCC, Test_BFV_EvalCC) {
	
	usint result = BFVCrossCorrelation();
	usint expectedResult = 11;

	EXPECT_EQ(result, expectedResult);
}

TEST_F(UTEvalCC, Test_BFVrns_EvalCC) {

	usint result = BFVrnsCrossCorrelation();
	usint expectedResult = 11;

	EXPECT_EQ(result, expectedResult);

}

usint BGVCrossCorrelation() {

	usint m = 22;
	PlaintextModulus p = 89;
	BigInteger modulusP(p);

	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");

	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedEncoding::SetParams(m, p);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	// Compute evaluation keys
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(cc->MakePackedPlaintext({0})); };

	Matrix<Plaintext> x = Matrix<Plaintext>(zeroAlloc, 2, 1);

	x(0, 0) = cc->MakePackedPlaintext({ 0, 1, 1, 1, 0, 1, 1, 1 });
	x(1, 0) = cc->MakePackedPlaintext({ 1, 0, 1, 1, 0, 1, 1, 0 });

	Matrix<Plaintext> y = Matrix<Plaintext>(zeroAlloc, 2, 1);

	y(0, 0) = cc->MakePackedPlaintext({ 0, 1, 1, 1, 0, 1, 1, 1 });
	y(1, 0) = cc->MakePackedPlaintext({ 1, 0, 1, 1, 0, 1, 1, 0 });

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<Poly>>> xEncrypted = cc->EncryptMatrix(kp.publicKey, x);

	shared_ptr<Matrix<RationalCiphertext<Poly>>> yEncrypted = cc->EncryptMatrix(kp.publicKey, y);


	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalCrossCorrelation(xEncrypted, yEncrypted, batchSize);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, result, &intArrayNew);

	return intArrayNew->GetPackedValue()[0];
}


usint BFVCrossCorrelation() {

	usint m = 22;
	PlaintextModulus p = 89; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("72385066601");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("69414828251");
	BigInteger bigmodulus("77302754575416994210914689");
	BigInteger bigroot("76686504597021638023705542");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigInteger bigEvalMultModulus("37778931862957161710549");
	BigInteger bigEvalMultRootOfUnity("7161758688665914206613");
	BigInteger bigEvalMultModulusAlt("1461501637330902918203684832716283019655932547329");
	BigInteger bigEvalMultRootOfUnityAlt("570268124029534407621996591794583635795426001824");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigVector, BigInteger>(m, bigEvalMultModulus);

	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedEncoding::SetParams(m, p);

	usint batchSize = 8;

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	BigInteger delta(modulusQ.DividedBy(modulusP));

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

	Matrix<Plaintext> x = Matrix<Plaintext>(zeroAlloc, 2, 1);

	x(0, 0) = cc->MakePackedPlaintext({ 0, 1, 1, 1, 0, 1, 1, 1 });
	x(1, 0) = cc->MakePackedPlaintext({ 1, 0, 1, 1, 0, 1, 1, 0 });

	Matrix<Plaintext> y = Matrix<Plaintext>(zeroAlloc, 2, 1);

	y(0, 0) = cc->MakePackedPlaintext({ 0, 1, 1, 1, 0, 1, 1, 1 });
	y(1, 0) = cc->MakePackedPlaintext({ 1, 0, 1, 1, 0, 1, 1, 0 });

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<Poly>>> xEncrypted = cc->EncryptMatrix(kp.publicKey, x);

	shared_ptr<Matrix<RationalCiphertext<Poly>>> yEncrypted = cc->EncryptMatrix(kp.publicKey, y);


	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalCrossCorrelation(xEncrypted, yEncrypted, batchSize);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, result, &intArrayNew);

	return intArrayNew->GetPackedValue()[0];

}

usint BFVrnsCrossCorrelation() {

	usint ptm = 65537;
	double sigma = 3.2;
	double rootHermiteFactor = 1.06;
	usint batchSize = 8;

	EncodingParams encodingParams(new EncodingParamsImpl(ptm,batchSize));

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			encodingParams, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED,3);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	// Compute evaluation keys
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(cc->MakePackedPlaintext({0})); };

	Matrix<Plaintext> x = Matrix<Plaintext>(zeroAlloc, 2, 1);

	x(0, 0) = cc->MakePackedPlaintext({ 0, 1, 1, 1, 0, 1, 1, 1 });
	x(1, 0) = cc->MakePackedPlaintext({ 1, 0, 1, 1, 0, 1, 1, 0 });

	Matrix<Plaintext> y = Matrix<Plaintext>(zeroAlloc, 2, 1);

	y(0, 0) = cc->MakePackedPlaintext({ 0, 1, 1, 1, 0, 1, 1, 1 });
	y(1, 0) = cc->MakePackedPlaintext({ 1, 0, 1, 1, 0, 1, 1, 0 });

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xEncrypted = cc->EncryptMatrix(kp.publicKey, x);

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yEncrypted = cc->EncryptMatrix(kp.publicKey, y);


	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalCrossCorrelation(xEncrypted, yEncrypted, batchSize);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, result, &intArrayNew);

	return intArrayNew->GetPackedValue()[0];

}

