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
#include <fstream>

#include "../lib/cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

#include "math/matrix.h"

#include <omp.h>

using namespace lbcrypto;

class UTStatisticalEval : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

#include "../lib/cryptocontexthelper.h"

/** Tests linear regression for the Null scheme
* based on of a design matrix of 2x2 and response vector of 2x1
*/
TEST_F(UTStatisticalEval, Null_Eval_Lin_Regression) {

	usint plaintextModulus = 256;
	usint m = 64;
	typename Poly::Integer modulus(plaintextModulus);
	typename Poly::Integer rootOfUnity("268585022");

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, plaintextModulus);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(cc->MakeCoefPackedPlaintext({int64_t(0)})); };

	Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 2, 2);

	std::vector<int64_t> vectorOfInts1 = { 1,0,1,1,0,1,0,1 };
	xP(0, 0) = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = { 1,1,0,1,0,1,1,0 };
	xP(0, 1) = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	std::vector<int64_t> vectorOfInts3 = { 1,1,1,1,0,1,0,1 };
	xP(1, 0) = cc->MakeCoefPackedPlaintext(vectorOfInts3);

	std::vector<int64_t> vectorOfInts4 = { 1,0,0,1,0,1,1,0 };
	xP(1, 1) = cc->MakeCoefPackedPlaintext(vectorOfInts4);

	Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

	std::vector<int64_t> vectorOfInts5 = { 1,1,1,0,0,1,0,1 };
	yP(0, 0) = cc->MakeCoefPackedPlaintext(vectorOfInts5);

	std::vector<int64_t> vectorOfInts6 = { 1,0,0,1,0,1,1,0 };
	yP(1, 0) = cc->MakeCoefPackedPlaintext(vectorOfInts6);

	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<Poly>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	shared_ptr<Matrix<RationalCiphertext<Poly>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegression(x, y);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	////////////////////////////////////////////////////////////
	// Correct output
	////////////////////////////////////////////////////////////

	std::vector<int64_t> numerator1 = { 0, 0, 0, -2, 1, 0, -3, 5, -5, -1, 6, -5, 6, 1, -3, 3, -1, 1,
		0, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	std::vector<int64_t> numerator2 = { 0, 0, 4, 6, 6, 11, 7, 8, 14, 8, 11, 8, 1, 7, 0, 4, 3, -2, 3, -2,
		2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	std::vector<int64_t> denominatorExpected = { 0, 0, 4, 4, 5, 10, 5, 12, 12, 10, 12, 6, 8, 4, 5, 2, 1, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	EXPECT_EQ(numerator1, (*numerator)(0, 0)->GetCoefPackedValue());
	EXPECT_EQ(numerator2, (*numerator)(1, 0)->GetCoefPackedValue());
	EXPECT_EQ(denominatorExpected, (*denominator)(0, 0)->GetCoefPackedValue());
	EXPECT_EQ(denominatorExpected, (*denominator)(1, 0)->GetCoefPackedValue());

}

/** Tests linear regression for the Null scheme
* based on of a design matrix of 2x2 and response vector of 2x1
* In contrast to the previous test, this one also converts an integer
* into a binary polynomial
*/
TEST_F(UTStatisticalEval, Null_Eval_Lin_Regression_Int) {

	PlaintextModulus plaintextModulus = 512;
	usint m = 64;
	typename Poly::Integer modulus(plaintextModulus);
	typename Poly::Integer rootOfUnity("268585022");

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, plaintextModulus);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<Plaintext>(); };

	Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 2, 2);

	xP(0, 0) = cc->MakeIntegerPlaintext(173);
	xP(0, 1) = cc->MakeIntegerPlaintext(107);
	xP(1, 0) = cc->MakeIntegerPlaintext(175);
	xP(1, 1) = cc->MakeIntegerPlaintext(105);

	Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

	yP(0, 0) = cc->MakeIntegerPlaintext(167);
	yP(1, 0) = cc->MakeIntegerPlaintext(105);

	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	LPKeyPair<Poly> kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<Poly>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	shared_ptr<Matrix<RationalCiphertext<Poly>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegression(x, y);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	////////////////////////////////////////////////////////////
	// Correct output
	////////////////////////////////////////////////////////////

	int64_t numerator1 = -3528000;
	int64_t numerator2 = 6193600;
	int64_t denominatorExpected = 313600;

	EXPECT_EQ(numerator1, (*numerator)(0, 0)->GetIntegerValue()) << "numerator(0,0) mismatch";
	EXPECT_EQ(numerator2, (*numerator)(1, 0)->GetIntegerValue()) << "numerator(1,0) mismatch";
	EXPECT_EQ(denominatorExpected, (*denominator)(0, 0)->GetIntegerValue()) << "denominator(0,0) mismatch";
	EXPECT_EQ(denominatorExpected, (*denominator)(1, 0)->GetIntegerValue()) << "denominator(1,0) mismatch";

}

/** Tests linear regression for the BFV scheme
* based on of a design matrix of 2x2 and response vector of 2x1
* In contrast to the previous test, this one also converts an integer
* into a binary polynomial
*/
TEST_F(UTStatisticalEval, BFV_Eval_Lin_Regression_Int) {

	usint plaintextModulus = 512;
	usint relWindow = 8;
	float stdDev = 4;

	//Set crypto parametes
	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(plaintextModulus, 1.06, relWindow, stdDev, 0, 3, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<Plaintext>(); };

	Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 2, 2);

	xP(0, 0) = cc->MakeIntegerPlaintext(173);
	xP(0, 1) = cc->MakeIntegerPlaintext(107);
	xP(1, 0) = cc->MakeIntegerPlaintext(175);
	xP(1, 1) = cc->MakeIntegerPlaintext(105);

	Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

	yP(0, 0) = cc->MakeIntegerPlaintext(167);
	yP(1, 0) = cc->MakeIntegerPlaintext(105);

	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	kp = cc->KeyGen();

	cc->EvalMultKeyGen(kp.secretKey);

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<Poly>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	shared_ptr<Matrix<RationalCiphertext<Poly>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegression(x, y);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	////////////////////////////////////////////////////////////
	// Correct output
	////////////////////////////////////////////////////////////

	int64_t numerator1 = -3528000;
	int64_t numerator2 = 6193600;
	int64_t denominatorExpected = 313600;

	EXPECT_EQ(numerator1, (*numerator)(0, 0)->GetIntegerValue());
	EXPECT_EQ(numerator2, (*numerator)(1, 0)->GetIntegerValue());
	EXPECT_EQ(denominatorExpected, (*denominator)(0, 0)->GetIntegerValue());
	EXPECT_EQ(denominatorExpected, (*denominator)(1, 0)->GetIntegerValue());

}

/** Tests linear regression for the BFVrns scheme
* based on of a design matrix of 2x2 and response vector of 2x1
* In contrast to the previous test, this one also converts an integer
* into a binary polynomial
*/
TEST_F(UTStatisticalEval, BFVrns_Eval_Lin_Regression_Int) {

	usint plaintextModulus = 512;
	float stdDev = 4;

	//Set crypto parametes
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(plaintextModulus, 1.06, stdDev, 0, 4, 0, OPTIMIZED);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<Plaintext>(); };

	Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 2, 2);

	xP(0, 0) = cc->MakeIntegerPlaintext(173);
	xP(0, 1) = cc->MakeIntegerPlaintext(107);
	xP(1, 0) = cc->MakeIntegerPlaintext(175);
	xP(1, 1) = cc->MakeIntegerPlaintext(105);

	Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

	yP(0, 0) = cc->MakeIntegerPlaintext(167);
	yP(1, 0) = cc->MakeIntegerPlaintext(105);

	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	kp = cc->KeyGen();

	cc->EvalMultKeyGen(kp.secretKey);

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	/////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> result;

	// turns off loop parallelization for the main computation
	omp_set_num_threads(1);
#pragma omp parallel
	{
		result = cc->EvalLinRegression(x, y);
	}

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	////////////////////////////////////////////////////////////
	// Correct output
	////////////////////////////////////////////////////////////

	int64_t numerator1 = -3528000;
	int64_t numerator2 = 6193600;
	int64_t denominatorExpected = 313600;

	EXPECT_EQ(numerator1, (*numerator)(0, 0)->GetIntegerValue());
	EXPECT_EQ(numerator2, (*numerator)(1, 0)->GetIntegerValue());
	EXPECT_EQ(denominatorExpected, (*denominator)(0, 0)->GetIntegerValue());
	EXPECT_EQ(denominatorExpected, (*denominator)(1, 0)->GetIntegerValue());

}
