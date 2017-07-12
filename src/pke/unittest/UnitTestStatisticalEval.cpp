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

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

#include "math/matrix.h"

using namespace lbcrypto;

class UnitTestBV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

#include "../lib/cryptocontexthelper.h"

/** Tests linear regression for the Null scheme
* based on of a design matrix of 2x2 and response vector of 2x1
*/
TEST(UTStatisticalEval, Null_Eval_Lin_Regression) {

	usint plaintextModulus = 256;
	usint m = 64;
	typename Poly::Integer modulus("256");
	typename Poly::Integer rootOfUnity("268585022");

	shared_ptr<Poly::Params> ep( new Poly::Params(m, modulus, rootOfUnity) );
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextNull(ep, plaintextModulus);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<IntPlaintextEncoding>(); };

	Matrix<IntPlaintextEncoding> xP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 2);

	std::vector<uint32_t> vectorOfInts1 = { 1,0,1,1,0,1,0,1 };
	xP(0, 0) = vectorOfInts1;

	std::vector<uint32_t> vectorOfInts2 = { 1,1,0,1,0,1,1,0 };
	xP(0, 1) = vectorOfInts2;

	std::vector<uint32_t> vectorOfInts3 = { 1,1,1,1,0,1,0,1 };
	xP(1, 0) = vectorOfInts3;

	std::vector<uint32_t> vectorOfInts4 = { 1,0,0,1,0,1,1,0 };
	xP(1, 1) = vectorOfInts4;

	Matrix<IntPlaintextEncoding> yP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	std::vector<uint32_t> vectorOfInts5 = { 1,1,1,0,0,1,0,1 };
	yP(0, 0) = vectorOfInts5;

	std::vector<uint32_t> vectorOfInts6 = { 1,0,0,1,0,1,1,0 };
	yP(1, 0) = vectorOfInts6;


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

	Matrix<IntPlaintextEncoding> numerator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<IntPlaintextEncoding> denominator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	////////////////////////////////////////////////////////////
	// Correct output
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding numerator1 = { 0, 0, 0, 254, 1, 0, 253, 5, 251, 255, 6, 251, 6, 1, 253, 3, 255, 1, 
		0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	IntPlaintextEncoding numerator2 = { 0, 0, 4, 6, 6, 11, 7, 8, 14, 8, 11, 8, 1, 7, 0, 4, 3, 254, 3, 254, 
		2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	IntPlaintextEncoding denominatorExpected = { 0, 0, 4, 4, 5, 10, 5, 12, 12, 10, 12, 6, 8, 4, 5, 2, 1, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	EXPECT_EQ(numerator1, numerator(0, 0));
	EXPECT_EQ(numerator2, numerator(1, 0));
	EXPECT_EQ(denominatorExpected, denominator(0, 0));
	EXPECT_EQ(denominatorExpected, denominator(1, 0));

}

/** Tests linear regression for the Null scheme
* based on of a design matrix of 2x2 and response vector of 2x1
* In contrast to the previous test, this one also converts an integer
* into a binary polynomial
*/
TEST(UTStatisticalEval, Null_Eval_Lin_Regression_Int) {

	usint plaintextModulus = 256;
	usint m = 64;
	typename Poly::Integer modulus("256");
	typename Poly::Integer rootOfUnity("268585022");

	shared_ptr<Poly::Params> ep( new Poly::Params(m, modulus, rootOfUnity) );
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextNull(ep, plaintextModulus);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<IntPlaintextEncoding>(); };

	Matrix<IntPlaintextEncoding> xP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 2);

	xP(0, 0) = 173;
	xP(0, 1) = 107;
	xP(1, 0) = 175;
	xP(1, 1) = 105;

	Matrix<IntPlaintextEncoding> yP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = 167;
	yP(1, 0) = 105;

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

	Matrix<IntPlaintextEncoding> numerator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<IntPlaintextEncoding> denominator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	////////////////////////////////////////////////////////////
	// Correct output
	////////////////////////////////////////////////////////////

	int32_t numerator1 = -3528000;
	int32_t numerator2 = 6193600;
	int32_t denominatorExpected = 313600;

	EXPECT_EQ(numerator1, numerator(0, 0).EvalToInt(plaintextModulus));
	EXPECT_EQ(numerator2, numerator(1, 0).EvalToInt(plaintextModulus));
	EXPECT_EQ(denominatorExpected, denominator(0, 0).EvalToInt(plaintextModulus));
	EXPECT_EQ(denominatorExpected, denominator(1, 0).EvalToInt(plaintextModulus));

}

/** Tests linear regression for the FV scheme
* based on of a design matrix of 2x2 and response vector of 2x1
* In contrast to the previous test, this one also converts an integer
* into a binary polynomial
*/
TEST(UTStatisticalEval, FV_Eval_Lin_Regression_Int) {

	usint plaintextModulus = 256;
	usint relWindow = 8;
	float stdDev = 4;

	//Set crypto parametes
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(plaintextModulus, 1.06, relWindow, stdDev, 0, 4, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<IntPlaintextEncoding>(); };

	Matrix<IntPlaintextEncoding> xP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 2);

	xP(0, 0) = 173;
	xP(0, 1) = 107;
	xP(1, 0) = 175;
	xP(1, 1) = 105;

	Matrix<IntPlaintextEncoding> yP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = 167;
	yP(1, 0) = 105;

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

	Matrix<IntPlaintextEncoding> numerator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<IntPlaintextEncoding> denominator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	////////////////////////////////////////////////////////////
	// Correct output
	////////////////////////////////////////////////////////////

	int32_t numerator1 = -3528000;
	int32_t numerator2 = 6193600;
	int32_t denominatorExpected = 313600;

	EXPECT_EQ(numerator1, numerator(0, 0).EvalToInt(plaintextModulus));
	EXPECT_EQ(numerator2, numerator(1, 0).EvalToInt(plaintextModulus));
	EXPECT_EQ(denominatorExpected, denominator(0, 0).EvalToInt(plaintextModulus));
	EXPECT_EQ(denominatorExpected, denominator(1, 0).EvalToInt(plaintextModulus));

}

