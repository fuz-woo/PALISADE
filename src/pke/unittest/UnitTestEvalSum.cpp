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

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestEvalSum : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};


usint ArbLTVEvalSumPackedArray(std::vector<usint> &clearVector);
usint ArbBVEvalSumPackedArray(std::vector<usint> &clearVector);
usint ArbBVEvalSumPackedArrayPrime(std::vector<usint> &clearVector);
usint ArbFVEvalSumPackedArray(std::vector<usint> &clearVector);


TEST(UTEvalSum, Test_LTV_EvalSum) {

	usint size = 10;
	std::vector<usint> input(size,0);
	usint limit = 15;
	usint plainttextMod = 89;

	random_device rnd_device;
	mt19937 mersenne_engine(rnd_device());
	uniform_int_distribution<usint> dist(0, limit);

	auto gen = std::bind(dist, mersenne_engine);
	generate(input.begin(), input.end()-2, gen);

	usint expectedSum = std::accumulate(input.begin(), input.end(), 0);

	expectedSum %= plainttextMod;
	
	usint result = ArbLTVEvalSumPackedArray(input);

	EXPECT_EQ(result, expectedSum);
	
}


TEST(UTEvalSum, Test_BV_EvalSum) {
	usint size = 10;
	std::vector<usint> input(size,0);
	usint limit = 15;
	usint plainttextMod = 89;

	random_device rnd_device;
	mt19937 mersenne_engine(rnd_device());
	uniform_int_distribution<usint> dist(0, limit);

	auto gen = std::bind(dist, mersenne_engine);
	generate(input.begin(), input.end()-2, gen);

	usint expectedSum = std::accumulate(input.begin(), input.end(), 0);

	expectedSum %= plainttextMod;

	usint result = ArbBVEvalSumPackedArray(input);

	EXPECT_EQ(result, expectedSum);
}

TEST(UTEvalSum, Test_BV_EvalSum_Prime_Cyclotomics) {
	usint size = 10;
	std::vector<usint> input(size, 0);
	usint limit = 15;
	usint plainttextMod = 23;

	random_device rnd_device;
	mt19937 mersenne_engine(rnd_device());
	uniform_int_distribution<usint> dist(0, limit);

	auto gen = std::bind(dist, mersenne_engine);
	generate(input.begin(), input.end() - 2, gen);

	usint expectedSum = std::accumulate(input.begin(), input.end(), 0);

	expectedSum %= plainttextMod;

	usint result = ArbBVEvalSumPackedArrayPrime(input);

	EXPECT_EQ(result, expectedSum);
}

TEST(UTEvalSum, Test_FV_EvalSum) {
	
	usint size = 10;
	std::vector<usint> input(size,0);
	usint limit = 15;
	usint plainttextMod = 89;

	random_device rnd_device;
	mt19937 mersenne_engine(rnd_device());
	uniform_int_distribution<usint> dist(0, limit);

	auto gen = std::bind(dist, mersenne_engine);
	generate(input.begin(), input.end()-2, gen);

	usint expectedSum = std::accumulate(input.begin(), input.end(), 0);

	expectedSum %= plainttextMod;

	usint result = ArbFVEvalSumPackedArray(input);

	EXPECT_EQ(result, expectedSum);

}



usint ArbLTVEvalSumPackedArray(std::vector<usint> &clearVector) {

	PackedIntPlaintextEncoding::Destroy();
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().Destroy();

	usint m = 22;
	usint p = 89;
	BigInteger modulusP(p);

	BigInteger modulusQ("1152921504606847009");
	BigInteger squareRootOfRoot("1147559132892757400");

	BigInteger bigmodulus("1361129467683753853853498429727072847489");
	BigInteger bigroot("574170933302565148884487552139817611806");


	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, encodingParams, 16, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = std::move(clearVector);
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc->EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	return intArrayNew[0];

}


usint ArbBVEvalSumPackedArray(std::vector<usint> &clearVector) {

	usint m = 22;
	usint p = 89;
	BigInteger modulusP(p);
	
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = std::move(clearVector);
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	cc->EvalSumKeyGen(kp.secretKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc->EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	return intArrayNew[0];
}

usint ArbBVEvalSumPackedArrayPrime(std::vector<usint> &clearVector) {

	usint m = 11;
	usint p = 23;
	BigInteger modulusP(p);

	BigInteger modulusQ("1125899906842679");
	BigInteger squareRootOfRoot("7742739281594");

	BigInteger bigmodulus("81129638414606681695789005144449");
	BigInteger bigroot("74771531227552428119450922526156");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = std::move(clearVector);
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	cc->EvalSumKeyGen(kp.secretKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc->EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	return intArrayNew[0];
}



usint ArbFVEvalSumPackedArray(std::vector<usint> &clearVector) {

	usint m = 22;
	usint p = 89;
	BigInteger modulusP(p);

	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(params, encodingParams, 8, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = std::move(clearVector);
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	cc->EvalSumKeyGen(kp.secretKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc->EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	return intArrayNew[0];

}
