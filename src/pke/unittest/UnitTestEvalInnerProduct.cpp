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

class UnitTestEvalInnerProduct : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

usint ArbLTVInnerProductPackedArray(std::vector<usint> &input1,std::vector<usint> &input2);
usint ArbBVInnerProductPackedArray(std::vector<usint> &input1, std::vector<usint> &input2);
usint ArbFVInnerProductPackedArray(std::vector<usint> &input1, std::vector<usint> &input2);

TEST(UTEvalIP, Test_LTV_EvalInnerProduct) {

	usint size = 10;
	std::vector<usint> input1(size, 0);
	std::vector<usint> input2(size, 0);
	usint limit = 15;
	usint plainttextMod = 89;

	random_device rnd_device;
	mt19937 mersenne_engine(rnd_device());
	uniform_int_distribution<usint> dist(0, limit);

	auto gen = std::bind(dist, mersenne_engine);
	generate(input1.begin(), input1.end() - 2, gen);
	generate(input2.begin(), input2.end() - 2, gen);

	usint expectedResult = std::inner_product(input1.begin(), input1.end(), input2.begin(), 0);
	expectedResult %= plainttextMod;

	usint result = ArbLTVInnerProductPackedArray(input1, input2);

	EXPECT_EQ(result, expectedResult);
	
}

TEST(UTEvalIP, Test_BV_EvalInnerProduct) {
	usint size = 10;
	std::vector<usint> input1(size, 0);
	std::vector<usint> input2(size, 0);
	usint limit = 15;
	usint plainttextMod = 89;

	random_device rnd_device;
	mt19937 mersenne_engine(rnd_device());
	uniform_int_distribution<usint> dist(0, limit);

	auto gen = std::bind(dist, mersenne_engine);
	generate(input1.begin(), input1.end() - 2, gen);
	generate(input2.begin(), input2.end() - 2, gen);

	usint expectedResult = std::inner_product(input1.begin(), input1.end(), input2.begin(), 0);
	expectedResult %= plainttextMod;

	usint result = ArbBVInnerProductPackedArray(input1, input2);

	EXPECT_EQ(result, expectedResult);

}

TEST(UTEvalIP, Test_FV_EvalInnerProduct) {
	
	usint size = 10;
	std::vector<usint> input1(size, 0);
	std::vector<usint> input2(size, 0);
	usint limit = 15;
	usint plainttextMod = 2333;

	random_device rnd_device;
	mt19937 mersenne_engine(rnd_device());
	uniform_int_distribution<usint> dist(0, limit);

	auto gen = std::bind(dist, mersenne_engine);
	generate(input1.begin(), input1.end() - 2, gen);
	generate(input2.begin(), input2.end() - 2, gen);

	usint expectedResult = std::inner_product(input1.begin(), input1.end(), input2.begin(), 0);
	expectedResult %= plainttextMod;

	usint result = ArbFVInnerProductPackedArray(input1, input2);

	EXPECT_EQ(result, expectedResult);
}



usint ArbLTVInnerProductPackedArray(std::vector<usint> &input1, std::vector<usint> &input2) {

	usint m = 22;
	usint p = 89;
	BigInteger modulusP(p);
	
	BigInteger modulusQ("1267650600228229401496703214121");
	BigInteger squareRootOfRoot("498618454049802547396506932253");

	BigInteger bigmodulus("1645504557321206042154969182557350504982735865633579863348616321");
	BigInteger bigroot("201473555181182026164891698186176997440470643522932663932844212");

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

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;

	std::vector<usint> vectorOfInts1 = std::move(input1);
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);


	std::vector<usint> vectorOfInts2 = std::move(input2);
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);
	cc->EvalMultKeyGen(kp.secretKey);

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false);

	auto result = cc->EvalInnerProduct(ciphertext1[0], ciphertext2[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(result);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	return intArrayNew[0];

}


usint ArbBVInnerProductPackedArray(std::vector<usint> &input1, std::vector<usint> &input2) {

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

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;

	std::vector<usint> vectorOfInts1 = std::move(input1);
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);


	std::vector<usint> vectorOfInts2 = std::move(input2);
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false);

	auto result = cc->EvalInnerProduct(ciphertext1[0], ciphertext2[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(result);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	return intArrayNew[0];

}


usint ArbFVInnerProductPackedArray(std::vector<usint> &input1, std::vector<usint> &input2) {

	usint m = 22;
	usint p = 2333; // we choose s.t. 2m|p-1 to leverage CRTArb
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

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(params, encodingParams, 1, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;

	std::vector<usint> vectorOfInts1 = std::move(input1);
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);


	std::vector<usint> vectorOfInts2 = std::move(input2);
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false);

	auto result = cc->EvalInnerProduct(ciphertext1[0], ciphertext2[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(result);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	return intArrayNew[0];

}


