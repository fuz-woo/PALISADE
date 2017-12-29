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

class UTEvalSum : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};


usint ArbLTVEvalSumPackedArray(std::vector<uint64_t> &clearVector, PlaintextModulus p);
usint ArbBGVEvalSumPackedArray(std::vector<uint64_t> &clearVector, PlaintextModulus p);
usint ArbBGVEvalSumPackedArrayPrime(std::vector<uint64_t> &clearVector, PlaintextModulus p);
usint ArbBFVEvalSumPackedArray(std::vector<uint64_t> &clearVector, PlaintextModulus p);

void
EvalSumSetup(std::vector<uint64_t>& input, usint& expectedSum, PlaintextModulus plaintextMod) {

	usint limit = 15;

	random_device rnd_device;
	mt19937 mersenne_engine(rnd_device());
	uniform_int_distribution<usint> dist(0, limit);

	auto gen = std::bind(dist, mersenne_engine);
	generate(input.begin(), input.end()-2, gen);

	expectedSum = std::accumulate(input.begin(), input.end(), 0);

	expectedSum %= plaintextMod;
}

TEST_F(UTEvalSum, Test_LTV_EvalSum) {

	usint size = 10;
	std::vector<uint64_t> input(size,0);
	usint expectedSum;
	
	EvalSumSetup(input,expectedSum, 89);

	usint result = ArbLTVEvalSumPackedArray(input, 89);

	EXPECT_EQ(result, expectedSum);
}

TEST_F(UTEvalSum, Test_BGV_EvalSum) {

	usint size = 10;
	std::vector<uint64_t> input(size,0);
	usint expectedSum;

	EvalSumSetup(input,expectedSum, 89);

	usint result = ArbBGVEvalSumPackedArray(input, 89);

	EXPECT_EQ(result, expectedSum);
}

TEST_F(UTEvalSum, Test_BGV_EvalSum_Prime_Cyclotomics) {

	usint size = 10;
	std::vector<uint64_t> input(size,0);
	usint expectedSum;

	EvalSumSetup(input,expectedSum, 23);

	usint result = ArbBGVEvalSumPackedArrayPrime(input, 23);

	EXPECT_EQ(result, expectedSum);
}

TEST_F(UTEvalSum, Test_BFV_EvalSum) {
	
	usint size = 10;
	std::vector<uint64_t> input(size,0);
	usint expectedSum;

	EvalSumSetup(input,expectedSum, 89);

	usint result = ArbBFVEvalSumPackedArray(input, 89);

	EXPECT_EQ(result, expectedSum);

}

usint ArbLTVEvalSumPackedArray(std::vector<uint64_t> &clearVector, PlaintextModulus p) {

	usint m = 22;
	BigInteger modulusP(p);

	/*BigInteger modulusQ("1152921504606847009");
	BigInteger squareRootOfRoot("1147559132892757400");

	BigInteger bigmodulus("1361129467683753853853498429727072847489");
	BigInteger bigroot("574170933302565148884487552139817611806");*/

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

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, encodingParams, 16, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	Ciphertext<Poly> ciphertext;

	std::vector<uint64_t> vectorOfInts = std::move(clearVector);
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray);

	auto ciphertextSum = cc->EvalSum(ciphertext, batchSize);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew);

	return intArrayNew->GetPackedValue()[0];

}

usint ArbBGVEvalSumPackedArray(std::vector<uint64_t> &clearVector, PlaintextModulus p) {

	usint m = 22;
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

	Ciphertext<Poly> ciphertext;

	Plaintext intArray = cc->MakePackedPlaintext(clearVector);

	cc->EvalSumKeyGen(kp.secretKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray);

	auto ciphertextSum = cc->EvalSum(ciphertext, batchSize);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew);

	return intArrayNew->GetPackedValue()[0];
}

usint ArbBGVEvalSumPackedArrayPrime(std::vector<uint64_t> &clearVector, PlaintextModulus p) {

	usint m = 11;
	BigInteger modulusP(p);

	BigInteger modulusQ("1125899906842679");
	BigInteger squareRootOfRoot("7742739281594");

	BigInteger bigmodulus("81129638414606681695789005144449");
	BigInteger bigroot("74771531227552428119450922526156");

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

	Ciphertext<Poly> ciphertext;

	Plaintext intArray = cc->MakePackedPlaintext(clearVector);

	cc->EvalSumKeyGen(kp.secretKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray);

	auto ciphertextSum = cc->EvalSum(ciphertext, batchSize);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew);

	return intArrayNew->GetPackedValue()[0];
}

usint ArbBFVEvalSumPackedArray(std::vector<uint64_t> &clearVector, PlaintextModulus p) {

	usint m = 22;
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

	BigInteger delta(modulusQ.DividedBy(modulusP));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(params, encodingParams, 8, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	Ciphertext<Poly> ciphertext;

	std::vector<uint64_t> vectorOfInts = std::move(clearVector);
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	cc->EvalSumKeyGen(kp.secretKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray);

	auto ciphertextSum = cc->EvalSum(ciphertext, batchSize);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew);

	return intArrayNew->GetPackedValue()[0];

}
