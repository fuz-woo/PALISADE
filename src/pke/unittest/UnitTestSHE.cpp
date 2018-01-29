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
#include <list>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"
#include "utils/testcasegen.h"

using namespace std;
using namespace lbcrypto;

class UTSHE : public ::testing::Test {

public:
	const usint m = 16;
	UTSHE() {}
	~UTSHE() {}

protected:
	void SetUp() {
	}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}
};

// This file unit tests the SHE capabilities for all schemes, using all known elements

// FIXME NativePoly SHE tests no bueno on Mult
//GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFV_rlwe, ORD, PTM)
//GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFV_opt, ORD, PTM)

#define GENERATE_TEST_CASES_FUNC(x,y,ORD,PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_opt, ORD, PTM)

static vector<string> AllSchemes( {"Null", "LTV", "BGV", "BFV", /*"BFVrns"*/} );
typedef ::testing::Types<Poly, DCRTPoly, NativePoly> EncryptElementTypes;

// NOTE the SHE tests are all based on these
static const usint ORDER = 16;
static const usint PTMOD = 64;

template<class Element>
static void UnitTest_Add(const CryptoContext<Element> cc, const string& failmsg) {

	std::vector<int64_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	std::vector<int64_t> vectorOfIntsAdd = { 3,1,6,3,2,2,5,1 };
	Plaintext plaintextAdd = cc->MakeCoefPackedPlaintext(vectorOfIntsAdd);

	std::vector<int64_t> vectorOfIntsSub = { -1,-1,0,-1,-2,0,-1,1 };
	Plaintext plaintextSub = cc->MakeCoefPackedPlaintext(vectorOfIntsSub);

	LPKeyPair<Element> kp = cc->KeyGen();
	Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
	Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);

	Ciphertext<Element> cResult = cc->EvalAdd(ciphertext1, ciphertext2);

	Plaintext results;
	cc->Decrypt(kp.secretKey, cResult, &results);

	results->SetLength(plaintextAdd->GetLength());
	EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue()) << failmsg << " EvalAdd fails";

	cResult = cc->EvalSub(ciphertext1, ciphertext2);

	cc->Decrypt(kp.secretKey, cResult, &results);

	results->SetLength(plaintextSub->GetLength());
	EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue()) << failmsg << " EvalSub fails";

	cResult = cc->EvalAdd(ciphertext1, plaintext2);

	cc->Decrypt(kp.secretKey, cResult, &results);
	results->SetLength(plaintextAdd->GetLength());
	EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue()) << failmsg << " EvalAdd Ct and Pt fails";

	cResult = cc->EvalSub(ciphertext1, plaintext2);

	cc->Decrypt(kp.secretKey, cResult, &results);
	results->SetLength(plaintextSub->GetLength());
	EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue()) << failmsg << " EvalSub Ct and Pt fails";
}

GENERATE_TEST_CASES_FUNC(UTSHE, UnitTest_Add, ORDER, PTMOD)

template<class Element>
static void UnitTest_Mult(const CryptoContext<Element> cc, const string& failmsg) {

	std::vector<int64_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	// For cyclotomic order != 16, the expected result is the convolution of vectorOfInt21 and vectorOfInts2
	std::vector<int64_t> vectorOfIntsMultLong = { 2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3 };
	std::vector<int64_t> vectorOfIntsMult = { -17, -11, 2, 0, 5, 9, 16, 12 };

	Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	Plaintext intArrayExpected = cc->MakeCoefPackedPlaintext(cc->GetCyclotomicOrder() == 16 ? vectorOfIntsMult : vectorOfIntsMultLong);

	// Initialize the public key containers.
	LPKeyPair<Element> kp = cc->KeyGen();

	Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);

	Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	cc->EvalMultKeyGen(kp.secretKey);

	Ciphertext<Element> cResult = cc->EvalMult(ciphertext1, ciphertext2);

	Plaintext results;

	cc->Decrypt(kp.secretKey, cResult, &results);

	results->SetLength(intArrayExpected->GetLength());
	EXPECT_EQ(intArrayExpected->GetCoefPackedValue(), results->GetCoefPackedValue()) << failmsg << " EvalMult fails";

	cResult = cc->EvalMult(ciphertext1, plaintext2);

	cc->Decrypt(kp.secretKey, cResult, &results);
	results->SetLength(intArrayExpected->GetLength());
	EXPECT_EQ(intArrayExpected->GetCoefPackedValue(), results->GetCoefPackedValue()) << failmsg << " EvalMult Ct and Pt fails";
}

GENERATE_TEST_CASES_FUNC(UTSHE, UnitTest_Mult, ORDER, PTMOD)

TEST_F(UTSHE, keyswitch_sparse_key_SingleCRT_byteplaintext) {

	usint m = 512;
	usint plaintextModulus = 256;

	CryptoContext<Poly> cc = GenCryptoContextLTV<Poly>(m, plaintextModulus, 50);

	Plaintext plaintext = cc->MakeStringPlaintext("I am good, what are you?! 32 ch");

	LPKeyPair<Poly> kp = cc->KeyGen();

	Ciphertext<Poly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);

	LPKeyPair<Poly> kp2 = cc->SparseKeyGen();

	LPEvalKey<Poly> keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

	Ciphertext<Poly> newCt = cc->KeySwitch(keySwitchHint, ciphertext);

	Plaintext plaintextNew;

	cc->Decrypt(kp2.secretKey, newCt, &plaintextNew);

	EXPECT_EQ(plaintext->GetStringValue(), plaintextNew->GetStringValue());
}

TEST_F(UTSHE, keyswitch_sparse_key_SingleCRT_intArray) {

	//Poly::DestroyPreComputedSamples();
	usint m = 16;
	usint ptm = 2;
	float stdDev = 4;

	BigInteger q;
	BigInteger temp;

	q = FirstPrime<BigInteger>(22, m);

	BigInteger rootOfUnity(RootOfUnity(m, q));
	shared_ptr<Poly::Params> params( new Poly::Params(m, q, rootOfUnity) );

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, ptm, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);
	cc->Enable(SHE);

	LPKeyPair<Poly> kp = cc->KeyGen();

	Ciphertext<Poly> ciphertext;

	std::vector<int64_t> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	Plaintext intArray = cc->MakeCoefPackedPlaintext(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray);

	LPKeyPair<Poly> kp2 = cc->SparseKeyGen();

	LPEvalKey<Poly> keySwitchHint;
	keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

	Ciphertext<Poly> newCt = cc->KeySwitch(keySwitchHint, ciphertext);

	Plaintext intArrayNew;

	cc->Decrypt(kp2.secretKey, newCt, &intArrayNew);

	//this step is needed because there is no marker for padding in the case of Plaintext
	intArrayNew->SetLength(intArray->GetLength());

	EXPECT_EQ(intArray->GetCoefPackedValue(), intArrayNew->GetCoefPackedValue());
}

TEST_F(UTSHE, keyswitch_SingleCRT) {

	usint m = 512;

	float stdDev = 4;

	shared_ptr<Poly::Params> params = ElemParamFactory::GenElemParams<Poly::Params>(m, 50);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, 256, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	Plaintext plaintext = cc->MakeStringPlaintext("I am good, what are you?! 32 ch");

	LPKeyPair<Poly> kp = cc->KeyGen();

	Ciphertext<Poly> ciphertext =
			cc->Encrypt(kp.publicKey, plaintext);

	LPKeyPair<Poly> kp2 = cc->KeyGen();

	LPEvalKey<Poly> keySwitchHint;
	keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

	Ciphertext<Poly> newCt = cc->KeySwitch(keySwitchHint, ciphertext);

	Plaintext plaintextNew;

	cc->Decrypt(kp2.secretKey, newCt, &plaintextNew);

	EXPECT_EQ(plaintext->GetStringValue(), plaintextNew->GetStringValue());
}

TEST_F(UTSHE, sparsekeygen_single_crt_encrypt_decrypt) {

	usint m = 2048;

	float stdDev = 4;

	shared_ptr<Poly::Params> params = ElemParamFactory::GenElemParams<Poly::Params>(m);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, 256, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);
	cc->Enable(SHE);

	Plaintext plaintext = cc->MakeStringPlaintext("I am good, what are you?! 32 ch");

	LPKeyPair<Poly> kp = cc->SparseKeyGen();

	Ciphertext<Poly> ciphertext =
			cc->Encrypt(kp.publicKey, plaintext);

	Plaintext plaintextNew;

	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);

	EXPECT_EQ(plaintextNew->GetStringValue(), plaintext->GetStringValue());

	Poly privateElement(kp.secretKey->GetPrivateElement());
	privateElement.SwitchFormat();

	for (usint i = 1; i < privateElement.GetLength(); i += 2) {
		EXPECT_EQ(BigInteger(0), privateElement.at(i));
	}
}

TEST_F(UTSHE, keyswitch_ModReduce_DCRT) {

	usint m = 512;

	float stdDev = 4;
	usint size = 4;
	usint plaintextmodulus = 256;
	usint relinWindow = 1;

	shared_ptr<ILDCRTParams<BigInteger>> params = GenerateDCRTParams<BigInteger>( m, size, 30 );

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(params, plaintextmodulus, relinWindow, stdDev);

	Plaintext plaintext = cc->MakeStringPlaintext("I am good, what are you?! 32 ch");

	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);
	cc->Enable(SHE);

	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	Ciphertext<DCRTPoly> ciphertext =
			cc->Encrypt(kp.publicKey, plaintext);

	LPKeyPair<DCRTPoly> kp2 = cc->KeyGen();

	LPEvalKey<DCRTPoly> keySwitchHint;
	keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

	Ciphertext<DCRTPoly> newCt = cc->KeySwitch(keySwitchHint, ciphertext);

	Plaintext plaintextNewKeySwitch;

	cc->Decrypt(kp2.secretKey, newCt, &plaintextNewKeySwitch);

	EXPECT_EQ(plaintext->GetStringValue(), plaintextNewKeySwitch->GetStringValue()) << "Key-Switched Decrypt fails";

	/**************************KEYSWITCH TEST END******************************/
	/**************************MODREDUCE TEST BEGIN******************************/

	newCt = cc->ModReduce(newCt);
	DCRTPoly sk2PrivateElement(kp2.secretKey->GetPrivateElement());
	sk2PrivateElement.DropLastElement();
	kp2.secretKey->SetPrivateElement(sk2PrivateElement);

	Plaintext plaintextNewModReduce;

	cc->Decrypt(kp2.secretKey, newCt, &plaintextNewModReduce);
	
	EXPECT_EQ(plaintext->GetStringValue(), plaintextNewModReduce->GetStringValue()) << "Mod Reduced Decrypt fails";
}

TEST_F(UTSHE, ringreduce_single_crt) {
	usint m = 16;

	float stdDev = 4;

	shared_ptr<Poly::Params> params = ElemParamFactory::GenElemParams<Poly::Params>(m);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, 2, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);
	cc->Enable(SHE);

	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	Plaintext intArray = cc->MakeCoefPackedPlaintext(vectorOfInts);

	Ciphertext<Poly> ciphertext = cc->Encrypt(kp.publicKey, intArray);

	LPKeyPair<Poly> kp2 = cc->SparseKeyGen();

	LPEvalKey<Poly> keySwitchHint;
	keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

	Ciphertext<Poly> newCt = cc->KeySwitch(keySwitchHint, ciphertext);

	Plaintext intArrayNew;

	cc->Decrypt(kp2.secretKey, newCt, &intArrayNew);

	ciphertext = cc->RingReduce(ciphertext, keySwitchHint);

	Poly skSparseElement(kp2.secretKey->GetPrivateElement());
	skSparseElement.SwitchFormat();
	skSparseElement.Decompose();
	skSparseElement.SwitchFormat();

	kp2.secretKey->SetPrivateElement(skSparseElement);

	Plaintext intArrayNewRR;

	cc->Decrypt(kp2.secretKey, ciphertext, &intArrayNewRR);

	std::vector<int64_t> intArrayExpected = {1,1,1,1};

	EXPECT_EQ(intArrayNewRR->GetCoefPackedValue(), intArrayExpected);
}

TEST_F(UTSHE, ringreduce_double_crt) {

	usint m = 16;
	float stdDev = 4;
	usint plaintextmodulus = 2;
	usint relinWindow = 1;
	usint size = 3;

	shared_ptr<ILDCRTParams<BigInteger>> params = GenerateDCRTParams<BigInteger>( m, size, 30 );

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(params, plaintextmodulus, relinWindow, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);
	cc->Enable(SHE);

	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	Ciphertext<DCRTPoly> ciphertext;

	std::vector<int64_t> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	Plaintext intArray = cc->MakeCoefPackedPlaintext(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray);

	LPKeyPair<DCRTPoly> kp2 = cc->SparseKeyGen();

	LPEvalKey<DCRTPoly> keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

	Ciphertext<DCRTPoly> newCiphertext = cc->KeySwitch(keySwitchHint, ciphertext);

	Plaintext intArrayNew;

	cc->Decrypt(kp2.secretKey, newCiphertext, &intArrayNew);

	ciphertext = cc->RingReduce(ciphertext, keySwitchHint);

	DCRTPoly skSparseElement(kp2.secretKey->GetPrivateElement());
	skSparseElement.SwitchFormat();
	skSparseElement.Decompose();
	skSparseElement.SwitchFormat();

	kp2.secretKey->SetPrivateElement(skSparseElement);

	Plaintext intArrayNewRR;

	cc->Decrypt(kp2.secretKey, ciphertext, &intArrayNewRR);

	vector<int64_t> intArrayExpected({ 1,1,1,1 });

	EXPECT_EQ(intArrayNewRR->GetCoefPackedValue(), intArrayExpected);

}

TEST_F(UTSHE, canringreduce) {
	BigInteger m1("17729");
	BigInteger m2("17761");
	std::vector<BigInteger> moduli;
	moduli.reserve(2);
	moduli.push_back(m1);
	moduli.push_back(m2);

	LPPublicKeyEncryptionSchemeLTV<Poly> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);
	algorithm.Enable(SHE);

	EXPECT_TRUE(algorithm.CanRingReduce(4096, moduli, 1.006));
	EXPECT_TRUE(algorithm.CanRingReduce(2048, moduli, 1.006));
	EXPECT_FALSE(algorithm.CanRingReduce(1024, moduli, 1.006));
	EXPECT_FALSE(algorithm.CanRingReduce(512, moduli, 1.006));

}

TEST_F(UTSHE, decomposeMult) {
  bool dbg_flag = false;
	usint m1 = 16;

	BigInteger modulus;
	modulus = FirstPrime<BigInteger>(22, m1);
	BigInteger rootOfUnity(RootOfUnity(m1, modulus));
	shared_ptr<ILParams> params( new ILParams(m1, modulus, rootOfUnity) );
	shared_ptr<ILParams> params2( new ILParams(m1 / 2, modulus, rootOfUnity) );
	DEBUG("1");

	Poly x1(params, Format::COEFFICIENT);
	DEBUG("x1 format "<<x1.GetFormat());
	x1 = { 0,0,0,0,0,0,1,0 };

	Poly x2(params, Format::COEFFICIENT);
	x2 = { 0,0,0,0,0,0,1,0 };

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();
	DEBUG("2");
	x1.Decompose();
	x2.Decompose();

	Poly resultsEval(params2, Format::EVALUATION);
	DEBUG("resultsEval format "<<resultsEval.GetFormat());
	x1.SwitchFormat();
	x2.SwitchFormat();
	DEBUG("x1 format "<<x1.GetFormat());
	DEBUG("x2 format "<<x2.GetFormat());
	DEBUG("3");
	resultsEval = x1*x2;

	resultsEval.SwitchFormat();
	DEBUG("4");

	//note now need to do this or else x3 has not data, and when SetFormat is called it tries to switch from EVALUATION and calls CRT on empty vector
	x1.SwitchFormat();

	Poly x3(x1.CloneParametersOnly());


	DEBUG("x1 format "<<x1.GetFormat());
	DEBUG("x3 format "<<x3.GetFormat());
	x3.SetFormat(Format::COEFFICIENT);
	DEBUG("x3 format "<<x3.GetFormat());
	x3 = { 0,0,0,1 };

	Poly x4(x1.CloneParametersOnly());
	x4.SetFormat(Format::COEFFICIENT);
	x4 = { 0,0,0,1 };

	x3.SwitchFormat();
	x4.SwitchFormat();
	DEBUG("5");
	Poly resultsTest(x4.CloneParametersOnly());

	resultsTest = x3 * x4;

	resultsTest.SwitchFormat();
	DEBUG("6");
}
