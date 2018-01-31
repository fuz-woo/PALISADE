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
#include "lattice/elemparamfactory.h"

#include <cmath>


using namespace std;
using namespace lbcrypto;

// A new one of these is created for each test
class UTSHEAdvanced : public testing::Test
{
public:
	UTSHEAdvanced() {}

	void SetUp()
	{
	}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}
};

const usint dcrtBits = 40;

#if !defined(_MSC_VER)

TEST_F(UTSHEAdvanced, test_eval_mult_single_crt) {

	usint m = 16;
	usint relin = 1;
	float stdDev = 4;
	PlaintextModulus ptm = 20;

	shared_ptr<Poly::Params> parms = ElemParamFactory::GenElemParams<Poly::Params>(m, 50);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(parms, ptm, relin, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<Poly> kp;

	std::vector<int64_t> vectorOfInts1 = { 2 };
	Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = { 3 };
	Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);

	Ciphertext<Poly> ciphertext1;
	Ciphertext<Poly> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	Ciphertext<Poly> cResult =
		cc->EvalMult(ciphertext1, ciphertext2);

	LPKeyPair<Poly> newKp = cc->KeyGen();

	LPEvalKey<Poly> keySwitchHint2 = cc->KeySwitchGen(kp.secretKey, newKp.secretKey);

	cResult = cc->KeySwitch(keySwitchHint2, cResult);

	Plaintext results;

	cc->Decrypt(newKp.secretKey, cResult, &results);

	EXPECT_EQ(results->GetCoefPackedValue().at(0), 6);
}


TEST_F(UTSHEAdvanced, test_eval_mult_double_crt) {

	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	PlaintextModulus plaintextModulus = 40;

	vector<NativeInteger> init_moduli(init_size);

	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, init_m);
	NativeInteger temp;
	BigInteger modulus("1");

	for (usint i = 0; i < init_size; i++) {
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus * BigInteger(init_moduli[i]);
		q = NextPrime(q, init_m);
	}

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(init_m, init_moduli, init_rootsOfUnity));

	usint relWindow = 1;

	// Fixme use the ParameterSelection version of genCryptoContext
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(params, plaintextModulus, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc->Enable(SHE);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<DCRTPoly> kp;

	//Generating new cryptoparameters for when modulus reduction is done. - not used?
	std::vector<int64_t> vectorOfInts1 = { 2, 4 };
	Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = { 3, 3 };
	Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);

	Ciphertext<DCRTPoly> ciphertext1;
	Ciphertext<DCRTPoly> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	Ciphertext<DCRTPoly> cResult = cc->EvalMult(ciphertext1, ciphertext2);

	LPKeyPair<DCRTPoly> newKp = cc->KeyGen();

	LPEvalKey<DCRTPoly> keySwitchHint2 = cc->KeySwitchGen(kp.secretKey, newKp.secretKey);

	cResult = cc->KeySwitch(keySwitchHint2, cResult);

	Plaintext results;

	cc->Decrypt(newKp.secretKey, cResult, &results);

	EXPECT_EQ(6, results->GetCoefPackedValue().at(0));
	EXPECT_EQ(18, results->GetCoefPackedValue().at(1));
	EXPECT_EQ(12, results->GetCoefPackedValue().at(2));
}


TEST_F(UTSHEAdvanced, test_eval_add_single_crt) {
	bool dbg_flag = false;
	usint m = 16;
	PlaintextModulus ptm = 20;

	float stdDev = 4;

	shared_ptr<Poly::Params> parms = ElemParamFactory::GenElemParams<Poly::Params>(m);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(parms, ptm, 1, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<Poly> kp;

	DEBUG("Filling 1");
	std::vector<int64_t> vectorOfInts1 = { 2, 3, 1, 4 };
	Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	DEBUG("Filling 2");
	std::vector<int64_t> vectorOfInts2 = { 3, 6, 3, 1 };
	Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	DEBUG("getting pairs");
	kp = cc->KeyGen();

	DEBUG("got pairs");
	Ciphertext<Poly> ciphertext1;
	Ciphertext<Poly> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	DEBUG("after crypt 1");
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);
	DEBUG("after crypt 2");

	Ciphertext<Poly> cResult;
	DEBUG("before EA");
	cResult = cc->EvalAdd(ciphertext1, ciphertext2);
	DEBUG("after");

	Ciphertext<Poly> ciphertextResults({ cResult });
	Plaintext results;

	cc->Decrypt(kp.secretKey, ciphertextResults, &results);

	EXPECT_EQ(5, results->GetCoefPackedValue().at(0));
	EXPECT_EQ(9, results->GetCoefPackedValue().at(1));
	EXPECT_EQ(4, results->GetCoefPackedValue().at(2));
	EXPECT_EQ(5, results->GetCoefPackedValue().at(3));
}


TEST_F(UTSHEAdvanced, test_eval_add_double_crt) {
	bool dbg_flag = false;
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;
	PlaintextModulus plaintextModulus = 16;

	vector<NativeInteger> init_moduli(init_size);

	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, init_m);
	NativeInteger temp;
	BigInteger modulus(1);
	DEBUG("1");

	for (size_t i = 0; i < init_size; i++) {
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus * BigInteger(init_moduli[i]);
		q = NextPrime(q, init_m);
	}
	DEBUG("2");
	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(init_m, init_moduli, init_rootsOfUnity));

	DEBUG("5");

	usint relWindow = 1;

	// Fixme use the ParameterSelection version of genCryptoContext
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(params, plaintextModulus, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc->Enable(SHE);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);

	std::vector<int64_t> vectorOfInts1 = { 2, 4, 8, 5 };
	Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = { 3, 3, 4, 1 };
	Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	Ciphertext<DCRTPoly> ciphertext1;
	Ciphertext<DCRTPoly> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	Ciphertext<DCRTPoly> cResult;

	cResult = cc->EvalAdd(ciphertext1, ciphertext2);


	Ciphertext<DCRTPoly> ciphertextResults({ cResult });
	Plaintext results;

	cc->Decrypt(kp.secretKey, ciphertextResults, &results);

	EXPECT_EQ(results->GetCoefPackedValue().at(0), 5);
	EXPECT_EQ(results->GetCoefPackedValue().at(1), 7);
	EXPECT_EQ(results->GetCoefPackedValue().at(2), -4);
	EXPECT_EQ(results->GetCoefPackedValue().at(3), 6);
	DEBUG("13");
}


TEST_F(UTSHEAdvanced, test_composed_eval_mult_two_towers) {
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 5;

	PlaintextModulus ptm = 16;

	shared_ptr<ILDCRTParams<BigInteger>> params = GenerateDCRTParams<BigInteger>( init_m, init_size, dcrtBits );

	shared_ptr<ILDCRTParams<BigInteger>> paramsSmall( new ILDCRTParams<BigInteger>( *params ) );
	paramsSmall->PopLastParam();

	usint relWindow = 4;

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(params, ptm, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc->Enable(SHE);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);

	CryptoContext<DCRTPoly> ccSmall = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(paramsSmall, ptm, relWindow, init_stdDev, init_size - 1);
	ccSmall->Enable(SHE);
	ccSmall->Enable(ENCRYPTION);
	ccSmall->Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	//Generating Quadratic KeySwitchHint from sk^2 to skNew
	cc->EvalMultKeyGen(kp.secretKey);

	std::vector<int64_t> firstElement = { 8, 5, 4 };
	Plaintext firstElementEncoding = cc->MakeCoefPackedPlaintext(firstElement);

	std::vector<int64_t> secondElement = { 7, 4, 2 };
	Plaintext secondElementEncoding = cc->MakeCoefPackedPlaintext(secondElement);

	Ciphertext<DCRTPoly> ciphertextElementOne;
	Ciphertext<DCRTPoly> ciphertextElementTwo;

	ciphertextElementOne = cc->Encrypt(kp.publicKey, firstElementEncoding);
	ciphertextElementTwo = cc->Encrypt(kp.publicKey, secondElementEncoding);

	Ciphertext<DCRTPoly> cResult = cc->ComposedEvalMult(ciphertextElementOne, ciphertextElementTwo);

	// ok let's try making the secret keys both have one less tower
	// because ComposedEvalMult performs a ModReduce

	DCRTPoly tempPrivateElement(kp.secretKey->GetPrivateElement());
	tempPrivateElement.DropLastElement();
	kp.secretKey->SetPrivateElement(tempPrivateElement);

	LPPrivateKey<DCRTPoly> kpSecretSmall( new LPPrivateKeyImpl<DCRTPoly>(ccSmall) );
	kpSecretSmall->SetPrivateElement(tempPrivateElement);
	LPKeyPair<DCRTPoly> kp1 = ccSmall->KeyGen();

	LPEvalKey<DCRTPoly> KeySwitchHint = ccSmall->KeySwitchGen(kpSecretSmall, kp1.secretKey);

	// have to perform the operation in the new context
	// FIXME we really need a ctor or an operator that copies into a new CryptoContext; below is kind of a hack
	Ciphertext<DCRTPoly> cResultSmall( new CiphertextImpl<DCRTPoly>(ccSmall) );
	cResultSmall->SetDepth( cResult->GetDepth() );
	cResultSmall->SetElements( cResult->GetElements() );
	cResultSmall->SetEncodingType( cResult->GetEncodingType() );

	cResult = ccSmall->KeySwitch(KeySwitchHint, cResultSmall);

	Plaintext results;

	ccSmall->Decrypt(kp1.secretKey, cResult, &results);

	EXPECT_EQ(results->GetCoefPackedValue().at(0), 8);
	EXPECT_EQ(results->GetCoefPackedValue().at(1), 3);
	EXPECT_EQ(results->GetCoefPackedValue().at(2), 0);
	EXPECT_EQ(results->GetCoefPackedValue().at(3), -6);
	EXPECT_EQ(results->GetCoefPackedValue().at(4), 8);
}
#endif
