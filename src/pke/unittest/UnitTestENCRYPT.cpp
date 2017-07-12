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

#include "palisade.h"
#include "cryptolayertests.h"
#include "cryptocontextparametersets.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

// This file unit tests the ENCRYPTION capabilities for all schemes, using both known elements

class UnitTestENCRYPT : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

static shared_ptr<CryptoContext<Poly>> GenerateTestCryptoContext(const string& parmsetName) {
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(parmsetName);
	cc->Enable(ENCRYPTION);
	return cc;
}

static shared_ptr<CryptoContext<DCRTPoly>> GenerateTestDCRTCryptoContext(const string& parmsetName, usint nTower, usint pbits) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextHelper::getNewDCRTContext(parmsetName, nTower, pbits);
	cc->Enable(ENCRYPTION);
	return cc;
}

template <typename Element>
void
UnitTestEncryption(const shared_ptr<CryptoContext<Element>> cc) {
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;

	GenerateTestPlaintext(cc->GetCyclotomicOrder(),
			cc->GetCryptoParameters()->GetPlaintextModulus(),
			plaintextShort, plaintextFull, plaintextLong);

	size_t intSize = cc->GetCyclotomicOrder() / 2;
	auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	vector<uint32_t> intvec;
	for( size_t ii=0; ii<intSize; ii++)
		intvec.push_back( rand() % ptm );
	IntPlaintextEncoding plaintextInt(intvec);

	vector<int32_t> sintvec;
	for( size_t ii=0; ii<intSize; ii++) {
		int rnum = rand() % ptm;
		if( rnum > (int)ptm/2 ) rnum = ptm - rnum;
		sintvec.push_back( rnum );
	}
	SignedIntPlaintextEncoding plaintextSInt(sintvec);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encrypt and decrypt short, with padding, full, and long
	////////////////////////////////////////////////////////////

	if( plaintextShort.size() == 0 ) {
		std::cout << "This set of test parameters generated zero-length test strings, skipping string cases" << std::endl;
	} else {
		vector<shared_ptr<Ciphertext<Element>>> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort, true);
		BytePlaintextEncoding plaintextShortNew;
		cc->Decrypt(kp.secretKey, ciphertext, &plaintextShortNew, true);
		EXPECT_EQ(plaintextShortNew, plaintextShort) << "Encrypt short plaintext with padding";

		vector<shared_ptr<Ciphertext<Element>>> ciphertext2 = cc->Encrypt(kp.publicKey, plaintextFull, false);
		BytePlaintextEncoding plaintextFullNew;
		cc->Decrypt(kp.secretKey, ciphertext2, &plaintextFullNew, false);
		EXPECT_EQ(plaintextFullNew, plaintextFull) << "Encrypt regular plaintext";

		vector<shared_ptr<Ciphertext<Element>>> ciphertext3 = cc->Encrypt(kp.publicKey, plaintextLong, false);
		BytePlaintextEncoding plaintextLongNew;
		cc->Decrypt(kp.secretKey, ciphertext3, &plaintextLongNew, false);
		EXPECT_EQ(plaintextLongNew, plaintextLong) << "Encrypt long plaintext";
	}

	vector<shared_ptr<Ciphertext<Element>>> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt, false);
	IntPlaintextEncoding plaintextIntNew;
	cc->Decrypt(kp.secretKey, ciphertext4, &plaintextIntNew, false);
	EXPECT_EQ(plaintextIntNew, plaintextInt) << "Encrypt integer plaintext";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext5 = cc->Encrypt(kp.publicKey, plaintextSInt, false);
	SignedIntPlaintextEncoding plaintextSIntNew;
	cc->Decrypt(kp.secretKey, ciphertext5, &plaintextSIntNew, false);
	EXPECT_EQ(plaintextSIntNew, plaintextSInt) << "Encrypt signed integer plaintext";
}

TEST(UTENCRYPT, LTV_Poly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(4096, 2, 20);
	UnitTestEncryption<Poly>(cc);
}

TEST(UTENCRYPT, LTV_DCRTPoly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayLTV(4096, 3, 2, 20);
	UnitTestEncryption<DCRTPoly>(cc);
}

TEST(UTENCRYPT, StSt_Poly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("StSt6");
	UnitTestEncryption<Poly>(cc);
}

TEST(UTENCRYPT, StSt_DCRTPoly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("StSt6", 3, 20);
	UnitTestEncryption<DCRTPoly>(cc);
}

TEST(UTENCRYPT, BV_Poly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("BV2");
	UnitTestEncryption<Poly>(cc);
}

TEST(UTENCRYPT, BV_DCRTPoly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("BV2", 3, 20);
	UnitTestEncryption<DCRTPoly>(cc);
}

TEST(UTENCRYPT, Null_Poly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("Null");
	UnitTestEncryption<Poly>(cc);
}

TEST(UTENCRYPT, Null_DCRTPoly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("Null", 3, 20);
	UnitTestEncryption<DCRTPoly>(cc);
}

TEST(UTENCRYPT, FV_Poly_Encrypt_Decrypt) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("FV2");
	UnitTestEncryption<Poly>(cc);
}

//TEST(UTENCRYPT, FV_DCRTPoly_Encrypt_Decrypt) {
//	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("FV2", 3, 20);
//	UnitTestEncryption<DCRTPoly>(cc);
//}
