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
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

class UnitTestPRE : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

// NOTE the PRE tests are all based on these
static const usint ORDER = 2048;
static const usint PTM = 256;
static const usint TOWERS = 3;

template <class Element>
void
UnitTestReEncrypt(shared_ptr<CryptoContext<Element>> cc, bool publicVersion) {
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;

	GenerateTestPlaintext(cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(),
			cc->GetCryptoParameters()->GetPlaintextModulus(),
			plaintextShort, plaintextFull, plaintextLong);

	size_t intSize = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
	auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	vector<uint32_t> intvec;
	for( size_t ii=0; ii<intSize; ii++)
		intvec.push_back( rand() % ptm );
	IntPlaintextEncoding plaintextInt(intvec);

	////////////////////////////////////////////////////////////
	//Perform the key generation operations
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<Element> newKp = cc->KeyGen();


	if (!newKp.good()) {
		std::cout << "Key generation 2 failed!" << std::endl;
		exit(1);
	}
	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	shared_ptr<LPEvalKey<Element>> evalKey;
	if( publicVersion )
		evalKey = cc->ReKeyGen(newKp.publicKey, kp.secretKey);
	else
		evalKey = cc->ReKeyGen(newKp.secretKey, kp.secretKey);


	vector<shared_ptr<Ciphertext<Element>>> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort, true);
	BytePlaintextEncoding plaintextShortNew;
	vector<shared_ptr<Ciphertext<Element>>> reCiphertext = cc->ReEncrypt(evalKey, ciphertext);
	DecryptResult result = cc->Decrypt(newKp.secretKey, reCiphertext, &plaintextShortNew, true);
	EXPECT_EQ(plaintextShortNew, plaintextShort) << "ReEncrypt short plaintext with padding";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext2 = cc->Encrypt(kp.publicKey, plaintextFull, false);
	BytePlaintextEncoding plaintextFullNew;
	vector<shared_ptr<Ciphertext<Element>>> reCiphertext2 = cc->ReEncrypt(evalKey, ciphertext2);
	result = cc->Decrypt(newKp.secretKey, reCiphertext2, &plaintextFullNew, false);
	EXPECT_EQ(plaintextFullNew, plaintextFull) << "ReEncrypt regular plaintext";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext3 = cc->Encrypt(kp.publicKey, plaintextLong, false);
	BytePlaintextEncoding plaintextLongNew;
	vector<shared_ptr<Ciphertext<Element>>> reCiphertext3 = cc->ReEncrypt(evalKey, ciphertext3);
	result = cc->Decrypt(newKp.secretKey, reCiphertext3, &plaintextLongNew, false);
	EXPECT_EQ(plaintextLongNew, plaintextLong) << "ReEncrypt long plaintext";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt, false);
	IntPlaintextEncoding plaintextIntNew;
	vector<shared_ptr<Ciphertext<Element>>> reCiphertext4 = cc->ReEncrypt(evalKey, ciphertext4);
	result = cc->Decrypt(newKp.secretKey, reCiphertext4, &plaintextIntNew, false);
	EXPECT_EQ(plaintextIntNew, plaintextInt) << "ReEncrypt integer plaintext";
}

TEST(UTPRE, LTV_Poly_ReEncrypt_pub) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(ORDER, PTM);
	UnitTestReEncrypt<Poly>(cc, true);
}

//TEST(UTPRE, LTV_DCRTPoly_ReEncrypt_pub) {
//	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayLTV(ORDER, TOWERS, PTM);
//	UnitTestReEncrypt<DCRTPoly>(cc, true);
//}

//TEST(UTPRE, StSt_Poly_ReEncrypt_pub) {
//	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementStSt(ORDER, PTM);
//	UnitTestReEncrypt<Poly>(cc, true);
//}
//
//TEST(UTPRE, StSt_DCRTPoly_ReEncrypt_pub) {
//	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayStSt(ORDER, TOWERS, PTM);
//	UnitTestReEncrypt<DCRTPoly>(cc, true);
//}

TEST(UTPRE, Null_Poly_ReEncrypt_pub) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementNull(ORDER, PTM);
	UnitTestReEncrypt<Poly>(cc, true);
}

TEST(UTPRE, Null_DCRTPoly_ReEncrypt_pub) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayNull(ORDER, TOWERS, PTM, 30);
	UnitTestReEncrypt<DCRTPoly>(cc, true);
}

TEST(UTPRE, BV_Poly_ReEncrypt_pri) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementBV(ORDER, PTM);
	UnitTestReEncrypt<Poly>(cc, false);
}

#if !defined(_MSC_VER)
TEST(UTPRE, BV_DCRTPoly_ReEncrypt_pri) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayBV(ORDER, TOWERS, PTM);
	UnitTestReEncrypt<DCRTPoly>(cc, false);
}
#endif

TEST(UTPRE, FV_Poly_ReEncrypt_pri) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementFV(ORDER, PTM);
	UnitTestReEncrypt<Poly>(cc, false);
}

//TEST(UTPRE, FV_DCRTPoly_ReEncrypt_pri) {
//	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayFV(ORDER, TOWERS, PTM);
//	UnitTestReEncrypt<DCRTPoly>(cc, false);
//}
