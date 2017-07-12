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

#include "palisade.h"
#include "cryptocontext.h"
#include "math/nbtheory.h"
#include "utils/utilities.h"
#include "utils/parmfactory.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;


class UnitTestPkeSerialize : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

static shared_ptr<CryptoContext<Poly>> GenerateTestCryptoContext(const string& parmsetName) {
	BigInteger modulusP(256);
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(parmsetName);
	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP,PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP),8));
	cc->GetCryptoParameters()->SetEncodingParams(encodingParams);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

static shared_ptr<CryptoContext<DCRTPoly>> GenerateTestDCRTCryptoContext(const string& parmsetName, usint nTower, usint pbits) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextHelper::getNewDCRTContext(parmsetName, nTower, pbits);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

template<typename T>
void UnitTestContext(shared_ptr<CryptoContext<T>> cc) {

	LPKeyPair<T> kp = cc->KeyGen();
	try {
		cc->EvalMultKeyGen(kp.secretKey);
	} catch(...) {}
	try {
		cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);
	} catch(...) {}

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( cc->Serialize(&ser) ) << "Serialization failed";

	shared_ptr<CryptoContext<T>> newcc = CryptoContextFactory<T>::DeserializeAndCreateContext(ser);
	ASSERT_TRUE( newcc ) << "Deserialization failed";

	EXPECT_EQ( cc->GetEncryptionAlgorithm()->GetEnabled(), (usint)(ENCRYPTION|SHE) ) << "Enabled features mismatch after ser/deser";

	EXPECT_EQ( *cc->GetCryptoParameters(), *newcc->GetCryptoParameters() ) << "Mismatch after ser/deser";

	Serialized serK;
	ASSERT_TRUE( kp.publicKey->Serialize(&serK) ) << "Key serialization failed";
	shared_ptr<LPPublicKey<T>> newPub = cc->deserializePublicKey(serK);
	ASSERT_TRUE( newPub ) << "Key deserialize failed";

	EXPECT_EQ( *kp.publicKey, *newPub ) << "Key mismatch";

	shared_ptr<CryptoContext<T>> newccFromkey = CryptoContextFactory<T>::DeserializeAndCreateContext(serK);
	ASSERT_TRUE( newccFromkey ) << "Deserialization from key failed";

	shared_ptr<LPPublicKey<T>> finalPub = newccFromkey->deserializePublicKey(serK);
	ASSERT_TRUE( finalPub ) << "Key deserialize in new ctx failed";
	EXPECT_EQ( *newPub, *finalPub ) << "Key mismatch from new ctx";
}

TEST(UTPKESer, LTV_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("LTV5");
	UnitTestContext<Poly>(cc);
}

TEST(UTPKESer, LTV_DCRTPoly_Serial) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("LTV5", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST(UTPKESer, StSt_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("StSt6");
	UnitTestContext<Poly>(cc);
}

TEST(UTPKESer, StSt_DCRTPoly_Serial) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("StSt6", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST(UTPKESer, BV_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("BV2");
	UnitTestContext<Poly>(cc);
}

TEST(UTPKESer, BV_DCRTPoly_Serial) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("BV2", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST(UTPKESer, Null_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("Null");
	UnitTestContext<Poly>(cc);
}

TEST(UTPKESer, Null_DCRTPoly_Serial) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("Null", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST(UTPKESer, FV_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("FV2");
	UnitTestContext<Poly>(cc);
}

//TEST(UTPKESer, FV_DCRTPoly_Serial) {
//	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("FV2", 3, 20);
//	UnitTestContext<DCRTPoly>(cc);
//}

// REMAINDER OF THE TESTS USE LTV AS A REPRESENTITIVE CONTEXT
TEST(UTPKESer, LTV_keys_and_ciphertext) {
        bool dbg_flag = false;
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("LTV5");
	LPKeyPair<Poly> kp = cc->KeyGen();
	LPKeyPair<Poly> kpnew;

	DEBUG("step 1");
	{
		Serialized ser;

		ser.SetObject();

		DEBUG("step 1.1");
		ASSERT_TRUE( kp.publicKey->Serialize(&ser) ) << "Public Key serialization failed";

		DEBUG("step 1.2");
		ASSERT_TRUE( (kpnew.publicKey = cc->deserializePublicKey(ser)) ) << "Public key deserialization failed";
		DEBUG("step 1.3");
		EXPECT_EQ( *kp.publicKey, *kpnew.publicKey ) << "Public key mismatch after ser/deser";
	}
	DEBUG("step 2");
	{
		Serialized ser;
		ser.SetObject();
		ASSERT_TRUE( kp.secretKey->Serialize(&ser) ) << "Secret Key serialization failed";

		ASSERT_TRUE( (kpnew.secretKey = cc->deserializeSecretKey(ser)) ) << "Secret key deserialization failed";

		EXPECT_EQ( *kp.secretKey, *kpnew.secretKey ) << "Secret key mismatch after ser/deser";
	}
	DEBUG("step 3");
	BytePlaintextEncoding plaintextShort("This is just a little test");
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort, true);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( ciphertext[0]->Serialize(&ser) ) << "Ciphertext serialize failed";
	DEBUG("step 4");
	shared_ptr<Ciphertext<Poly>> newC;
	ASSERT_TRUE( (newC = cc->deserializeCiphertext(ser)) ) << "Ciphertext deserialization failed";

	EXPECT_EQ( *ciphertext[0], *newC ) << "Ciphertext mismatch";

	DEBUG("step 5");
	ciphertext[0] = newC;
	BytePlaintextEncoding plaintextShortNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextShortNew, true);
	EXPECT_EQ(plaintextShortNew, plaintextShort) << "Decrypted deserialize failed";
}
