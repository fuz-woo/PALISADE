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


class UTPKESer : public ::testing::Test {
protected:
	void SetUp() {
	}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
		CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
		CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
	}
};

static CryptoContext<Poly> GenerateTestCryptoContext(const string& parmsetName) {
	PlaintextModulus modulusP(256);
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(parmsetName,
			EncodingParams(new EncodingParamsImpl(modulusP,8)));
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

static CryptoContext<DCRTPoly> GenerateTestDCRTCryptoContext(const string& parmsetName, usint nTower, usint pbits) {
	CryptoContext<DCRTPoly> cc = CryptoContextHelper::getNewDCRTContext(parmsetName, nTower, pbits);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

TEST_F(UTPKESer, LTV_Context_Factory) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("LTV5");
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 0) << "Contexts not cleared";

	cc = GenerateTestCryptoContext("LTV5");
	CryptoContext<Poly> cc2 = GenerateTestCryptoContext("LTV5");
	EXPECT_EQ(cc.get(), cc2.get()) << "Context mismatch";
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "Context count error";
}

template<typename T>
void UnitTestContext(CryptoContext<T> cc) {

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

	CryptoContext<T> newcc = CryptoContextFactory<T>::DeserializeAndCreateContext(ser);
	ASSERT_TRUE( newcc ) << "Deserialization failed";

	EXPECT_EQ( cc->GetEncryptionAlgorithm()->GetEnabled(), (usint)(ENCRYPTION|SHE) ) << "Enabled features mismatch after ser/deser";

	EXPECT_EQ( *cc->GetCryptoParameters(), *newcc->GetCryptoParameters() ) << "Mismatch after ser/deser";

	Serialized serK;
	ASSERT_TRUE( kp.publicKey->Serialize(&serK) ) << "Key serialization failed";
	LPPublicKey<T> newPub = cc->deserializePublicKey(serK);
	ASSERT_TRUE( newPub ) << "Key deserialize failed";

	EXPECT_EQ( *kp.publicKey, *newPub ) << "Key mismatch";

	CryptoContext<T> newccFromkey = CryptoContextFactory<T>::DeserializeAndCreateContext(serK);
	ASSERT_TRUE( newccFromkey ) << "Deserialization from key failed";

	LPPublicKey<T> finalPub = newccFromkey->deserializePublicKey(serK);
	ASSERT_TRUE( finalPub ) << "Key deserialize in new ctx failed";
	EXPECT_EQ( *newPub, *finalPub ) << "Key mismatch from new ctx";
}

TEST_F(UTPKESer, LTV_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("LTV5");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, LTV_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("LTV5", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, StSt_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("StSt6");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, StSt_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("StSt6", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, BGV_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("BGV2");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, BGV_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("BGV2", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, Null_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("Null");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, Null_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("Null", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, BFV_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("BFV2");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, BFVrns_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("BFVrns2", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

// REMAINDER OF THE TESTS USE BGV AS A REPRESENTITIVE CONTEXT
TEST_F(UTPKESer, Keys_and_ciphertext) {
        bool dbg_flag = false;

        // generate a context with encoding params
    	usint m = 22;
    	PlaintextModulus p = 2333;
    	BigInteger modulusP(p);
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

    	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 8, stdDev, OPTIMIZED);

    	cc->Enable(ENCRYPTION|SHE);

    	CryptoContext<Poly> cc2 = GenerateTestCryptoContext("LTV4");

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
	vector<int64_t> vals = { 1,3,5,7,9,2,4,6,8,11 };
	Plaintext plaintextShort = cc->MakeCoefPackedPlaintext( vals );
	Ciphertext<Poly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( ciphertext->Serialize(&ser) ) << "Ciphertext serialize failed";
	DEBUG("step 4");
	Ciphertext<Poly> newC;
	ASSERT_TRUE( (newC = cc->deserializeCiphertext(ser)) ) << "Ciphertext deserialization failed";

	EXPECT_EQ( *ciphertext, *newC ) << "Ciphertext mismatch";

	DEBUG("step 5");
	Plaintext plaintextShortNew;
	cc->Decrypt(kp.secretKey, newC, &plaintextShortNew);
	EXPECT_EQ(*plaintextShortNew, *plaintextShort) << "Decrypted deserialize failed";

	DEBUG("step 6");
	LPKeyPair<Poly> kp2 = cc->KeyGen();
	LPKeyPair<Poly> kp3 = cc2->KeyGen();

	cc->EvalMultKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp2.secretKey);
	cc2->EvalMultKeyGen(kp3.secretKey);

	// serialize a bunch of mult keys
	Serialized ser0;
	cc->SerializeEvalMultKey(&ser0, kp.secretKey->GetKeyTag());
	Serialized ser2a;
	Serialized ser2b;
	cc->SerializeEvalMultKey(&ser2a, cc);
	cc->SerializeEvalMultKey(&ser2b, cc2);
	Serialized ser3;
	cc->SerializeEvalMultKey(&ser3);

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalSumKeyGen(kp2.secretKey);
	//cc2->EvalSumKeyGen(kp3.secretKey); // LTV does not support it...

	// serialize a bunch of sum keys
	Serialized aser0;
	cc->SerializeEvalSumKey(&aser0, kp.secretKey->GetKeyTag());
	Serialized aser2a;
	Serialized aser2b;
	cc->SerializeEvalSumKey(&aser2a, cc);
	cc->SerializeEvalSumKey(&aser2b, cc2);
	Serialized aser3;
	cc->SerializeEvalSumKey(&aser3);

	// test mult deserialize
	cc->ClearEvalMultKeys();
	cc->ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	cc->DeserializeEvalMultKey(ser0);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-key deser, context";
	EXPECT_EQ(cc->GetAllEvalMultKeys().size(), 1U) << "one-key deser, keys";

	cc->ClearEvalMultKeys();
	cc->ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	cc->DeserializeEvalMultKey(ser2a);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser, context";
	EXPECT_EQ(cc->GetAllEvalMultKeys().size(), 2U) << "one-ctx deser, keys";

	cc->ClearEvalMultKeys();
	cc->ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	cc->DeserializeEvalMultKey(ser2b);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser2, context";
	EXPECT_EQ(cc->GetAllEvalMultKeys().size(), 1U) << "one-ctx deser2, keys";

	cc->ClearEvalMultKeys();
	cc->ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	cc->DeserializeEvalMultKey(ser3);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 2) << "all-key deser, context";
	EXPECT_EQ(cc->GetAllEvalMultKeys().size(), 3U) << "all-key deser, keys";

	// test sum deserialize
	cc->ClearEvalMultKeys();
	cc->ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	cc->DeserializeEvalSumKey(aser0);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-key deser, context";
	EXPECT_EQ(cc->GetAllEvalSumKeys().size(), 1U) << "one-key deser, keys";

	cc->ClearEvalMultKeys();
	cc->ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	cc->DeserializeEvalSumKey(aser2a);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser, context";
	EXPECT_EQ(cc->GetAllEvalSumKeys().size(), 2U) << "one-ctx deser, keys";

	cc->ClearEvalMultKeys();
	cc->ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	cc->DeserializeEvalSumKey(aser2b);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser2, context";
	EXPECT_EQ(cc->GetAllEvalSumKeys().size(), 0U) << "one-ctx deser2, keys";

	cc->ClearEvalMultKeys();
	cc->ClearEvalSumKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	cc->DeserializeEvalSumKey(aser3);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 2) << "all-key deser, context";
	EXPECT_EQ(cc->GetAllEvalSumKeys().size(), 2U) << "all-key deser, keys";

	// FIXME add tests to delete one context worth of keys, or a single key


}
