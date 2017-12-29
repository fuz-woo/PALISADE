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
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

class UTMultiparty : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

// NOTE the PRE tests are all based on these
//static const usint ORDER = 2048;
//static const usint PTM = 256;
//static const usint TOWERS = 3;

template <class Element>
void UnitTestMultiparty(CryptoContext<Element> cc, bool publicVersion) {
	
	// Initialize Public Key Containers
	LPKeyPair<Element> kp1;
	LPKeyPair<Element> kp2;
	LPKeyPair<Element> kp3;

	LPKeyPair<Element> kpMultiparty;

	LPEvalKey<Element> evalKey1;
	LPEvalKey<Element> evalKey2;
	LPEvalKey<Element> evalKey3;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	kp1 = cc->KeyGen();
	kp2 = cc->MultipartyKeyGen(kp1.publicKey,false,true);
	kp3 = cc->MultipartyKeyGen(kp1.publicKey,false,true);

	ASSERT_TRUE(kp1.good()) << "Key generation failed!";
	ASSERT_TRUE(kp2.good()) << "Key generation failed!";
	ASSERT_TRUE(kp3.good()) << "Key generation failed!";

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	vector<LPPrivateKey<Element>> secretKeys;
	secretKeys.push_back(kp1.secretKey);
	secretKeys.push_back(kp2.secretKey);
	secretKeys.push_back(kp3.secretKey);

	kpMultiparty = cc->MultipartyKeyGen(secretKeys);	// This is the same core key generation operation.

	ASSERT_TRUE(kpMultiparty.good()) << "Key generation failed!";

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	evalKey1 = cc->ReKeyGen(kpMultiparty.secretKey, kp1.secretKey);
	evalKey2 = cc->ReKeyGen(kpMultiparty.secretKey, kp2.secretKey);
	evalKey3 = cc->ReKeyGen(kpMultiparty.secretKey, kp3.secretKey);

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////
	std::vector<int64_t> vectorOfInts1 = {1,1,1,1,1,1,1,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts2 = {1,0,0,1,1,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts3 = {1,1,1,1,0,0,0,0,0,0,0,0};
	Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
	Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);
	Plaintext plaintext3 = cc->MakeCoefPackedPlaintext(vectorOfInts3);

	std::vector<int64_t> vectorOfIntsSum(vectorOfInts1.size());

	int64_t half(cc->GetCryptoParameters()->GetPlaintextModulus()>>1);

	for (size_t i=0; i<vectorOfInts1.size(); i++){
		int64_t value = (vectorOfInts1[i] + vectorOfInts2[i]+ vectorOfInts3[i])%cc->GetCryptoParameters()->GetPlaintextModulus();
		if (value > half)
			value = value - cc->GetCryptoParameters()->GetPlaintextModulus();
		vectorOfIntsSum[i] = value;
	}

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	Ciphertext<Element> ciphertext1;
	Ciphertext<Element> ciphertext2;
	Ciphertext<Element> ciphertext3;

	ciphertext1 = cc->Encrypt(kp1.publicKey, plaintext1);
	ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
	ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);
	
	////////////////////////////////////////////////////////////
	// Re-Encryption
	////////////////////////////////////////////////////////////

	Ciphertext<Element> ciphertext1New;
	Ciphertext<Element> ciphertext2New;
	Ciphertext<Element> ciphertext3New;

	ciphertext1New = cc->ReEncrypt(evalKey1, ciphertext1);
	ciphertext2New = cc->ReEncrypt(evalKey2, ciphertext2);
	ciphertext3New = cc->ReEncrypt(evalKey3, ciphertext3);

	////////////////////////////////////////////////////////////
	// EvalAdd Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	Ciphertext<Element> ciphertextAddNew12;
	Ciphertext<Element> ciphertextAddNew;

	ciphertextAddNew12 = cc->EvalAdd(ciphertext1New,ciphertext2New);
	ciphertextAddNew = cc->EvalAdd(ciphertextAddNew12,ciphertext3New);

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	Plaintext plaintextAddNew;

	cc->Decrypt(kpMultiparty.secretKey, ciphertextAddNew, &plaintextAddNew);

	plaintextAddNew->SetLength(plaintext1->GetLength());

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data with Multiparty
	////////////////////////////////////////////////////////////

	Plaintext plaintextAddNew1;
	Plaintext plaintextAddNew2;
	Plaintext plaintextAddNew3;

	Element partialPlaintext1;
	Element partialPlaintext2;
	Element partialPlaintext3;

	Plaintext plaintextMultipartyNew;

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = kp1.secretKey->GetCryptoParameters();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	auto ciphertextPartial1 = cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAddNew});
	auto ciphertextPartial2 = cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAddNew});
	auto ciphertextPartial3 = cc->MultipartyDecryptMain(kp3.secretKey, {ciphertextAddNew});

	vector<Ciphertext<Element>> partialCiphertextVec;
	partialCiphertextVec.push_back(ciphertextPartial1[0]);
	partialCiphertextVec.push_back(ciphertextPartial2[0]);
	partialCiphertextVec.push_back(ciphertextPartial3[0]);

	cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

	plaintextMultipartyNew->SetLength(plaintext1->GetLength());

	EXPECT_EQ(vectorOfIntsSum, plaintextMultipartyNew->GetCoefPackedValue()) << "Multiparty: Does not match plaintext addition.";
	EXPECT_EQ(plaintextAddNew->GetCoefPackedValue(), plaintextMultipartyNew->GetCoefPackedValue()) << "Multiparty: Does not match the results of direction encryption.";
}

//TEST_F(UTMultiparty, LTV_Poly_Multiparty_pub) {
//	CryptoContext<Poly> cc = GenCryptoContextElementLTV(ORDER, PTM);
//	UnitTestMultiparty<Poly>(cc, true);
//}
//
//TEST_F(UTMultiparty, LTV_DCRTPoly_Multiparty_pub) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayLTV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<DCRTPoly>(cc, true);
//}

//TEST_F(UTMultiparty, StSt_Poly_Multiparty_pub) {
//	CryptoContext<Poly> cc = GenCryptoContextElementStSt(ORDER, PTM);
//	UnitTestMultiparty<Poly>(cc, true);
//}
//
//TEST_F(UTMultiparty, StSt_DCRTPoly_Multiparty_pub) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayStSt(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<DCRTPoly>(cc, true);
//}

//TEST_F(UTMultiparty, Null_Poly_Multiparty_pri) {
//	string input = "NULL";
	//CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	//cc->Enable(ENCRYPTION);
	//cc->Enable(SHE);
	//cc->Enable(PRE);
	//cc->Enable(MULTIPARTY);
	//UnitTestMultiparty<Poly>(cc, true);
//}

//TEST_F(UTMultiparty, Null_DCRTPoly_Multiparty_pri) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayNull(ORDER, TOWERS, PTM, 30);
//	UnitTestMultiparty<DCRTPoly>(cc, true);
//}

//TEST_F(UTMultiparty, BGV_Poly_Multiparty_pri) {
//	CryptoContext<Poly> cc = GenCryptoContextElementBGV(ORDER, PTM);
//	UnitTestMultiparty<Poly>(cc, false);
//}

//TEST_F(UTMultiparty, BGV_DCRTPoly_Multiparty_pri) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayBGV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<DCRTPoly>(cc, false);
//}

TEST_F(UTMultiparty, BFV1_Poly_Multiparty_pri) {
	string input = "BFV1";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST_F(UTMultiparty, BFV2_Poly_Multiparty_pri) {
	string input = "BFV2";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST_F(UTMultiparty, BFVrns_RLWE_DCRTPoly_Multiparty_pri) {
	CryptoContext<DCRTPoly> cc = GenCryptoContextBFVrns<DCRTPoly>(4, RLWE);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<DCRTPoly>(cc, true);
}

TEST_F(UTMultiparty, BFVrns2_OPTIMIZED_DCRTPoly_Multiparty_pri) {
	CryptoContext<DCRTPoly> cc = GenCryptoContextBFVrns<DCRTPoly>(16, OPTIMIZED);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<DCRTPoly>(cc, true);
}

TEST_F(UTMultiparty, BGV1_Poly_Multiparty_pri) {
	string input = "BGV1";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST_F(UTMultiparty, BGV2_Poly_Multiparty_pri) {
	string input = "BGV2";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST_F(UTMultiparty, BGV3_Poly_Multiparty_pri) {
	string input = "BGV3";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST_F(UTMultiparty, BGV4_Poly_Multiparty_pri) {
	string input = "BGV4";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST_F(UTMultiparty, BGV5_Poly_Multiparty_pri) {
	string input = "BGV5";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST_F(UTMultiparty, Null_Poly_Multiparty_pri) {
	string input = "Null";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST_F(UTMultiparty, Null2_Poly_Multiparty_pri) {
	string input = "Null2";
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

//TEST_F(UTMultiparty, BFV_DCRTPoly_Multiparty_pri) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayBFV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<DCRTPoly>(cc, false);
//}
