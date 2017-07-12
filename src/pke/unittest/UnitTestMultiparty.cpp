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

class UTMultiparty : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

// NOTE the PRE tests are all based on these
//static const usint ORDER = 2048;
//static const usint PTM = 256;
//static const usint TOWERS = 3;

template <class Element>
void
UnitTestMultiparty(shared_ptr<CryptoContext<Element>> cc, bool publicVersion) {
	
	// Initialize Public Key Containers
	LPKeyPair<Poly> kp1;
	LPKeyPair<Poly> kp2;
	LPKeyPair<Poly> kp3;

	LPKeyPair<Poly> kpMultiparty;

	shared_ptr<LPEvalKey<Poly>> evalKey1;
	shared_ptr<LPEvalKey<Poly>> evalKey2;
	shared_ptr<LPEvalKey<Poly>> evalKey3;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	kp1 = cc->KeyGen();
	kp2 = cc->MultipartyKeyGen(kp1.publicKey);
	kp3 = cc->MultipartyKeyGen(kp1.publicKey);

	if( !kp1.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}
	if( !kp2.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}
	if( !kp3.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	vector<shared_ptr<LPPrivateKey<Poly>>> secretKeys;
	secretKeys.push_back(kp1.secretKey);
	secretKeys.push_back(kp2.secretKey);
	secretKeys.push_back(kp3.secretKey);

	kpMultiparty = cc->MultipartyKeyGen(secretKeys);	// This is the same core key generation operation.

	if( !kpMultiparty.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	evalKey1 = cc->ReKeyGen(kpMultiparty.secretKey, kp1.secretKey);
	evalKey2 = cc->ReKeyGen(kpMultiparty.secretKey, kp2.secretKey);
	evalKey3 = cc->ReKeyGen(kpMultiparty.secretKey, kp3.secretKey);

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	


	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////
/*
	std::vector<uint32_t> vectorOfInts1 = {2,2,2,2,2,2,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts2 = {3,3,3,3,3,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {1,1,1,1,0,0,0,0,0,0,0,0};
*/
	std::vector<uint32_t> vectorOfInts1 = {1,1,1,1,1,1,1,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts2 = {1,0,0,1,1,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {1,1,1,1,0,0,0,0,0,0,0,0};
	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);
	IntPlaintextEncoding plaintext3(vectorOfInts3);

	//std::vector<uint32_t> vectorOfIntsAdd = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3 };
	//IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext3;

	ciphertext1 = cc->Encrypt(kp1.publicKey, plaintext1, true);
	ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2, true);
	ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3, true);
	
	////////////////////////////////////////////////////////////
	// Re-Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1New;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2New;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext3New;

	ciphertext1New = cc->ReEncrypt(evalKey1, ciphertext1);
	ciphertext2New = cc->ReEncrypt(evalKey2, ciphertext2);
	ciphertext3New = cc->ReEncrypt(evalKey3, ciphertext3);

	////////////////////////////////////////////////////////////
	// EvalAdd Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextAddNew12;
	shared_ptr<Ciphertext<Poly>> ciphertextAddNew123;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextAddVectNew;

	ciphertextAddNew12 = cc->EvalAdd(ciphertext1New[0],ciphertext2New[0]);
	ciphertextAddNew123 = cc->EvalAdd(ciphertextAddNew12,ciphertext3New[0]);

	ciphertextAddVectNew.push_back(ciphertextAddNew123);

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAddNew;

	cc->Decrypt(kpMultiparty.secretKey, ciphertextAddVectNew, &plaintextAddNew, true);

	//std::cin.get();

	plaintextAddNew.resize(plaintext1.size());

//	cout << "\n Resulting Added Plaintext with Re-Encryption: \n";
//	cout << plaintextAddNew << endl;

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data with Multiparty
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAddNew1;
	IntPlaintextEncoding plaintextAddNew2;
	IntPlaintextEncoding plaintextAddNew3;

	Poly partialPlaintext1;
	Poly partialPlaintext2;
	Poly partialPlaintext3;
	//IntPlaintextEncoding plaintextAddNewFinal;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextPartial1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextPartial2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextPartial3;

	IntPlaintextEncoding plaintextMultipartyNew;

	const shared_ptr<LPCryptoParameters<Poly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
	const shared_ptr<typename Poly::Params> elementParams = cryptoParams->GetElementParams();

	ciphertextPartial1 = cc->MultipartyDecryptLead(kp1.secretKey, ciphertextAddVectNew);
	ciphertextPartial2 = cc->MultipartyDecryptMain(kp2.secretKey, ciphertextAddVectNew);
	ciphertextPartial3 = cc->MultipartyDecryptMain(kp3.secretKey, ciphertextAddVectNew);

	vector<vector<shared_ptr<Ciphertext<Poly>>>> partialCiphertextVec;
	partialCiphertextVec.push_back(ciphertextPartial1);
	partialCiphertextVec.push_back(ciphertextPartial2);
	partialCiphertextVec.push_back(ciphertextPartial3);

	cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew, true);

	plaintextMultipartyNew.resize(plaintext1.size());

//	cout << "\n Resulting Fused Plaintext with Re-Encryption: \n";
//	cout << plaintextMultipartyNew << endl;

	EXPECT_EQ(plaintextAddNew, plaintextMultipartyNew) << "Multiparty integer plaintext";
}

//TEST(UTMultiparty, LTV_Poly_Multiparty_pub) {
//	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(ORDER, PTM);
//	UnitTestMultiparty<Poly>(cc, true);
//}
//
//TEST(UTMultiparty, LTV_DCRTPoly_Multiparty_pub) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayLTV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<DCRTPoly>(cc, true);
//}

//TEST(UTMultiparty, StSt_Poly_Multiparty_pub) {
//	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementStSt(ORDER, PTM);
//	UnitTestMultiparty<Poly>(cc, true);
//}
//
//TEST(UTMultiparty, StSt_DCRTPoly_Multiparty_pub) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayStSt(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<DCRTPoly>(cc, true);
//}

//TEST(UTMultiparty, Null_Poly_Multiparty_pri) {
//	string input = "NULL";
	//shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	//cc->Enable(ENCRYPTION);
	//cc->Enable(SHE);
	//cc->Enable(PRE);
	//cc->Enable(MULTIPARTY);
	//UnitTestMultiparty<Poly>(cc, true);
//}

//TEST(UTMultiparty, Null_DCRTPoly_Multiparty_pri) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayNull(ORDER, TOWERS, PTM, 30);
//	UnitTestMultiparty<DCRTPoly>(cc, true);
//}

//TEST(UTMultiparty, BV_Poly_Multiparty_pri) {
//	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementBV(ORDER, PTM);
//	UnitTestMultiparty<Poly>(cc, false);
//}

//TEST(UTMultiparty, BV_DCRTPoly_Multiparty_pri) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayBV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<DCRTPoly>(cc, false);
//}

TEST(UTMultiparty, FV1_Poly_Multiparty_pri) {
	string input = "FV1";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST(UTMultiparty, FV2_Poly_Multiparty_pri) {
	string input = "FV2";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST(UTMultiparty, BV1_Poly_Multiparty_pri) {
	string input = "BV1";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST(UTMultiparty, BV2_Poly_Multiparty_pri) {
	string input = "BV2";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST(UTMultiparty, BV3_Poly_Multiparty_pri) {
	string input = "BV3";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST(UTMultiparty, BV4_Poly_Multiparty_pri) {
	string input = "BV4";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST(UTMultiparty, BV5_Poly_Multiparty_pri) {
	string input = "BV5";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST(UTMultiparty, Null_Poly_Multiparty_pri) {
	string input = "Null";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

TEST(UTMultiparty, Null2_Poly_Multiparty_pri) {
	string input = "Null2";
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);
	UnitTestMultiparty<Poly>(cc, true);
}

//TEST(UTMultiparty, FV_DCRTPoly_Multiparty_pri) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayFV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<DCRTPoly>(cc, false);
//}
