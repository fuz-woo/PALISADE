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
#include <fstream>

#include "../lib/cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestBFV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

//Tests EvalMult w/o keyswitching and EvalMultMany for BFV in the OPTIMIZED mode
TEST(UTBFVEVALMM, Poly_BFV_Eval_Mult_Many_Operations) {

	int relWindow = 1;
	int plaintextModulus = 256;
	double sigma = 4;
	double rootHermiteFactor = 1.03;

	//Set Crypto Parameters
	CryptoContext<Poly> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextBFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 3, 0, OPTIMIZED, 4);

	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<Poly> keyPair;
	keyPair = cryptoContext->KeyGen();

	ASSERT_TRUE(keyPair.good()) << "Key generation failed!";

	//Create evaluation key vector to be used in keyswitching
	cryptoContext->EvalMultKeysGen(keyPair.secretKey);

	////////////////////////////////////////////////////////////
	//Plaintext
	////////////////////////////////////////////////////////////

	std::vector<int64_t> vectorOfInts1 = {5,4,3,2,1,0,5,4,3,2,1,0};
	std::vector<int64_t> vectorOfInts2 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts3 = {3,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts4 = {4,0,0,0,0,0,0,0,0,0,0,0};

	std::vector<int64_t> vectorOfInts5 = {10,8,6,4,2,0,10,8,6,4,2,0};
	std::vector<int64_t> vectorOfInts6 = {30,24,18,12,6,0,30,24,18,12,6,0};
	std::vector<int64_t> vectorOfInts7 = {120,96,72,48,24,0,120,96,72,48,24,0};

	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
	Plaintext plaintext3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);
	Plaintext plaintext4 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts4);

	Plaintext plaintextResult1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts5);
	Plaintext plaintextResult2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts6);
	Plaintext plaintextResult3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts7);

	Ciphertext<Poly> ciphertext1;
	Ciphertext<Poly> ciphertext2;
	Ciphertext<Poly> ciphertext3;
	Ciphertext<Poly> ciphertext4;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
	ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
	ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4);

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	Ciphertext<Poly> ciphertextMul12;
	Ciphertext<Poly> ciphertextMul123;
	Ciphertext<Poly> ciphertextMul1234;

	Ciphertext<Poly> ciphertextMulVect3;
	Ciphertext<Poly> ciphertextMulVect4;
	Ciphertext<Poly> ciphertextMulVect5;

	//Perform consecutive multiplications and do a keyswtiching at the end.
	ciphertextMul12     = cryptoContext->EvalMultNoRelin(ciphertext1,ciphertext2);
	ciphertextMul123    = cryptoContext->EvalMultNoRelin(ciphertextMul12, ciphertext3);
	ciphertextMul1234   = cryptoContext->EvalMultAndRelinearize(ciphertextMul123, ciphertext4);

	////////////////////////////////////////////////////////////
	//Decryption of multiplicative results with and without keyswtiching (depends on the level)
	////////////////////////////////////////////////////////////

	Plaintext plaintextMul1;
	Plaintext plaintextMul2;
	Plaintext plaintextMul3;

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMul1);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul123, &plaintextMul2);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul1234, &plaintextMul3);

	////////////////////////////////////////////////////////////
	//Prepare EvalMultMany
	////////////////////////////////////////////////////////////

	Ciphertext<Poly> ciphertextMul12345;
	vector<Ciphertext<Poly>> cipherTextList;

	cipherTextList.push_back(ciphertext1);
	cipherTextList.push_back(ciphertext2);
	cipherTextList.push_back(ciphertext3);
	cipherTextList.push_back(ciphertext4);

	////////////////////////////////////////////////////////////
	//Compute EvalMultMany
	////////////////////////////////////////////////////////////

	ciphertextMul12345 = cryptoContext->EvalMultMany(cipherTextList);

	////////////////////////////////////////////////////////////
	//Decrypt EvalMultMany
	////////////////////////////////////////////////////////////

	Plaintext plaintextMulMany;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12345, &plaintextMulMany);

	plaintextResult1->SetLength( plaintextMul1->GetLength() );
	plaintextResult2->SetLength( plaintextMul2->GetLength() );
	plaintextResult3->SetLength( plaintextMul3->GetLength() );

	EXPECT_EQ(*plaintextMul1, *plaintextResult1) << "BFV.EvalMult gives incorrect results.\n";
	EXPECT_EQ(*plaintextMul2, *plaintextResult2) << "BFV.EvalMult gives incorrect results.\n";
	EXPECT_EQ(*plaintextMul3, *plaintextResult3) << "BFV.EvalMultAndRelinearize gives incorrect results.\n";
	EXPECT_EQ(*plaintextMulMany, *plaintextResult3) << "BFV.EvalMultMany gives incorrect results.\n";

}

//Tests EvalMult w/o keyswitching and EvalMultMany for BFVrns in the OPTIMIZED mode
TEST(UTBFVrnsEVALMM, Poly_BFVrns_Eval_Mult_Many_Operations) {

	int plaintextModulus = 256;
	double sigma = 4;
	double rootHermiteFactor = 1.03;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			plaintextModulus, rootHermiteFactor, sigma, 0, 3, 0, OPTIMIZED,4);

	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<DCRTPoly> keyPair;
	keyPair = cryptoContext->KeyGen();

	ASSERT_TRUE(keyPair.good()) << "Key generation failed!";

	//Create evaluation key vector to be used in keyswitching
	cryptoContext->EvalMultKeysGen(keyPair.secretKey);

	////////////////////////////////////////////////////////////
	//Plaintext
	////////////////////////////////////////////////////////////

	std::vector<int64_t> vectorOfInts1 = {5,4,3,2,1,0,5,4,3,2,1,0};
	std::vector<int64_t> vectorOfInts2 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts3 = {3,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts4 = {4,0,0,0,0,0,0,0,0,0,0,0};

	std::vector<int64_t> vectorOfInts5 = {10,8,6,4,2,0,10,8,6,4,2,0};
	std::vector<int64_t> vectorOfInts6 = {30,24,18,12,6,0,30,24,18,12,6,0};
	std::vector<int64_t> vectorOfInts7 = {120,96,72,48,24,0,120,96,72,48,24,0};

	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
	Plaintext plaintext3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);
	Plaintext plaintext4 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts4);

	Plaintext plaintextResult1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts5);
	Plaintext plaintextResult2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts6);
	Plaintext plaintextResult3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts7);

	Ciphertext<DCRTPoly> ciphertext1;
	Ciphertext<DCRTPoly> ciphertext2;
	Ciphertext<DCRTPoly> ciphertext3;
	Ciphertext<DCRTPoly> ciphertext4;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
	ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
	ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4);

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	Ciphertext<DCRTPoly> ciphertextMul12;
	Ciphertext<DCRTPoly> ciphertextMul123;
	Ciphertext<DCRTPoly> ciphertextMul1234;

	Ciphertext<DCRTPoly> ciphertextMulVect3;
	Ciphertext<DCRTPoly> ciphertextMulVect4;
	Ciphertext<DCRTPoly> ciphertextMulVect5;

	//Perform consecutive multiplications and do a keyswtiching at the end.
	ciphertextMul12     = cryptoContext->EvalMultNoRelin(ciphertext1,ciphertext2);
	ciphertextMul123    = cryptoContext->EvalMultNoRelin(ciphertextMul12, ciphertext3);
	ciphertextMul1234   = cryptoContext->EvalMultAndRelinearize(ciphertextMul123, ciphertext4);

	////////////////////////////////////////////////////////////
	//Decryption of multiplicative results with and without keyswtiching (depends on the level)
	////////////////////////////////////////////////////////////

	Plaintext plaintextMul1;
	Plaintext plaintextMul2;
	Plaintext plaintextMul3;

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMul1);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul123, &plaintextMul2);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul1234, &plaintextMul3);

	////////////////////////////////////////////////////////////
	//Prepare EvalMultMany
	////////////////////////////////////////////////////////////

	Ciphertext<DCRTPoly> ciphertextMul12345;
	vector<Ciphertext<DCRTPoly>> cipherTextList;

	cipherTextList.push_back(ciphertext1);
	cipherTextList.push_back(ciphertext2);
	cipherTextList.push_back(ciphertext3);
	cipherTextList.push_back(ciphertext4);

	////////////////////////////////////////////////////////////
	//Compute EvalMultMany
	////////////////////////////////////////////////////////////

	ciphertextMul12345 = cryptoContext->EvalMultMany(cipherTextList);

	////////////////////////////////////////////////////////////
	//Decrypt EvalMultMany
	////////////////////////////////////////////////////////////

	Plaintext plaintextMulMany;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12345, &plaintextMulMany);

	plaintextResult1->SetLength( plaintextMul1->GetLength() );
	plaintextResult2->SetLength( plaintextMul2->GetLength() );
	plaintextResult3->SetLength( plaintextMul3->GetLength() );

	EXPECT_EQ(*plaintextMul1, *plaintextResult1) << "BFVrns.EvalMult gives incorrect results.\n";
	EXPECT_EQ(*plaintextMul2, *plaintextResult2) << "BFVrns.EvalMult gives incorrect results.\n";
	EXPECT_EQ(*plaintextMul3, *plaintextResult3) << "BFVrns.EvalMultAndRelinearize gives incorrect results.\n";
	EXPECT_EQ(*plaintextMulMany, *plaintextResult3) << "BFVrns.EvalMultMany gives incorrect results.\n";

}

