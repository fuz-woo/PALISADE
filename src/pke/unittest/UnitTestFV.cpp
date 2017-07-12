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

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

#include "cryptolayertests.h"

using namespace std;
using namespace lbcrypto;

class UnitTestBV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

//FIXME I think all of these operations are duplicated in other unit test files, so perhaps this entire file can be deleted

//Tests EvalAdd, EvalSub, and EvalMul operations for FV in the RLWE mode
TEST(UTFV, Poly_FV_Eval_Operations) {

	usint m = 2048;

	BigInteger modulus("1099511678977");
	BigInteger rootOfUnity("928976858506");

	BigInteger bigModulus("1237940039285380274899136513");
	BigInteger bigRootOfUnity("1067388930511360414468370668");

	BigInteger plaintextModulus("64");

	float stdDev = 4;

	shared_ptr<Poly::Params> parms( new Poly::Params(m, modulus, rootOfUnity) );

	//Set crypto parametes
	BigInteger delta(modulus.DividedBy(plaintextModulus));
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(parms,
			64, 1, stdDev, delta.ToString(), RLWE, bigModulus.ToString(),
			bigRootOfUnity.ToString(), 0, 9, 1.006);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp;

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 3,1,6,3,2,2,5,1 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	std::vector<uint32_t> vectorOfIntsSub = { 63,63,0,63,62,0,63,1 };
	IntPlaintextEncoding plaintextSub(vectorOfIntsSub);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1, true);
	ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2, true);

	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextAdd;

	shared_ptr<Ciphertext<Poly>> ciphertextTemp = cc->EvalAdd(ciphertext1[0], ciphertext2[0]);

	ciphertextAdd.push_back(ciphertextTemp);

	IntPlaintextEncoding plaintextNew;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	DecryptResult result = cc->Decrypt(kp.secretKey, ciphertextAdd, &plaintextNew, true);

	//this step is needed because there is no marker for padding in the case of IntPlaintextEncoding
	plaintextNew.resize(plaintextAdd.size());

	EXPECT_EQ(plaintextAdd, plaintextNew) << "FV.EvalAdd gives incorrect results.\n";

	////////////////////////////////////////////////////////////
	//EvalSub Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSub;

	shared_ptr<Ciphertext<Poly>> ciphertextTempSub = cc->EvalSub(ciphertext1[0], ciphertext2[0]);

	ciphertextSub.push_back(ciphertextTempSub);

	IntPlaintextEncoding plaintextNewSub;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	result = cc->Decrypt(kp.secretKey, ciphertextSub, &plaintextNewSub, true);

	plaintextNewSub.resize(plaintextSub.size());

	EXPECT_EQ(plaintextSub, plaintextNewSub) << "FV.EvalSub gives incorrect results.\n";


	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	cc->EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMult;

	shared_ptr<Ciphertext<Poly>> ciphertextTempMult = cc->EvalMult(ciphertext1[0], ciphertext2[0]);

	ciphertextMult.push_back(ciphertextTempMult);

	IntPlaintextEncoding plaintextNewMult;

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	result = cc->Decrypt(kp.secretKey, ciphertextMult, &plaintextNewMult, true);

	plaintextNewMult.resize(plaintextMult.size());

	EXPECT_EQ(plaintextMult, plaintextNewMult) << "FV.EvalMult gives incorrect results.\n";

}

// Generates parameters for FV in the RLWE mode to support a single EvalMult and then validates that single EvalMult works correctly
TEST(UTFV, Poly_FV_ParamsGen_EvalMul) {

	usint relWindow = 16;
	usint plaintextModulus = 4;
	float stdDev = 4;

	//Set crypto parametes
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(plaintextModulus, 1.006, relWindow, stdDev, 0, 2, 0, RLWE);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp;

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1, false);
	ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2, false);

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	cc->EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMult;

	shared_ptr<Ciphertext<Poly>> ciphertextTempMult = cc->EvalMult(ciphertext1[0], ciphertext2[0]);

	ciphertextMult.push_back(ciphertextTempMult);

	IntPlaintextEncoding plaintextNewMult;

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	cc->Decrypt(kp.secretKey, ciphertextMult, &plaintextNewMult, true);

	plaintextNewMult.resize(plaintextMult.size());

	EXPECT_EQ(plaintextMult, plaintextNewMult) << "FV.EvalMult gives incorrect results when parameters are generated on the fly by ParamsGen.\n";

}

//Tests ParamsGen, EvalAdd, EvalSub, and EvalMul operations for FV in the OPTIMIZED mode
TEST(UTFV, Poly_FV_Optimized_Eval_Operations) {

	usint relWindow = 16;
	usint plaintextModulus = 64;
	float stdDev = 4;

	//Set crypto parameters
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(plaintextModulus, 1.006, relWindow, stdDev, 0, 1, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp;

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 3,1,6,3,2,2,5,1 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	std::vector<uint32_t> vectorOfIntsSub = { 63,63,0,63,62,0,63,1 };
	IntPlaintextEncoding plaintextSub(vectorOfIntsSub);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1, false);
	ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2, false);

	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextAdd;

	shared_ptr<Ciphertext<Poly>> ciphertextTemp;

	//YSP this needs to be switched to the CryptoUtility operation
	ciphertextTemp = cc->EvalAdd(ciphertext1[0], ciphertext2[0]);

	ciphertextAdd.push_back(ciphertextTemp);

	IntPlaintextEncoding plaintextNew;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	DecryptResult result = cc->Decrypt(kp.secretKey, ciphertextAdd, &plaintextNew, true);

	plaintextNew.resize(plaintextAdd.size());

	EXPECT_EQ(plaintextAdd, plaintextNew) << "FVOptimized.EvalAdd gives incorrect results.\n";

	////////////////////////////////////////////////////////////
	//EvalSub Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSub;

	shared_ptr<Ciphertext<Poly>> ciphertextTempSub;

	ciphertextTempSub = cc->EvalSub(ciphertext1[0], ciphertext2[0]);

	ciphertextSub.push_back(ciphertextTempSub);

	IntPlaintextEncoding plaintextNewSub;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	result = cc->Decrypt(kp.secretKey, ciphertextSub, &plaintextNewSub, true);

	plaintextNewSub.resize(plaintextSub.size());

	EXPECT_EQ(plaintextSub, plaintextNewSub) << "FVOptimized.EvalSub gives incorrect results.\n";


	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	cc->EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMult;

	shared_ptr<Ciphertext<Poly>> ciphertextTempMult;

	ciphertextTempMult = cc->EvalMult(ciphertext1[0], ciphertext2[0]);

	ciphertextMult.push_back(ciphertextTempMult);

	IntPlaintextEncoding plaintextNewMult;

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	result = cc->Decrypt(kp.secretKey, ciphertextMult, &plaintextNewMult, true);

	plaintextNewMult.resize(plaintextMult.size());

	EXPECT_EQ(plaintextMult, plaintextNewMult) << "FVOptimized.EvalMult gives incorrect results.\n";

}
