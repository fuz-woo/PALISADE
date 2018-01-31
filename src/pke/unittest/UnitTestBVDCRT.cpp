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

using namespace std;
using namespace lbcrypto;

class UTBGVDCRT : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

//FIXME this test might be redundant in other files; perhaps this entire file can go

#if !defined(_MSC_VER)
TEST_F(UTBGVDCRT, Poly_bgv_DCRT_MODREDUCE) {

	usint m = 8;

	usint numOfTower = 3;

	PlaintextModulus plaintextModulus = 8;

	float stdDev = 4;

	shared_ptr<ILDCRTParams<BigInteger>> params = GenerateDCRTParams<BigInteger>(m, numOfTower, 48);

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGV(params, plaintextModulus, m, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts1 = { 4,1,2,3 };

	Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
	Plaintext intArrayNew;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, intArray1);

	cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew);
	EXPECT_EQ(intArray1->GetCoefPackedValue(), intArrayNew->GetCoefPackedValue()) << "Decrypt without ModReduce fails";

	Ciphertext<DCRTPoly> ciphertextR = cc->ModReduce(ciphertext);

	//drop a tower from the secret key
	
	auto skEl(kp.secretKey->GetPrivateElement());
	skEl.DropLastElement();
	kp.secretKey->SetPrivateElement(skEl);

	Plaintext intArrayNew2;
	cc->Decrypt(kp.secretKey, ciphertextR, &intArrayNew2);
	intArrayNew2->SetLength(intArray1->GetLength());

	EXPECT_EQ(intArray1->GetCoefPackedValue(), intArrayNew2->GetCoefPackedValue()) << "Decrypt after ModReduce fails";;

}
#endif




