/*
 * @file UnitTestEncryptStream
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
#include <sstream>
#include <vector>

#include "../lib/cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

#include "cryptocontextgen.h"
#include "lattice/elemparamfactory.h"

using namespace std;
using namespace lbcrypto;



class UTEncryptStream : public ::testing::Test {

public:
	UTEncryptStream() {}

	virtual void SetUp() {
	}

	virtual void TearDown() {

	}
};

TEST_F(UTEncryptStream, Stream_Encryptor_Test_BFV)
{
	string	base = "Strange women lying in ponds distributing swords is no basis for a system of government!";
	stringstream		bigSource, mid, bigDest;
	for( size_t i = 0; i < 5000; i++ )
		bigSource << base;

	CryptoContext<Poly> cc = GenCryptoContextBFV<Poly>(1024, 256);
	LPKeyPair<Poly> kp = cc->KeyGen();

	cc->EncryptStream(kp.publicKey, bigSource, mid);
	cc->DecryptStream(kp.secretKey, mid, bigDest);

	EXPECT_EQ(bigSource.str(), bigDest.str());
}

TEST_F(UTEncryptStream, Stream_Encryptor_Test_BFVrns)
{
	string	base = "Strange women lying in ponds distributing swords is no basis for a system of government!";
	stringstream		bigSource, mid, bigDest;
	for( size_t i = 0; i < 5000; i++ )
		bigSource << base;

	CryptoContext<DCRTPoly> cc = GenCryptoContextBFVrns<DCRTPoly>(256);
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	cc->EncryptStream(kp.publicKey, bigSource, mid);
	cc->DecryptStream(kp.secretKey, mid, bigDest);

	EXPECT_EQ(bigSource.str(), bigDest.str());
}
