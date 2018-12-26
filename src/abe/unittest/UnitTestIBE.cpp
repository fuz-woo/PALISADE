/**
 * @file UnitTestIBE.cpp - Unit test file for identity based encryption

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

#include "../lib/math/backend.h"
#include "../lib/abecontext.h"


using namespace std;
using namespace lbcrypto;

template <class T>
class UTIBE : public ::testing::Test {

public:


protected:
	UTIBE() {}

	virtual void SetUp() {

	}

	virtual void TearDown() {

	}

	virtual ~UTIBE() {  }

};
//Body of the unittest
template <class Element>
void UnitTestIBE(SecurityLevel level){
	
    ABEContext<Element> context;
    context.GenerateIBEContext(level);
    IBEMasterPublicKey<Element> mpk;
	IBEMasterSecretKey<Element> msk;
    context.Setup(&mpk,&msk);
    IBEUserIdentifier<Element> id(context.GenerateRandomElement());
    IBESecretKey<Element> sk;
	context.KeyGen(msk,mpk,id,&sk);
    
    std::vector<int64_t> vectorOfInts = { 1,0,0,1,1,0,1,0, 1, 0};
    Plaintext pt = context.MakeCoefPackedPlaintext(vectorOfInts);
    IBECiphertext<Element> ct;
	context.Encrypt(mpk,id,pt,&ct);
	Plaintext dt = context.Decrypt(sk,ct);

	EXPECT_EQ(pt->GetElement<Element>(),dt->GetElement<Element>());
}
//Tests for 128 bit security
TEST(UTIBE, ibe_128_poly) {
	UnitTestIBE<Poly>(HEStd_128_classic);
}
TEST(UTIBE, ibe_128_native) {
	UnitTestIBE<NativePoly>(HEStd_128_classic);
}
TEST(UTIBE, ibe_192_poly) {
	UnitTestIBE<Poly>(HEStd_192_classic);
}
//Tests for 192 bit security
TEST(UTIBE, ibe_192_native) {
	UnitTestIBE<NativePoly>(HEStd_192_classic);
}
//Tests for 256 bit security
TEST(UTIBE, ibe_256_poly) {
	UnitTestIBE<Poly>(HEStd_256_classic);
}

TEST(UTIBE, ibe_256_native) {
	UnitTestIBE<NativePoly>(HEStd_256_classic);
}