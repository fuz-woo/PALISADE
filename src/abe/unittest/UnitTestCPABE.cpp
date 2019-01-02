/**
 * @file UnitTEstCPABE.cpp - Unit test file for ciphertext-policy attribute based encryption

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
class UTCPABE : public ::testing::Test {

public:


protected:
	UTCPABE() {}

	virtual void SetUp() {

	}

	virtual void TearDown() {

	}

	virtual ~UTCPABE() {  }

};
//Test body
template <class Element>
void UnitTestCPABE(SecurityLevel level,usint ell){
    ABEContext<Element> context;
    context.GenerateCPABEContext(level,ell);
    CPABEMasterPublicKey<Element> mpk;
	CPABEMasterSecretKey<Element> msk;
    context.Setup(&mpk,&msk);

    std::vector<usint> s(ell);
	std::vector<int> w(ell);

    for(usint j=0; j<ell; j++)
		s[j] = rand()%2;

	for(usint j=0; j<ell; j++)
		w[j] = s[j];

	for(usint j=0; j<ell; j++)
		if(w[j]==1) {
			w[j] = 0;
			break;
		}
	for(usint j=0; j<ell; j++)
		if(s[j]==0) {
			w[j] = -1;
			break;
		}
    
    CPABEUserAccess<Element> ua(s);
    CPABEAccessPolicy<Element> ap(w);

    CPABESecretKey<Element> sk;
	context.KeyGen(msk,mpk,ua,&sk);
    std::vector<int64_t> vectorOfInts = { 1,0,0,1,1,0,1,0, 1, 0};
    Plaintext pt = context.MakeCoefPackedPlaintext(vectorOfInts);
    CPABECiphertext<Element> ct;
	context.Encrypt(mpk,ap,pt,&ct);
	Plaintext dt = context.Decrypt(ap,ua,sk,ct);


    EXPECT_EQ(pt->GetElement<Element>(),dt->GetElement<Element>());

}
//Test for 128 bit security and 6,8,16,20,32 attributes
TEST(UTCPABE, cp_abe_128_poly_6) {
	UnitTestCPABE<Poly>(HEStd_128_classic,6);
}
TEST(UTCPABE, cp_abe_128_native_6) {
	UnitTestCPABE<NativePoly>(HEStd_128_classic,6);
}
TEST(UTCPABE, cp_abe_128_poly_8) {
	UnitTestCPABE<Poly>(HEStd_128_classic,8);
}
TEST(UTCPABE, cp_abe_128_native_8) {
	UnitTestCPABE<NativePoly>(HEStd_128_classic,8);
}
TEST(UTCPABE, cp_abe_128_native_16) {
	UnitTestCPABE<NativePoly>(HEStd_128_classic,16);
}
TEST(UTCPABE, cp_abe_128_native_20) {
	UnitTestCPABE<NativePoly>(HEStd_128_classic,20);
}
TEST(UTCPABE, cp_abe_128_native_32) {
	UnitTestCPABE<NativePoly>(HEStd_128_classic,32);
}
//Test for 192 bit security and 6,8,16,20,32 attributes native poly only
TEST(UTCPABE, cp_abe_192_native_6) {
	UnitTestCPABE<NativePoly>(HEStd_192_classic,6);
}
TEST(UTCPABE, cp_abe_192_native_8) {
	UnitTestCPABE<NativePoly>(HEStd_192_classic,8);
}
TEST(UTCPABE, cp_abe_192_native_16) {
	UnitTestCPABE<NativePoly>(HEStd_192_classic,16);
}
TEST(UTCPABE, cp_abe_192_native_20) {
	UnitTestCPABE<NativePoly>(HEStd_192_classic,20);
}
TEST(UTCPABE, cp_abe_192_native_32) {
	UnitTestCPABE<NativePoly>(HEStd_192_classic,32);
}
//Test for 256 bit security and 6,8,16,20,32 attributes native poly only
TEST(UTCPABE, cp_abe_256_native_6) {
	UnitTestCPABE<NativePoly>(HEStd_256_classic,6);
}
TEST(UTCPABE, cp_abe_256_native_8) {
	UnitTestCPABE<NativePoly>(HEStd_256_classic,8);
}
TEST(UTCPABE, cp_abe_256_native_16) {
	UnitTestCPABE<NativePoly>(HEStd_256_classic,16);
}
TEST(UTCPABE, cp_abe_256_native_20) {
	UnitTestCPABE<NativePoly>(HEStd_256_classic,20);
}
TEST(UTCPABE, cp_abe_256_native_32) {
	UnitTestCPABE<NativePoly>(HEStd_256_classic,32);
}
