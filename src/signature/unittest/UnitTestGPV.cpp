/*
 * @file This code exercises the GPV signature methods of the PALISADE lattice encryption library.
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
#include "../lib/signaturecontext.h"
#include "encoding/encodings.h"

using namespace lbcrypto;

class UnitTestSignatureGPV : public ::testing::Test {
protected:
	virtual void SetUp() {
	}

	virtual void TearDown() {
		// Code here will be called immediately after each test
		// (right before the destructor).
	}
};
/*---------------------------------------	TESTING METHODS OF SIGNATURE  --------------------------------------------*/

//TEST FOR BASIC SIGNING & VERIFICATION PROCESS IN POLY
TEST(UTSignatureGPV,simple_sign_verify) {
  bool dbg_flag = false;

  DEBUG("Context Generation");
	SignatureContext<Poly> context;
  context.GenerateGPVContext(1024);
  DEBUG("Key Generation");
  GPVVerificationKey<Poly> vk;
  GPVSignKey<Poly> sk;
  context.KeyGen(&sk,&vk);
  string pt = "This is a test";
  GPVPlaintext<Poly> plaintext(pt);
  DEBUG("Signing");
  GPVSignature<Poly> signature;
  context.Sign(plaintext,sk,vk,&signature);
  DEBUG("Verification");
  bool result1 = context.Verify(plaintext,signature,vk);
    
	EXPECT_EQ(true, result1)
		<<"Failed verification";
}

//TEST FOR BASIC SIGNING & VERIFICATION PROCESS FOR NATIVEPOLY WITH MODULUS SIZE <60 BITS

TEST(UTSignatureGPV,simple_sign_verify_native_below_sixty_bits) {
  bool dbg_flag = false;

  DEBUG("Context Generation");
	SignatureContext<NativePoly> context;
  context.GenerateGPVContext(1024);
  DEBUG("Key Generation");
  GPVVerificationKey<NativePoly> vk;
  GPVSignKey<NativePoly> sk;
  context.KeyGen(&sk,&vk);
  string pt = "This is a test";
  GPVPlaintext<NativePoly> plaintext(pt);
  DEBUG("Signing");
  GPVSignature<NativePoly> signature;
  context.Sign(plaintext,sk,vk,&signature);
  DEBUG("Verification");
  bool result1 = context.Verify(plaintext,signature,vk);
    
	EXPECT_EQ(true, result1)
		<<"Failed verification";
 

}

//TEST FOR BASIC SIGNING & VERIFICATION PROCESS FOR NATIVEPOLY WITH MODULUS SIZE >60 BITS

TEST(UTSignatureGPV,simple_sign_verify_native_above_sixty_bits) {
  
  bool dbg_flag = false;

  DEBUG("Context Generation");
	SignatureContext<NativePoly> context;
  context.GenerateGPVContext(1024,61,64);
  DEBUG("Key Generation");
  GPVVerificationKey<NativePoly> vk;
  GPVSignKey<NativePoly> sk;
  context.KeyGen(&sk,&vk);
  string pt = "This is a test";
  GPVPlaintext<NativePoly> plaintext(pt);
  DEBUG("Signing");
  GPVSignature<NativePoly> signature;
  context.Sign(plaintext,sk,vk,&signature);
  DEBUG("Verification");
  bool result1 = context.Verify(plaintext,signature,vk);
    
	EXPECT_EQ(true, result1)
		<<"Failed verification";

}
/*
//TEST FOR BASIC SIGNING & VERIFICATION PROCESS - TWO STEP PROCESS (Commented Out Since SignatureContext  does not include online-offline split yet)
TEST(UTSignatureGPV, simple_sign_verify_two_phase) {
	bool dbg_flag = false;

	DEBUG("Step 1");
	Poly::DggType dgg(4);
	usint sm = 16;
	BigInteger smodulus("1152921504606847009");
	BigInteger srootOfUnity("405107564542978792");

	shared_ptr<ILParams> silParams(new ILParams(sm, smodulus, srootOfUnity));
	DEBUG("Step 2");
	ChineseRemainderTransformFTT<BigVector>::PreCompute(srootOfUnity, sm, smodulus);
	DEBUG("Step 4");
	LPSignatureParameters<Poly> signParams(silParams, dgg);
	DEBUG("Step 5");
	LPSignKeyGPVGM<Poly> s_k(signParams);
	DEBUG("Step 6");
	LPVerificationKeyGPVGM<Poly> v_k(signParams);
	DEBUG("Step 7");
	LPSignatureSchemeGPVGM<Poly> scheme;
	DEBUG("Step 8");
	scheme.KeyGen(&s_k, &v_k);
	DEBUG("Step 9");
	Signature<Matrix<Poly>> signature;
	DEBUG("Step 10");
	string text("Since hashing is integrated now");
	DEBUG("Step 11");

	shared_ptr<Matrix<Poly>> pVector = scheme.SampleOffline(s_k);

	scheme.SignOnline(s_k, pVector, text, &signature);

	EXPECT_EQ(true, scheme.Verify(v_k, signature, text))
		<< "Failed verification";

	DEBUG("Step 12");

}
*/

//TEST FOR SIGNING AND VERIFYING SIGNATURES GENERATED FROM MULTIPLE TEXTS. ONLY SIGNATURES CORRESPONDING TO THEIR RESPECTIVE TEXT SHOULD VERIFY
TEST(UTSignatureGPV, sign_verify_multiple_texts) {
  bool dbg_flag = false;
  
  DEBUG("Context Generation");
	SignatureContext<Poly> context;
  context.GenerateGPVContext(1024);
  DEBUG("Key Generation");
  GPVVerificationKey<Poly> vk;
  GPVSignKey<Poly> sk;
  context.KeyGen(&sk,&vk);
  GPVPlaintext<Poly> plaintext,plaintext2;
  string pt = "This is a test";
  string pt2 = "This is another one, funny isn't it?";
  plaintext.SetPlaintext(pt);
  plaintext2.SetPlaintext(pt2);
  DEBUG("Signing - PT 1");
  GPVSignature<Poly> signature,signature2;
  context.Sign(plaintext,sk,vk,&signature);
  DEBUG("Signing - PT 2");
  context.Sign(plaintext2,sk,vk,&signature2);
  DEBUG("Verification");
  bool result1 = context.Verify(plaintext,signature,vk);
  bool result2 = context.Verify(plaintext,signature2,vk);
  bool result3 = context.Verify(plaintext2,signature,vk);
  bool result4 = context.Verify(plaintext2,signature2,vk);

	EXPECT_EQ(true, result1)
			<<"Failed signature 1 - text 1 verification";
	EXPECT_EQ(true, result4)
			<< "Failed signature 2 - text 2 verification";
	EXPECT_NE(true, result2)
			<< "Failed signature 2 - text 1 verification";
	EXPECT_NE(true, result3)
			<< "Failed signature 1 - text 2 verification";

}

//TEST FOR SIGNING AND VERIFYING SIGNATURES GENERATED FROM MULTIPLE KEYS. ONLY SIGNATURES CORRESPONDING TO THEIR RESPECTIVE SPECIFIC KEY SHOULD VERIFY
TEST(UTSignatureGPV, sign_verify_multiple_keys) {
  bool dbg_flag = false;
  
  DEBUG("Context Generation");
	SignatureContext<Poly> context;
  context.GenerateGPVContext(1024);
  DEBUG("Key Generation - Key Pair 1");
  GPVVerificationKey<Poly> vk,vk2;
  GPVSignKey<Poly> sk,sk2;
  context.KeyGen(&sk,&vk);
  DEBUG("Key Generation - Key Pair 2");
  context.KeyGen(&sk2,&vk2);
  string pt = "This is a test";
  GPVPlaintext<Poly> plaintext(pt);
  DEBUG("Signing - KP 1");
  GPVSignature<Poly> signature,signature2;
  context.Sign(plaintext,sk,vk,&signature);
  DEBUG("Signing - KP 2");
  context.Sign(plaintext,sk2,vk2,&signature2);
  DEBUG("Verification");
  bool result1 = context.Verify(plaintext,signature,vk);
  bool result2 = context.Verify(plaintext,signature2,vk);
  bool result3 = context.Verify(plaintext,signature,vk2);
  bool result4 = context.Verify(plaintext,signature2,vk2);

	EXPECT_EQ(true, result1)
			<<"Failed signature 1 - key pair 1 verification";
	EXPECT_EQ(true, result4)
			<< "Failed signature 2 - key pair 2 verification";
	EXPECT_NE(true, result2)
			<< "Failed signature 2 - key pair 1 verification";
	EXPECT_NE(true, result3)
			<< "Failed signature 1 - key pair 2 verification";

}
/*
int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
*/
