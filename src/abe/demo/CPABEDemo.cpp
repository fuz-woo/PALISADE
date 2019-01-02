/**
 * @file CPABEDemo.cpp - Demo file for ciphertext-policy attribute based encryption

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
#include "palisade.h"
#include "../lib/abecontext.h"

using namespace lbcrypto;
int main(){
    //Create context under security level and number of attributes
	std::cout<<"This is a demo file of the CPABE scheme"<<std::endl<<std::endl;
	usint ringsize = 1024;
	usint numAttributes = 6;
	usint base = 64;
	TimeVar t1;
	std::cout<<"Used parameters:"<<std::endl;
	std::cout<<"Ring size: "<<ringsize<<std::endl;
	std::cout<<"Number of attributes: "<<numAttributes<<std::endl;
	std::cout<<"Base: "<<base<<std::endl<<std::endl;

	ABEContext<NativePoly> context;
	std::cout<<"Generating a context under these parameters"<<std::endl<<std::endl;
    context.GenerateCPABEContext(numAttributes,ringsize,base);
    
    std::cout<<"Generating master secret key and master public key"<<std::endl;
    //Generate master keys
    TIC(t1);
    CPABEMasterPublicKey<NativePoly> mpk;
	CPABEMasterSecretKey<NativePoly> msk;
    context.Setup(&mpk,&msk);
    double duration = TOC(t1);
    std::cout<<"Setup: "<<duration<<" ms"<<std::endl<<std::endl;

    //Create a random access policy and user attribute set
    std::cout<<" Creating access policy and user attribute sets"<<std::endl;
    std::vector<usint> s(6);
	std::vector<int> w(6);

    for(usint j=0; j<6; j++)
		s[j] = rand()%2;

	for(usint j=0; j<6; j++)
		w[j] = s[j];

	for(usint j=0; j<6; j++)
		if(w[j]==1) {
			w[j] = 0;
			break;
		}
	for(usint j=0; j<6; j++)
		if(s[j]==0) {
			w[j] = -1;
			break;
		}
    std::cout<<"User attribute set: "<<s<<std::endl;
    std::cout<<"Access policy defined:"<<w<<std::endl<<std::endl;
    CPABEUserAccess<NativePoly> ua(s);
    CPABEAccessPolicy<NativePoly> ap(w);

    //Create the key corresponding to the access policy
    CPABESecretKey<NativePoly> sk;
    std::cout<<"Creating secret key for the attribute set"<<std::endl;
    TIC(t1);
	context.KeyGen(msk,mpk,ua,&sk);
	duration = TOC(t1);
	std::cout<<"KeyGen: "<<duration<<" ms"<<std::endl<<std::endl;
    
    //Create a plaintext
    std::vector<int64_t> vectorOfInts = { 1,0,0,1,1,0,1,0, 1, 0};
    Plaintext pt = context.MakeCoefPackedPlaintext(vectorOfInts);
    std::cout<<"Plaintext vector of bits: "<<vectorOfInts<<std::endl<<std::endl;
    
    //Encrypt the plaintext
    std::cout<<"Encrypting the plaintext under the access policy"<<std::endl;
    TIC(t1);
    CPABECiphertext<NativePoly> ct;
	context.Encrypt(mpk,ap,pt,&ct);
	duration = TOC(t1);
	std::cout<<"Encryption: "<<duration<<" ms"<<std::endl<<std::endl;
    
    //Decrypt the ciphertext
	std::cout<<"Decrpyting the ciphertext"<<std::endl;
	TIC(t1);
	Plaintext dt = context.Decrypt(ap,ua,sk,ct);
	duration = TOC(t1);
	std::cout<<"Decryption: "<<duration<<" ms"<<std::endl<<std::endl;

	std::cout<<"Checking if the plaintext & decrypted text match"<<std::endl;
    //Check if original plaintext and decrypted plaintext match
    if(pt->GetElement<NativePoly>() == dt->GetElement<NativePoly>()){
        std::cout<<"Encryption & decryption successful"<<std::endl;
    }else{
        std::cout<<"Encryption & decryption failed"<<std::endl;
    }
}
