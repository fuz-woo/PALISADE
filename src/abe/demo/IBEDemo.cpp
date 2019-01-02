/**
 * @file IBEDemo.cpp - Demo file for identity based encryption

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
#include "../lib/abecontext.h"
#include "palisade.h"

using namespace lbcrypto;

int main(){
    //Create context under given ringsize and base
	  //Create context under security level and number of attributes
		std::cout<<"This is a demo file of the IBE scheme"<<std::endl<<std::endl;
		usint ringsize = 1024;
		usint base = 4;
		TimeVar t1;
		std::cout<<"Used parameters:"<<std::endl;
		std::cout<<"Ring size: "<<ringsize<<std::endl;
		std::cout<<"Base: "<<base<<std::endl<<std::endl;
		ABEContext<NativePoly> context;
		std::cout<<"Generating a context under these parameters"<<std::endl<<std::endl;
		context.GenerateIBEContext(ringsize,base);
    
    //Generate master keys
	std::cout<<"Generating master secret and public keys"<<std::endl;
    IBEMasterPublicKey<NativePoly> mpk;
	IBEMasterSecretKey<NativePoly> msk;
	TIC(t1);
    context.Setup(&mpk,&msk);
    double duration = TOC(t1);
    std::cout<<"Setup: "<<duration<<" ms"<<std::endl<<std::endl;
    
    std::cout<<"Creating a random identifier for the user"<<std::endl<<std::endl;
    //Generate a random identifier for the user
    IBEUserIdentifier<NativePoly> id(context.GenerateRandomElement());
    
    std::cout<<"Generating the secret key for the user"<<std::endl;
    //Generate the secret key for the user
    IBESecretKey<NativePoly> sk;
    TIC(t1);
	context.KeyGen(msk,mpk,id,&sk);
	duration = TOC(t1);
	std::cout<<"KeyGen: "<<duration<<" ms"<<std::endl<<std::endl;
    
    //Generate a plaintext
    std::vector<int64_t> vectorOfInts = { 1,0,0,1,1,0,1,0, 1, 0};
    Plaintext pt = context.MakeCoefPackedPlaintext(vectorOfInts);
    std::cout<<"Plaintext vector of bits:"<<vectorOfInts<<std::endl<<std::endl;
    
    //Encrypt the plaintext
    std::cout<<"Encrypting the plaintext for the user with the id"<<std::endl;
    IBECiphertext<NativePoly> ct;
    TIC(t1);
	context.Encrypt(mpk,id,pt,&ct);
	duration = TOC(t1);
	std::cout<<"Encryption: "<<duration<<" ms"<<std::endl<<std::endl;
    
    //Decrypt the ciphertext
	std::cout<<"Decrypting the ciphertext"<<std::endl;
	TIC(t1);
	Plaintext dt = context.Decrypt(id,id,sk,ct);
	duration = TOC(t1);
	std::cout<<"Decryption: "<<duration<<" ms"<<std::endl<<std::endl;


    std::cout<<"Checking if plaintext & decrypted text match"<<std::endl;
    //Check if original plaintext and decrypted plaintext match
    if(pt->GetElement<NativePoly>() == dt->GetElement<NativePoly>()){
        std::cout<<"Encryption & decryption successful"<<std::endl;
    }else{
        std::cout<<"Encryption & decryption failed"<<std::endl;
    }

    return 0;
}
