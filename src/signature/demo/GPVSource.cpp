/**
 * @file GPVSource.cpp - Demo file for GPV signature scheme

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
#include "../lib/signaturecontext.h"

using namespace lbcrypto;
    int main(){
    	std::cout<<"This is a demo file of the GPV signature scheme"<<std::endl<<std::endl;
        //We generate a signature context and make it a GPV context with ring size, you can also explicitly define ringsize, modulus bitwidth and base
        SignatureContext<Poly> context;
        usint ringsize = 1024;
        std::cout<<"Used ring size for calculations: "<<ringsize<<std::endl;
        std::cout<<"Generating context for GPV signature"<<std::endl<<std::endl;
        context.GenerateGPVContext(ringsize);
        
        //Create our sign and verification keys and generate them
        GPVVerificationKey<Poly> vk;
        GPVSignKey<Poly> sk;
        std::cout<<"Generating signing and verification keys"<<std::endl;
        double duration = 0.0;
        TimeVar t1;
        TIC(t1);
        context.KeyGen(&sk,&vk);
        duration = TOC(t1);
        std::cout<<"Keygen: "<<duration<<" ms"<<std::endl<<std::endl;
        //Create different plaintexts
        GPVPlaintext<Poly> plaintext, plaintext2;
        string pt1 = "This is a test";
        string pt2 = "This is the wrong one";
        std::cout<<"First plaintext: "<<pt1<<std::endl;
        std::cout<<"Second plaintext: "<<pt2<<std::endl<<std::endl;
        plaintext.SetPlaintext(pt1);
        plaintext2.SetPlaintext(pt2);
        

        //Sign the first plaintext with generated keys
        GPVSignature<Poly> signature;
        std::cout<<"Signing first plaintext"<<std::endl;
        TIC(t1);
        context.Sign(plaintext,sk,vk,&signature);
        duration = TOC(t1);
        std::cout<<"Signing: "<<duration<<" ms"<<std::endl<<std::endl;
        //Try to verify the signature with two different plaintexts
        std::cout<<"Trying to verify the signature with first plaintext and second plaintext"<<std::endl;
        TIC(t1);
        bool result1 = context.Verify(plaintext,signature,vk);
        bool result2 = context.Verify(plaintext2,signature,vk);
        duration = TOC(t1);
        std::cout<<"Average verify time: "<<duration / 2.0 <<" ms"<<std::endl<<std::endl;
        
        //Show the verification results
        std::cout<<"Verif result 1: "<<result1<<std::endl;
        std::cout<<"Verif result 2: "<<result2<<std::endl;    
        return 0;    
    }
