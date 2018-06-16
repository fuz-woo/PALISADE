/*
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
#include "utils/aesutil.h"
#include "utils/debug.h"
#include <iostream>

using namespace lbcrypto;

void CombineBytes(unsigned char* bytes,int64_t* numbers,const unsigned int bytelength);
void SplitBytes(int64_t* numbers,  unsigned char* bytes,const unsigned int numberlength);

int main() {
	double totaltime=0;
	bool dbg_flag = true;
	unsigned char iv[4]={1,2,3,4};
	unsigned char key[32]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
	AESUtil util(iv,key,32);
	TimeVar t1;
	for(int i=0;i<500;i++){
		int64_t numbervector[2048];
		unsigned char bytevector[2048*8];
		unsigned char encrypted_bytevector[2048*8];
		for(int j=0;j<2048;j++){
			numbervector[j] =0;
		}
		SplitBytes(numbervector,bytevector,2048);
		TIC(t1);
		util.Encrypt(bytevector,encrypted_bytevector,2048*8,CTR);
		totaltime+=TOC_US(t1);
		CombineBytes(encrypted_bytevector,numbervector,2048*8);
	}

	DEBUG("Time for 5 vectors of 2048: " << totaltime/100<< " us");
}
void CombineBytes(unsigned char* bytes,int64_t* numbers,const unsigned int bytelength){
	for(unsigned int i=0;i<bytelength;i+=8){
			numbers[i/8]=((int64_t)(bytes[i]*pow(2,56))) ^ ((int64_t)(bytes[i+1]*pow(2,48))) ^ ((int64_t)(bytes[i+2]*pow(2,40))) ^ ((int64_t)(bytes[i+3]*pow(2,32))) ^ ((int64_t)(bytes[i+4]*pow(2,24))) ^ ((int64_t)(bytes[i+5]*pow(2,16))) ^ ((int64_t)(bytes[i+6]*pow(2,8))) ^ ((int64_t)(bytes[i+7]));
		}
}
void SplitBytes(int64_t* numbers,  unsigned char* bytes,const unsigned int numberlength){
	for(unsigned int i=0;i<numberlength;i++){
		bytes[8*i]=(numbers[i] >> 56)  & 0xFF;
		bytes[8*i+1]=(numbers[i] >> 48)  & 0xFF;
		bytes[8*i+2]=(numbers[i] >> 40)  & 0xFF;
		bytes[8*i+3]=(numbers[i] >> 32)  & 0xFF;
		bytes[8*i+4]=(numbers[i] >> 24)  & 0xFF;
		bytes[8*i+5]=(numbers[i] >> 16)  & 0xFF;
		bytes[8*i+6]=(numbers[i] >> 8)  & 0xFF;
		bytes[8*i+7]=(numbers[i])  & 0xFF;
	}
}
