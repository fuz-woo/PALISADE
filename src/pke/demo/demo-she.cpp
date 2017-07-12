/*
 * @file demo_she.cpp - PALISADE library.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 * Demo software for FV multiparty operations.
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"
#include "encoding/byteplaintextencoding.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char *argv[]) {

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////


	std::cout << "\nThis code demonstrates the use of the FV scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;


	//Generate parameters.
	double diff, start, finish;

	int relWindow = 1;
	int plaintextModulus = 1024;
	double sigma = 4;
	double rootHermiteFactor = 1.006;	

	//Set Crypto Parameters	
	shared_ptr<CryptoContext<Poly>> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 2, 0);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);
	
	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();
	
	// Initialize Public Key Containers
	LPKeyPair<Poly> keyPair;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts1 = {3,2,1,3,2,1,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts2 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {1,0,0,0,0,0,0,0,0,0,0,0};
	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);
	IntPlaintextEncoding plaintext3(vectorOfInts3);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext3;

	start = currentDateTime();

	ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1, true);
	ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2, true);
	ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3, true);
	
	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintext1Dec;
	IntPlaintextEncoding plaintext2Dec;
	IntPlaintextEncoding plaintext3Dec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintext1Dec, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintext2Dec, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertext3, &plaintext3Dec, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintext1Dec.resize(plaintext1.size());
	plaintext2Dec.resize(plaintext1.size());
	plaintext3Dec.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintext1Dec << endl;
	cout << plaintext2Dec << endl;
	cout << plaintext3Dec << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// EvalAdd Operation
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextAdd12;
	shared_ptr<Ciphertext<Poly>> ciphertextAdd123;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextAddVect;

	start = currentDateTime();

	ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1[0],ciphertext2[0]);
	ciphertextAdd123 = cryptoContext->EvalAdd(ciphertextAdd12,ciphertext3[0]);

	ciphertextAddVect.push_back(ciphertextAdd123);

	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalAdd time: " << "\t" << diff << " ms" << endl;


	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAdd;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddVect, &plaintextAdd, true);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextAdd.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	cout << "\n Resulting Added Plaintext: \n";
	cout << plaintextAdd << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// EvalMult Operation
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextMul12;
	shared_ptr<Ciphertext<Poly>> ciphertextMul123;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect;

	start = currentDateTime();

	ciphertextMul12 = cryptoContext->EvalMult(ciphertext1[0],ciphertext2[0]);
	ciphertextMul123 = cryptoContext->EvalMult(ciphertextMul12,ciphertext3[0]);

	ciphertextMulVect.push_back(ciphertextMul123);

	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalMult time: " << "\t" << diff << " ms" << endl;


	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextMul;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect, &plaintextMul, true);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextMul.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	cout << "\n Resulting Plaintext (after polynomial multiplication): \n";
	cout << plaintextMul << endl;

	cout << "\n";
	////////////////////////////////////////////////////////////
	// Done
	////////////////////////////////////////////////////////////

	std::cout << "Execution Completed." << std::endl;

	return 0;
}
