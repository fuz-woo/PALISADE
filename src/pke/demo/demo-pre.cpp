/*
 * @file demo_pre.cpp - PALISADE library.
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

int main(int argc, char *argv[])
{

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////

	//Generate parameters.
	double diff, start, finish;

	std::cout << "\nThis code demonstrates the use of the FV, BV, StSt, Null and LTV schemes for basic proxy-re-encryption operations. " ;
	std::cout << "This code shows how to use schemes and pre-computed parameters for those schemes can be selected during run-time. " ;
	std::cout << "In this demonstration we encrypt data and then proxy re-encrypt it. " ;
	std::cout << "We do not generally recommend the use of the LTV scheme due to security concerns. " << std::endl;

	std::cout << "\nChoose parameter set: ";
	CryptoContextHelper::printParmSetNamesByFilter(std::cout,"PRE");

	string input;
	std::cin >> input;

	start = currentDateTime();

	shared_ptr<CryptoContext<Poly>> cryptoContext = CryptoContextHelper::getNewContext(input);
	if (!cryptoContext) {
		cout << "Error on " << input << endl;
		return 0;
	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "\nParam generation time: " << "\t" << diff << " ms" << endl;

	//Turn on features
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);
	cryptoContext->Enable(PRE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;
	std::cout << "r = " << cryptoContext->GetCryptoParameters()->GetRelinWindow() << std::endl;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	// Initialize Key Pair Containers
	LPKeyPair<Poly> keyPair1;

	std::cout << "\nRunning key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair1 = cryptoContext->KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair1.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts = {1,0,1,1,1,1,0,1,1,1,0,1};
	IntPlaintextEncoding plaintext(vectorOfInts);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;

	start = currentDateTime();

	ciphertext1 = cryptoContext->Encrypt(keyPair1.publicKey, plaintext, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextDec1;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair1.secretKey, ciphertext1, &plaintextDec1, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintextDec1.resize(plaintext.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext << endl;

	cout << "\n Resulting Decryption of Ciphertext before Re-Encryption: \n";
	cout << plaintextDec1 << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	// Initialize Key Pair Containers
	LPKeyPair<Poly> keyPair2;

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair2 = cryptoContext->KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair2.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	// Set a flag to determine which ReKeyGent interface is supported
	// flagBV == true means BV or FV
	// flagBV == false corresponds to LTV, StSt, and Null

	bool flagBV = true;

	if ((input.find("BV") == string::npos) && (input.find("FV") == string::npos))
		flagBV = false;

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;

	shared_ptr<LPEvalKey<Poly>> reencryptionKey12;

	start = currentDateTime();

	if (flagBV)
		reencryptionKey12 = cryptoContext->ReKeyGen(keyPair2.secretKey, keyPair1.secretKey);
	else
		reencryptionKey12 = cryptoContext->ReKeyGen(keyPair2.publicKey, keyPair1.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	// Re-Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;

	ciphertext2 = cryptoContext->ReEncrypt(reencryptionKey12, ciphertext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Re-Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextDec2;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair2.secretKey, ciphertext2, &plaintextDec2, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	plaintextDec2.resize(plaintext.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext << endl;

	cout << "\n Resulting Decryption of Ciphertext before Re-Encryption: \n";
	cout << plaintextDec1 << endl;

	cout << "\n Resulting Decryption of Ciphertext after Re-Encryption: \n";
	cout << plaintextDec2 << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// Done
	////////////////////////////////////////////////////////////

	std::cout << "Execution Completed." << std::endl;

	return 0;
}
