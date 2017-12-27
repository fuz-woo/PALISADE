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
 * Demo software for BFV multiparty operations.
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

void
keymaker(CryptoContext<Poly> ctx, string keyname)
{

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = ctx->KeyGen();

	if( kp.publicKey && kp.secretKey ) {
		Serialized pubK, privK;

		if( kp.publicKey->Serialize(&pubK) ) {
			if( !SerializableHelper::WriteSerializationToFile(pubK, DATAFOLDER + "/" + keyname + "PUB.txt") ) {
				cerr << "Error writing serialization of public key to " + keyname + "PUB.txt" << endl;
				return;
			}
		} else {
			cerr << "Error serializing public key" << endl;
			return;
		}

		if( kp.secretKey->Serialize(&privK) ) {
			if( !SerializableHelper::WriteSerializationToFile(privK, DATAFOLDER + "/" + keyname + "PRI.txt") ) {
				cerr << "Error writing serialization of private key to " + keyname + "PRI.txt" << endl;
				return;
			}
		} else {
			cerr << "Error serializing private key" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating keys" << endl;
	}

	return;
}


void
encrypter(CryptoContext<Poly> ctx, Plaintext iPlaintext, string pubkeyname, string ciphertextname)
{

	ofstream ctSer(DATAFOLDER + "/" + ciphertextname, ios::binary);
	if( !ctSer.is_open() ) {
		cerr << "could not open output file " << ciphertextname << endl;
		return;
	}

	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + pubkeyname, &kser) == false ) {
		cerr << "Could not read public key" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPublicKey<Poly> pk = ctx->deserializePublicKey(kser);

	if( !pk ) {
		cerr << "Could not deserialize public key" << endl;
		ctSer.close();
		return;
	}

	// now encrypt iPlaintext
	auto ciphertext = ctx->Encrypt(pk, iPlaintext);

	Serialized cSer;
	if( ciphertext->Serialize(&cSer) ) {
		if( !SerializableHelper::WriteSerializationToFile(cSer, DATAFOLDER + "/" + ciphertextname) ) {
			cerr << "Error writing serialization of ciphertext to " + ciphertextname << endl;
			return;
		}
	} else {
		cerr << "Error serializing ciphertext" << endl;
		return;
	}

	ctSer.close();
	return;
}


Plaintext
decrypter(CryptoContext<Poly> ctx, string ciphertextname, string prikeyname)
{
	Plaintext iPlaintext;

	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + prikeyname, &kser) == false ) {
		cerr << "Could not read private key" << endl;
		return iPlaintext;
	}

	LPPrivateKey<Poly> sk = ctx->deserializeSecretKey(kser);
	if( !sk ) {
		cerr << "Could not deserialize private key" << endl;
		return iPlaintext;
	}

	ifstream inCt(DATAFOLDER + "/" + ciphertextname, ios::binary);
	if( !inCt.is_open() ) {
		cerr << "Could not open ciphertext" << endl;
		return iPlaintext;
	}

	//Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + ciphertextname, &kser) == false ) {
		cerr << "Could not read ciphertext" << endl;
		return iPlaintext;
	}

	// Initialize the public key containers.
	Ciphertext<Poly> ct = ctx->deserializeCiphertext(kser);
	if( ct == NULL ) {
		cerr << "Could not deserialize ciphertext" << endl;
		return iPlaintext;
	}


	// now decrypt iPlaintext
	ctx->Decrypt(sk, ct, &iPlaintext);

	inCt.close();

	return iPlaintext;
}

int main(int argc, char *argv[])
{

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////


	std::cout << "\nThis code demonstrates a simple use of json serialization for BFV schemes with public key encryption. " << std::endl;
	std::cout << "This code creates and saves keys to disk, loads the keys from disk, encrypts data and saves ciphertext to disk. " << std::endl;
	std::cout << "The code then loads the ciphertext from disk and decrypts. " << std::endl;

	int relWindow = 1;
	int plaintextModulus = 64;
	double sigma = 4;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<Poly> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextBFV(
	            plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 1, 0);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	string keyFileName = "demo_json_key";
	string keyFileNamePublic = "demo_json_keyPUB.txt";
	string keyFileNamePrivate = "demo_json_keyPRI.txt";

	keymaker(cryptoContext, keyFileName);

	std::vector<int64_t> vectorOfInts1 = {3,1,4,2,1,1,0,1,0,0,0,0};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
	std::vector<int64_t> vectorOfInts2 = {1,1,1,0,1,1,0,1,0,0,0,0};
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

	string ciphertextFileName1 = "ciphertext1.txt";
	string ciphertextFileName2 = "ciphertext2.txt";

	encrypter(cryptoContext, plaintext1, keyFileNamePublic, ciphertextFileName1);
	encrypter(cryptoContext, plaintext2, keyFileNamePublic, ciphertextFileName2);
	
	Plaintext plaintext1_dec;
	Plaintext plaintext2_dec;

	plaintext1_dec = decrypter(cryptoContext, ciphertextFileName1, keyFileNamePrivate);
	plaintext2_dec = decrypter(cryptoContext, ciphertextFileName2, keyFileNamePrivate);

	plaintext1_dec->SetLength(plaintext1->GetLength());
	plaintext2_dec->SetLength(plaintext2->GetLength());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintext1_dec << endl;
	cout << plaintext2_dec << endl;

	return 0;
}
