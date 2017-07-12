/*
 * @file 
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

//static const usint ORDER = 2048;
//static const usint PTM = 256;
//double currentDateTime();

void usage()
{
	cout << "No args are needed." << endl;
}

int main(int argc, char *argv[]) {

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////

	//Generate parameters.
	double diff, start, finish;

	while( argc-- > 1 ) {
		string arg(*++argv);

		if( arg == "-help" || arg == "-?" ) {
			usage();
			return 0;
		}
		else if( arg[0] == '-' ) {
			usage();
			return(0);
		}
	}

	std::cout << "Choose parameter set: ";
	CryptoContextHelper::printAllParmSetNames(std::cout);

	string input;
	std::cin >> input;

	start = currentDateTime();

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(input);
	if( !cc ) {
		cout << "Error on " << input << endl;
		return 0;
	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Param generation time: " << "\t" << diff << " ms" << endl;

	//shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(ORDER, PTM);

	//Turn on features
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(PRE);
	cc->Enable(MULTIPARTY);


	std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();
	
	// Initialize Public Key Containers
	LPKeyPair<Poly> kp1;
	LPKeyPair<Poly> kp2;
	LPKeyPair<Poly> kp3;

	LPKeyPair<Poly> kpMultiparty;

	shared_ptr<LPEvalKey<Poly>> evalKey1;
	shared_ptr<LPEvalKey<Poly>> evalKey2;
	shared_ptr<LPEvalKey<Poly>> evalKey3;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	kp1 = cc->KeyGen();
	kp2 = cc->MultipartyKeyGen(kp1.publicKey);
	kp3 = cc->MultipartyKeyGen(kp1.publicKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !kp1.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}
	if( !kp2.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}
	if( !kp3.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	std::cout << "Generating a Multiparty key..." << std::endl;

	start = currentDateTime();


	vector<shared_ptr<LPPrivateKey<Poly>>> secretKeys;
	secretKeys.push_back(kp1.secretKey);
	secretKeys.push_back(kp2.secretKey);
	secretKeys.push_back(kp3.secretKey);

	kpMultiparty = cc->MultipartyKeyGen(secretKeys);	// This is the same core key generation operation.

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !kpMultiparty.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;

	bool flagBV = true;

	if ((input.find("BV") == string::npos) && (input.find("FV") == string::npos))
		flagBV = false;

	start = currentDateTime();

	if (flagBV) { 
		evalKey1 = cc->ReKeyGen(kpMultiparty.secretKey, kp1.secretKey);
		evalKey2 = cc->ReKeyGen(kpMultiparty.secretKey, kp2.secretKey);
		evalKey3 = cc->ReKeyGen(kpMultiparty.secretKey, kp3.secretKey);
	}
	else
	{
		evalKey1 = cc->ReKeyGen(kpMultiparty.publicKey, kp1.secretKey);
		evalKey2 = cc->ReKeyGen(kpMultiparty.publicKey, kp2.secretKey);
		evalKey3 = cc->ReKeyGen(kpMultiparty.publicKey, kp3.secretKey);
	}

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	


	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////
/*
	std::vector<uint32_t> vectorOfInts1 = {2,2,2,2,2,2,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts2 = {3,3,3,3,3,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {1,1,1,1,0,0,0,0,0,0,0,0};
*/
	std::vector<uint32_t> vectorOfInts1 = {1,1,1,1,1,1,1,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts2 = {1,0,0,1,1,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {1,1,1,1,0,0,0,0,0,0,0,0};

	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);
	IntPlaintextEncoding plaintext3(vectorOfInts3);

	//std::vector<uint32_t> vectorOfIntsAdd = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3 };
	//IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext3;

	ciphertext1 = cc->Encrypt(kp1.publicKey, plaintext1);
	ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
	ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);
	
	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	// Re-Encryption
	////////////////////////////////////////////////////////////


	start = currentDateTime();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1New;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2New;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext3New;

	ciphertext1New = cc->ReEncrypt(evalKey1, ciphertext1);
	ciphertext2New = cc->ReEncrypt(evalKey2, ciphertext2);
	ciphertext3New = cc->ReEncrypt(evalKey3, ciphertext3);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Re-Encryption time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	// EvalAdd Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextAddNew12;
	shared_ptr<Ciphertext<Poly>> ciphertextAddNew123;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextAddVectNew;

	start = currentDateTime();

	ciphertextAddNew12 = cc->EvalAdd(ciphertext1New[0],ciphertext2New[0]);
	ciphertextAddNew123 = cc->EvalAdd(ciphertextAddNew12,ciphertext3New[0]);

	ciphertextAddVectNew.push_back(ciphertextAddNew123);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Re-Encrypted Data Evaluation time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAddNew;

	start = currentDateTime();

	cc->Decrypt(kpMultiparty.secretKey, ciphertextAddVectNew, &plaintextAddNew);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextAddNew.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	cout << "\n Resulting Added Plaintext with Re-Encryption: \n";
	cout << plaintextAddNew << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data with Multiparty
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAddNew1;
	IntPlaintextEncoding plaintextAddNew2;
	IntPlaintextEncoding plaintextAddNew3;

	Poly partialPlaintext1;
	Poly partialPlaintext2;
	Poly partialPlaintext3;
	//IntPlaintextEncoding plaintextAddNewFinal;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextPartial1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextPartial2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextPartial3;

	IntPlaintextEncoding plaintextMultipartyNew;

	const shared_ptr<LPCryptoParameters<Poly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
	const shared_ptr<typename Poly::Params> elementParams = cryptoParams->GetElementParams();

	start = currentDateTime();

	ciphertextPartial1 = cc->MultipartyDecryptLead(kp1.secretKey, ciphertextAddVectNew);
	ciphertextPartial2 = cc->MultipartyDecryptMain(kp2.secretKey, ciphertextAddVectNew);
	ciphertextPartial3 = cc->MultipartyDecryptMain(kp3.secretKey, ciphertextAddVectNew);

	vector<vector<shared_ptr<Ciphertext<Poly>>>> partialCiphertextVec;
	partialCiphertextVec.push_back(ciphertextPartial1);
	partialCiphertextVec.push_back(ciphertextPartial2);
	partialCiphertextVec.push_back(ciphertextPartial3);

	cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	cout << "\n Original Plaintext: \n" << endl;
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	plaintextMultipartyNew.resize(plaintext1.size());

	cout << "\n Resulting Fused Plaintext with Re-Encryption: \n" << endl;
	cout << plaintextMultipartyNew << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// Done
	////////////////////////////////////////////////////////////

	std::cout << "Execution Completed. Press any key to continue." << std::endl;

	std::cin.get();

	return 0;
}
