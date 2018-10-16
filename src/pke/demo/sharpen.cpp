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
#include <limits>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "palisade.h"

#include "cryptocontexthelper.h"
#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

#include <iterator>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

void Sharpen(CryptoContext<DCRTPoly> cc, size_t size, int parCase);
void KeyGen(CryptoContext<DCRTPoly> cc);
void Encrypt(CryptoContext<DCRTPoly> cc, size_t size);
void Evaluate(CryptoContext<DCRTPoly> cc, size_t size);
void Decrypt(CryptoContext<DCRTPoly> cc, size_t size);

#define PROFILE

CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName) {

	std::cout << "Deserializing the crypto context...";

	Serialized	ccSer;
	if (SerializableHelper::ReadSerializationFromFile(ccFileName, &ccSer) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);

	cc->Enable(ENCRYPTION|SHE);

	std::cout << "Completed" << std::endl;

	return cc;
}


void DeserializeEvalKeys(CryptoContext<DCRTPoly> cc, const string& emFileName)
{

	Serialized	emSer, esSer;

	if (SerializableHelper::ReadSerializationFromFile(emFileName, &emSer) == false) {
		cerr << "Could not read the eval mult key file" << endl;
		return;
	}

	if( cc->DeserializeEvalMultKey(emSer) == false ) {
		cerr << "Could not deserialize the eval mult key file" << endl;
		return;
	}

	std::cout << "Completed" << std::endl;
}

void usage(const string& msg)
{
	if( msg.length() > 0 )
		cerr << msg << endl;
	std::cerr<< "Usage: "<<std::endl
			<< "arguments:" <<std::endl
			<< "  --run simple run w/o serialization" <<std::endl
			<< "  --keygen --encrypt --evaluate --decrypt operation to run" <<std::endl
			<< "  -d --deployment SPEC " << endl
			<< "  -s --size SIZE size of the image"  <<std::endl
			<< "  -h --help prints this message" <<std::endl;
	exit(EXIT_FAILURE);
}

string profile;

float parCases[][6] = {
		{0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0},
		{0, 1, 0, 0, 0, 0},
		{0, 0, 0, 0, 1, 0},
		{0, 0, 0, 0, 0, 1},
		{0, 0, 0, 0, .5, .5},
		{.5, .5, 0, 0, 0, 0}
};

const int OutRow = 0;
const int OutCol = 1;
const int InRow = 2;
const int InCol = 3;

int maxThreads;

int main(int argc, char **argv) {

	PalisadeParallelControls.Enable();
	maxThreads = omp_get_max_threads();

	static int operation_flag = 0;
	int opt;

	static struct option long_options[] =
	{
			/* These options set a flag. */
			//{"verbose", no_argument,       &verbose_flag, 1},
			//{"brief",   no_argument,       &verbose_flag, 0},
			{"run", 	no_argument,       &operation_flag, 0},
			{"keygen", 	no_argument,       &operation_flag, 1},
			{"encrypt",   no_argument,     &operation_flag, 2},
			{"evaluate",   no_argument,     &operation_flag, 3},
			{"decrypt",   no_argument,     &operation_flag, 4},

			{"deployment",	no_argument,	0, 'd'},
			{"size",			required_argument,	0, 's'},
			{"help",			no_argument,			0, 'h'},
			{0, 0, 0, 0}
	};
	/* getopt_long stores the option index here. */
	int option_index = 0;

	size_t size = 0;

	while ((opt = getopt_long(argc, argv, "s:d:h", long_options, &option_index)) != -1) {
		switch (opt)
		{
		case 0:
			if (long_options[option_index].flag != 0)
				break;
			break;
		case 's':
			size = stoi(optarg);
			break;
		case 'd':
			profile = string(optarg);
			break;
		case 'h':
		default: /* '?' */
			usage("");
		}
	}

	if( size == 0 ) //|| profile.length() == 0 )
		usage("");

	//auto cc = DeserializeContext(profile);
	usint ptm = 8192;
	double sigma = 3.19;
	double rootHermiteFactor = 1.004;

	std::cout << "Generating parameters...";

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED,3,30,60);

	std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB() << std::endl;

	// enable features that you wish to use
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	std::cout << "Completed" << std::endl;

	switch(operation_flag)
	{
	case 0:
		for( int parCase = 0; parCase <= 4; parCase++ ) {
			cout << "RUNNING CASE " << parCase << endl;
			Sharpen(cc, size, parCase);
		}
		break;
	case 1:
		KeyGen(cc);
		break;
	case 2:
		Encrypt(cc, size);
		break;
	case 3:
		Evaluate(cc, size);
		break;
	case 4:
		Decrypt(cc, size);
		break;
	default:
		exit(EXIT_FAILURE);
	}

	//Sharpen();

	//cin.get();
	return 0;
}

void SaveSharpened(string profile, size_t size, int width, int height, unsigned char* data) {
	string path = "Baboon" + to_string(size) + "-" + profile + "OUT.png";
	const char *pathc = path.c_str();
	stbi_write_png(pathc, width, height, 1, data, width * 1);
}

void KeyGen(CryptoContext<DCRTPoly> cc) {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeKeyGen(0.0), timeSer(0.0), timeTotal(0.0);

	std::cout << "Generating keys...";

	// Key generation
	LPKeyPair<DCRTPoly> kp;

	TIC(t1);

	kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);

	timeKeyGen = TOC(t1);

	std::cout << "Completed" << std::endl;

	TIC(t1);

	std::cout << "Serializing private and public keys...";

	if(kp.publicKey && kp.secretKey) {
		Serialized pubK, privK;

		if(kp.publicKey->Serialize(&pubK)) {
			if(!SerializableHelper::WriteSerializationToFile(pubK, "demoData/PUB.txt")) {
				cerr << "Error writing serialization of public key" << endl;
				return;
			}
		} else {
			cerr << "Error serializing public key" << endl;
			return;
		}

		if(kp.secretKey->Serialize(&privK)) {
			if(!SerializableHelper::WriteSerializationToFile(privK, "demoData/PRI.txt")) {
				cerr << "Error writing serialization of private key" << endl;
				return;
			}
		} else {
			cerr << "Error serializing private key" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating keys" << endl;
	}

	std::cout << "Completed" << std::endl;

	std::cout << "Serializing eval mult key...";

	Serialized emKeys;

	if (cc->SerializeEvalMultKey(&emKeys)) {
		if (!SerializableHelper::WriteSerializationToFile(emKeys, "demoData/EVALMULT.txt")) {
			cerr << "Error writing serialization of the eval mult key" << endl;
			return;
		}
	}
	else {
		cerr << "Error serializing eval mult key" << endl;
		return;
	}

	std::cout << "Completed" << std::endl;

	timeSer = TOC(t1);

	timeTotal = TOC(t_total);

	std::cout << "\nKeyGen Timing Summary" << std::endl;
	std::cout << "Key generation time:        " << "\t" << timeKeyGen << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Encrypt(CryptoContext<DCRTPoly> cc, size_t size) {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeEnc(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

	string pubKeyLoc = "demoData/PUB.txt";
	Serialized kser;
	if(SerializableHelper::ReadSerializationFromFile(pubKeyLoc, &kser) == false) {
		cerr << "Could not read public key" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPublicKey<DCRTPoly> pk = cc->deserializePublicKey(kser);

	timeSer = TOC(t1);

	// Read the image file
	int width, height, bpp;

	string path = "demoData/Baboon" + to_string(size) + ".png";
	const char *pathc = path.c_str();

	unsigned char* data = stbi_load( pathc, &width, &height, &bpp, 1 );
	if( data == NULL ) {
		cerr << "There's no file for that size" << endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "Constructing plaintext" << std::endl;

	vector<vector<Plaintext>> plaintext(height);

	for(int i = 0; i < height; i++)
	{
		//		std::cout << " [ ";
		for(int k = 0; k < width; k++) {
			//			std::cout << (unsigned int)(unsigned char)data[i*width+k] << " ";
			plaintext[i].push_back(cc->MakeFractionalPlaintext( (unsigned int)data[i*width + k]));
		}
		//		std::cout << " ] " << std::endl;
	}

	vector<vector<Ciphertext<DCRTPoly>>> image(height);

	std::cout << "Encrypting..." << std::flush;
	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {
			TIC(t1);
			imageRow[k] = cc->Encrypt(pk, plaintext[i][k]);
			timeEnc += TOC(t1);

			TIC(t1);
			string ciphertextname ="demoData/ciphertext-" + to_string(i+1) + "-" + to_string(k+1) + ".txt";
			ofstream ctSer(ciphertextname, ios::binary);

			if (!ctSer.is_open()) {
				cerr << "could not open output file " << ciphertextname << endl;
				return;
			}

			Serialized cSer;
			if (imageRow[k]->Serialize(&cSer)) {
				if (!SerializableHelper::WriteSerializationToFile(cSer, ciphertextname)) {
					cerr << "Error writing serialization of ciphertext to " + ciphertextname << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing ciphertext" << endl;
				return;
			}

			timeSer += TOC(t1);
		}
		image[i] = imageRow;
	}

	timeTotal = TOC(t_total);
	std::cout << "...done" << std::endl;

	std::cout << "\nEncryption Timing Summary" << std::endl;
	std::cout << "Encryption time:        " << "\t" << timeEnc << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Evaluate(CryptoContext<DCRTPoly> cc, size_t size)
{

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeEval(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

	DeserializeEvalKeys(cc, "demoData/EVALMULT.txt");

	int height = size;
	int width = size;

	size_t truncatedBits = 1;

	std::cout << "Deserializing ciphertexts..." << std::flush;

	vector<vector<Ciphertext<DCRTPoly>>> image(height);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {

			string ciphertextname = "demoData/ciphertext-" + to_string(i+1) + "-" + to_string(k+1) + ".txt";

			Serialized kser;
			if(SerializableHelper::ReadSerializationFromFile(ciphertextname, &kser) == false) {
				cerr << "Could not read ciphertext" << endl;
				return;
			}

			Ciphertext<DCRTPoly> ct = cc->deserializeCiphertext(kser);
			if(ct == NULL) {
				cerr << "Could not deserialize ciphertext" << endl;
				return;
			}
			else{
				imageRow[k] = ct;
			}
		}

		image[i] = imageRow;

	}

	std::cout << "...Done" << std::endl;

	timeSer = TOC(t1);

	std::cout << "Computing..." << std::flush;

	vector<vector<int>> weightsRaw = {{1, 1, 1}, {1, -8, 1}, {1, 1, 1}};

	vector<vector<Plaintext>> weight(weightsRaw.size());

	for(int i = 0; i < (int)weightsRaw.size(); i++)
	{
		for(int k = 0; k < (int)weightsRaw[0].size(); k++) {
			weight[i].push_back(cc->MakeFractionalPlaintext(weightsRaw[i][k]));
		}
	}

	vector<vector<Ciphertext<DCRTPoly>>> image2(image);

	TIC(t1);

	for(int x = 1; x < height-1; x++)
	{
		for(int y = 1; y < width-1; y++) {
			Ciphertext<DCRTPoly> pixel_value;
			for(int i = -1; i < 2; i++)
			{
				for(int j = -1; j < 2; j++) {
					if (pixel_value == NULL)
						pixel_value = cc->EvalMult(image[x+i][y+j],weight[i+1][j+1]);
					else
						pixel_value = cc->EvalAdd(pixel_value,cc->EvalMult(image[x+i][y+j],weight[i+1][j+1]));
				}
			}
			image2[x][y] = cc->EvalSub(image[x][y],cc->EvalRightShift(pixel_value,truncatedBits));

		}
	}

	timeEval = TOC(t1);

	std::cout << "...Done" << std::endl;

	std::cout << "Serializing the results..." << std::flush;

	TIC(t1);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {

			string ciphertextname ="demoData/ciphertext-result-" + to_string(i+1) + "-" + to_string(k+1) + ".txt";
			ofstream ctSer(ciphertextname, ios::binary);

			if (!ctSer.is_open()) {
				cerr << "could not open output file " << ciphertextname << endl;
				return;
			}

			Serialized cSer;
			if (image2[i][k]->Serialize(&cSer)) {
				if (!SerializableHelper::WriteSerializationToFile(cSer, ciphertextname)) {
					cerr << "Error writing serialization of ciphertext to " + ciphertextname << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing ciphertext" << endl;
				return;
			}
		}

	}

	timeSer += TOC(t1);

	std::cout << "...Done" << std::endl;

	timeTotal = TOC(t_total);

	std::cout << "\nEvaluation Timing Summary" << std::endl;
	std::cout << "Evaluation time:        " << "\t" << timeEval << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Decrypt(CryptoContext<DCRTPoly> cc, size_t size) {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeDec(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

	int height = size;
	int width = size;

	string privKeyLoc = "demoData/PRI.txt";
	Serialized kser;
	if(SerializableHelper::ReadSerializationFromFile(privKeyLoc, &kser) == false) {
		cerr << "Could not read privatekey" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPrivateKey<DCRTPoly> sk = cc->deserializeSecretKey(kser);

	std::cout << "Deserializing ciphertexts..." << std::flush;

	vector<vector<Ciphertext<DCRTPoly>>> image2(height);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {

			string ciphertextname = "demoData/ciphertext-result-" + to_string(i+1) + "-" + to_string(k+1) + ".txt";

			Serialized kser;
			if(SerializableHelper::ReadSerializationFromFile(ciphertextname, &kser) == false) {
				cerr << "Could not read ciphertext" << endl;
				return;
			}

			Ciphertext<DCRTPoly> ct = cc->deserializeCiphertext(kser);
			if(ct == NULL) {
				cerr << "Could not deserialize ciphertext" << endl;
				return;
			}
			else{
				imageRow[k] = ct;
			}
		}

		image2[i] = imageRow;

	}

	std::cout << "...Done" << std::endl;

	timeSer = TOC(t1);

	std::cout << "Decrypting..." << std::flush;

	vector<vector<Plaintext>> result(height);

	TIC(t1);

	for(int i = 0; i < height; i++)
	{
		result[i] = vector<Plaintext>(width);
		for(int k = 0; k < width; k++) {
			cc->Decrypt(sk, image2[i][k],&result[i][k]);
		}
	}

	timeDec = TOC(t1);

	std::cout << "...Done" << std::endl;

	unsigned char *data = new unsigned char[height*width];
	for(int i = 0; i < height; i++)
	{
		for(int k = 0; k < width; k++) {
			auto v = result[i][k]->GetIntegerValue();
			if( v < 0 ) v = 0;
			else if( v > 0xff ) v = 0xff;
			data[i*width + k] = v;
		}
	}

	SaveSharpened(profile, size, width, height, data);
	delete[] data;

	timeTotal = TOC(t_total);

	std::cout << "\nDecryption Timing Summary" << std::endl;
	std::cout << "Decryption time:        " << "\t" << timeDec << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

enum Stages {KEYGEN, ENCRYPT, EVALUATE, DECRYPT};

// This code demonstrates the implementation of 8-neighbor Laplacian image sharpening algorithm

void Sharpen(CryptoContext<DCRTPoly> cc, size_t size, int parCase) {

	TimeVar times[10], t_total; //for TIC TOC
	double timeResult[10];

	TIC(t_total);

	TIC(times[KEYGEN]);

	// Key generation
	LPKeyPair<DCRTPoly> keyPair;

	cout << "Generating keys..." << std::flush;
	keyPair = cc->KeyGen();
	cc->ClearEvalMultKeys();
	cc->EvalMultKeyGen(keyPair.secretKey);

	timeResult[KEYGEN] = TOC(times[KEYGEN]);

	size_t truncatedBits = 1;

	// Read the image file
	int width, height, bpp;

	string path = "demoData/Baboon" + to_string(size) + ".png";
	const char *pathc = path.c_str();

	unsigned char* data = stbi_load( pathc, &width, &height, &bpp, 1 );
	if( data == NULL ) {
		cerr << "There's no file for that size" << endl;
		exit(EXIT_FAILURE);
	}

	vector<vector<Plaintext>> plaintext(height);

	cout << endl << "Initializing plaintext..." << flush;
	for(int i = 0; i < height; i++)
	{
		for(int k = 0; k < width; k++) {
			plaintext[i].push_back(cc->MakeFractionalPlaintext( (unsigned int)(unsigned char)data[i*width + k]));
		}
	}

	delete[] data;

	cout << endl << "Encrypting..." << flush;
	TIC(times[ENCRYPT]);
	vector<vector<Ciphertext<DCRTPoly>>> image(height);

	for(int i = 0; i < height; i++)
	{
		vector<Ciphertext<DCRTPoly>> imageRow(width);
		for(int k = 0; k < width; k++) {
			imageRow[k] = cc->Encrypt(keyPair.publicKey, plaintext[i][k]);
		}
		image[i] = imageRow;
	}
	timeResult[ENCRYPT] = TOC(times[ENCRYPT]);

	cout << endl << "Calculating..." << flush;

	vector<vector<int>> weightsRaw = {{1, 1, 1}, {1, -8, 1}, {1, 1, 1}};

	vector<vector<Plaintext>> weight(weightsRaw.size());

	for(int i = 0; i < (int)weightsRaw.size(); i++)
	{
		for(int k = 0; k < (int)weightsRaw[0].size(); k++) {
			weight[i].push_back(cc->MakeFractionalPlaintext(weightsRaw[i][k]));
		}
	}

	TIC(times[EVALUATE]);
	vector<vector<Ciphertext<DCRTPoly>>> image2(image);

	omp_set_num_threads(maxThreads * parCases[parCase][OutRow]);
#pragma omp parallel for
	for(int x = 1; x < height-1; x++)
	{
		omp_set_num_threads(maxThreads * parCases[parCase][OutCol]);
#pragma omp parallel for
		for(int y = 1; y < width-1; y++) {
			Ciphertext<DCRTPoly> pixel_value;
			omp_set_num_threads(maxThreads * parCases[parCase][InRow]);
	#pragma omp parallel for
			for(int i = -1; i < 2; i++)
			{
				omp_set_num_threads(maxThreads * parCases[parCase][InCol]);
		#pragma omp parallel for
				for(int j = -1; j < 2; j++) {
					if (pixel_value == NULL)
						pixel_value = cc->EvalMult(image[x+i][y+j],weight[i+1][j+1]);
					else
						pixel_value = cc->EvalAdd(pixel_value,cc->EvalMult(image[x+i][y+j],weight[i+1][j+1]));
				}
			}
			image2[x][y] = cc->EvalSub(image[x][y],cc->EvalRightShift(pixel_value,truncatedBits));
		}
	}
	timeResult[EVALUATE] = TOC(times[EVALUATE]);

	cout << endl << "Decrypting..." << flush;
	TIC(times[DECRYPT]);
	vector<vector<Plaintext>> result(height);

	for(int i = 0; i < height; i++)
	{
		result[i] = vector<Plaintext>(width);
		for(int k = 0; k < width; k++) {
			cc->Decrypt(keyPair.secretKey, image2[i][k],&result[i][k]);
		}
	}
	timeResult[DECRYPT] = TOC(times[DECRYPT]);

	cout << endl;

	data = new unsigned char[height*width];
	for(int i = 0; i < height; i++)
	{
		for(int k = 0; k < width; k++) {
			auto v = result[i][k]->GetIntegerValue();
			if( v < 0 ) v = 0;
			else if( v > 0xff ) v = 0xff;
			data[i*width + k] = v;
		}
	}

	SaveSharpened(profile, size, width, height, data);
	delete[] data;

	cout << "Size " << size << " Case " << parCase << " KEYGEN: " << timeResult[KEYGEN] << "ms" << endl;
	cout << "Size " << size << " Case " << parCase << " ENCRYPT: " << timeResult[ENCRYPT] << "ms" << endl;
	cout << "Size " << size << " Case " << parCase << " EVALUATE: " << timeResult[EVALUATE] << "ms" << endl;
	cout << "Size " << size << " Case " << parCase << " DECRYPT: " << timeResult[DECRYPT] << "ms" << endl;

}

