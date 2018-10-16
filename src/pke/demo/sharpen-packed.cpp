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
 /*
BFV RNS testing programs
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

void Sharpen();
void KeyGen(size_t size);
void Encrypt(size_t size);
void Evaluate(size_t size);
void Decrypt(size_t size);

int main(int argc, char **argv) {

	static int operation_flag;
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
		/* These options don�t set a flag.
		   We distinguish them by their indices. */
		{"size",  	required_argument, 			0, 's'},
		{"help",    no_argument, 0, 'h'},
		{0, 0, 0, 0}
	  };
	/* getopt_long stores the option index here. */
	int option_index = 0;

	size_t size = 0;

	while ((opt = getopt_long(argc, argv, "s:h", long_options, &option_index)) != -1) {
		switch (opt)
		{
			case 0:
				if (long_options[option_index].flag != 0)
					break;
				break;
			case 's':
				size = stoi(optarg);
				break;
			case 'h':
			default: /* '?' */
			  std::cerr<< "Usage: "<<argv[0]<<" <arguments> " <<std::endl
				   << "arguments:" <<std::endl
				   << "  --run simple run w/o serialization" <<std::endl
				   << "  --keygen --encrypt --evaluate --decrypt operation to run" <<std::endl
				   << "  -s --size size of the image"  <<std::endl
				   << "  -h --help prints this message" <<std::endl;
			  exit(EXIT_FAILURE);
		}
	}

	switch(operation_flag)
	{
		case 0:
			Sharpen();
			break;
		case 1:
			KeyGen(size);
			break;
		case 2:
			Encrypt(size);
			break;
		case 3:
			Evaluate(size);
			break;
		case 4:
			Decrypt(size);
			break;
		default:
			exit(EXIT_FAILURE);
	}

	//Sharpen();

	//cin.get();
	return 0;
}

#define PROFILE

CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName)
{

	std::cout << "Deserializing the crypto context...";

	Serialized	ccSer;
	if (SerializableHelper::ReadSerializationFromFile(ccFileName, &ccSer) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);

	std::cout << "Completed" << std::endl;

	return cc;
}


CryptoContext<DCRTPoly> DeserializeContextWithEvalKeys(const string& ccFileName, const string& eaFileName)
{

	std::cout << "Deserializing the crypto context...";

	Serialized	ccSer, eaSer;
	if (SerializableHelper::ReadSerializationFromFile(ccFileName, &ccSer) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	if (SerializableHelper::ReadSerializationFromFile(eaFileName, &eaSer) == false) {
		cerr << "Could not read the eval automorphism key file" << endl;
		return 0;
	}

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);

	if( cc->DeserializeEvalAutomorphismKey(eaSer) == false ) {
		cerr << "Could not deserialize the eval automorphism key file" << endl;
		return 0;
	}

	std::cout << "Completed" << std::endl;

	return cc;

}

void KeyGen(size_t size) {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeKeyGen(0.0), timeSer(0.0), timeTotal(0.0);

	usint ptm = 65537;
	double sigma = 3.19;
	double rootHermiteFactor = 1.004;

	std::cout << "Generating parameters...";

	EncodingParams encodingParams(new EncodingParamsImpl(ptm));

	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			encodingParams, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED,2,30,60);

	uint32_t m = cryptoContext->GetCyclotomicOrder();
	PackedEncoding::SetParams(m, encodingParams);
	uint32_t batchSize = m/4;
	encodingParams->SetBatchSize(batchSize);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB() << std::endl;

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "Completed" << std::endl;

	std::cout << "Generating keys...";

	// Key generation
	LPKeyPair<DCRTPoly> kp;

	TIC(t1);

	kp = cryptoContext->KeyGen();

	timeKeyGen = TOC(t1);

	// Read the image file
	int width, height, bpp;
	string path = "demoData/Baboon" + to_string(size) + ".png";
	const char *pathc = path.c_str();

	/*unsigned char* data =*/ stbi_load( pathc, &width, &height, &bpp, 1 );

	// Rotations we are supporting
	vector<int32_t> indexList = {-1-width,-width,-width+1,-1,1,width-1,width,width+1};

	TIC(t1);
	cryptoContext->EvalAtIndexKeyGen(kp.secretKey,indexList);
	timeKeyGen += TOC(t1);

	std::cout << "Completed" << std::endl;

	TIC(t1);

	std::cout << "Serializing crypto context...";

	Serialized ctxt;

	if (cryptoContext->Serialize(&ctxt)) {
		if (!SerializableHelper::WriteSerializationToFile(ctxt, "demoData/cryptocontext.txt")) {
			cerr << "Error writing serialization of the crypto context to cryptocontext.txt" << endl;
			return;
		}
	}
	else {
		cerr << "Error serializing the crypto context" << endl;
		return;
	}

	std::cout << "Completed" << std::endl;

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

	std::cout << "Serializing eval automorphism keys...";

	Serialized eaKeys;

	if (cryptoContext->SerializeEvalAutomorphismKey(&eaKeys)) {
		if (!SerializableHelper::WriteSerializationToFile(eaKeys, "demoData/EVALAUTO.txt")) {
			cerr << "Error writing serialization of the eval automorphism keys" << endl;
			return;
		}
	}
	else {
		cerr << "Error serializing eval automorphism key" << endl;
		return;
	}

	std::cout << "Completed" << std::endl;

	timeSer = TOC(t1);

	timeTotal = TOC(t_total);

	std::cout << "\nTiming Summary" << std::endl;
	std::cout << "Key generation time:        " << "\t" << timeKeyGen << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Encrypt(size_t size) {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeEnc(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

	CryptoContext<DCRTPoly> cryptoContext = DeserializeContext("demoData/cryptocontext.txt");

	const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cryptoContext->GetCryptoParameters();
	const auto encodingParams = cryptoParams->GetEncodingParams();
	uint32_t batchSize = encodingParams->GetBatchSize();

	string pubKeyLoc = "demoData/PUB.txt";
	Serialized kser;
	if(SerializableHelper::ReadSerializationFromFile(pubKeyLoc, &kser) == false) {
		cerr << "Could not read public key" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPublicKey<DCRTPoly> pk = cryptoContext->deserializePublicKey(kser);

	timeSer = TOC(t1);

	// Read the image file
	int width, height, bpp;
	string path = "demoData/Baboon" + to_string(size) + ".png";
	const char *pathc = path.c_str();

	unsigned char* data = stbi_load( pathc, &width, &height, &bpp, 1 );

	vector<Plaintext> plaintext;

	vector<uint64_t> ptxtVector(batchSize);
	vector<uint64_t> ptxtVectorTemp(batchSize);

	size_t counter = 0;

	size_t slack = 0;

	for(int i = 0; i < height; i++)
	{
		std::cout << " [ ";
		for(int k = 0; k < width; k++) {
			std::cout << (unsigned int)(unsigned char)data[i*width+k] << " ";
			ptxtVector[(i*width+k)%batchSize] = (unsigned int)(unsigned char)data[i*width+k];
			counter++;
			if (((i*width+k+slack)%batchSize==0)&&(i+k)>0) {
				plaintext.push_back(cryptoContext->MakePackedPlaintext(ptxtVector));
				ptxtVectorTemp = std::vector<uint64_t>(batchSize);
				for (int j = 0; j < 2*width; j++)
					ptxtVectorTemp[j] = ptxtVector[batchSize-2*width+j];
				slack += 2*width;
				ptxtVector = ptxtVectorTemp;
				counter = 0;
			}
		}
		std::cout << " ] " << std::endl;
	}

	if (counter > 0)
		plaintext.push_back(cryptoContext->MakePackedPlaintext(ptxtVector));

	vector<Ciphertext<DCRTPoly>> image(plaintext.size());

	for(size_t i = 0; i < plaintext.size(); i++){

		TIC(t1);
		image[i] = cryptoContext->Encrypt(pk, plaintext[i]);
		timeEnc += TOC(t1);

		TIC(t1);

		string ciphertextname ="demoData/ciphertext-" + to_string(i+1) + ".txt";
		ofstream ctSer(ciphertextname, ios::binary);

		if (!ctSer.is_open()) {
			cerr << "could not open output file " << ciphertextname << endl;
			return;
		}

		Serialized cSer;
		if (image[i]->Serialize(&cSer)) {
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

	timeTotal = TOC(t_total);

	std::cout << "\nTiming Summary" << std::endl;
	std::cout << "Encryption time:        " << "\t" << timeEnc << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Evaluate(size_t size)
{

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeEval(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

    CryptoContext<DCRTPoly> cryptoContext = DeserializeContextWithEvalKeys("demoData/cryptocontext.txt","demoData/EVALAUTO.txt");

	const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cryptoContext->GetCryptoParameters();
	const auto encodingParams = cryptoParams->GetEncodingParams();
	int batchSize = encodingParams->GetBatchSize();

	int height = size;
	int width = size;

    int ciphertextCount;

    if (width*height < batchSize)
    	ciphertextCount = 1;
    else
    	ciphertextCount = ceil((double)batchSize/((double)(height+2)*width));

    std::cout << "Deserializing ciphertexts..." ;

    vector<Ciphertext<DCRTPoly>> image(ciphertextCount);

	for(int i = 0; i < ciphertextCount; i++)
	{

		string ciphertextname = "demoData/ciphertext-" + to_string(i+1) + ".txt";

		Serialized kser;
		if(SerializableHelper::ReadSerializationFromFile(ciphertextname, &kser) == false) {
				cerr << "Could not read ciphertext" << endl;
				return;
			}

		Ciphertext<DCRTPoly> ct = cryptoContext->deserializeCiphertext(kser);
		if(ct == NULL) {
			cerr << "Could not deserialize ciphertext" << endl;
			return;
		}
		else{
			image[i] = ct;
		}

	}

	std::cout << "Completed" << std::endl;

	timeSer = TOC(t1);

	std::cout << "Computing..." ;

	vector<int32_t> indexList = {-1-width,-width,-width+1,-1,1,width-1,width,width+1};

	TIC(t1);

	vector<uint64_t> eight(batchSize,8);
	Plaintext ptxtEight = cryptoContext->MakePackedPlaintext(eight);

	vector<uint64_t> two(batchSize,2);
	Plaintext ptxtTwo = cryptoContext->MakePackedPlaintext(two);

	vector<uint64_t> one(batchSize,1);
	Plaintext ptxtOne = cryptoContext->MakePackedPlaintext(one);

	vector<uint64_t> mask(batchSize);
	for (int i=0; i < batchSize; i++)
	{
		if ((i>width)&&(i<batchSize-width)&&(i%width!=0)&&(i%width!=width-1))
			mask[i]=1;
	}
	Plaintext ptxtMask = cryptoContext->MakePackedPlaintext(mask);

	vector<Ciphertext<DCRTPoly>> pixel_value(image.size());
	vector<Ciphertext<DCRTPoly>> image2(image.size());

	for (size_t k = 0; k < image.size(); k++) {
		for(size_t i = 0; i < indexList.size(); i++) {
			if (i == 0) {
				pixel_value[k] = cryptoContext->EvalAtIndex(image[k],indexList[i]);
			}
			else
				pixel_value[k] = cryptoContext->EvalAdd(pixel_value[k],cryptoContext->EvalAtIndex(image[k],indexList[i]));
		}
		pixel_value[k] = cryptoContext->EvalSub(pixel_value[k],cryptoContext->EvalMult(image[k],ptxtEight));
		pixel_value[k] = cryptoContext->EvalMult(pixel_value[k],ptxtMask);
		image2[k] = cryptoContext->EvalMult(image[k],ptxtTwo);
		image2[k] = cryptoContext->EvalAdd(image2[k],ptxtOne);
		image2[k] = cryptoContext->EvalSub(image2[k],pixel_value[k]);
	}

	timeEval = TOC(t1);

	std::cout << "Completed" << std::endl;

	std::cout << "Serializing the results..." ;

	TIC(t1);

	for(int i = 0; i < ciphertextCount; i++)
	{

		string ciphertextname ="demoData/ciphertext-result-" + to_string(i+1) + ".txt";
		ofstream ctSer(ciphertextname, ios::binary);

		if (!ctSer.is_open()) {
			cerr << "could not open output file " << ciphertextname << endl;
			return;
		}

		Serialized cSer;
		if (image2[i]->Serialize(&cSer)) {
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

	timeSer += TOC(t1);

	std::cout << "Completed" << std::endl;

	timeTotal = TOC(t_total);

	std::cout << "\nTiming Summary" << std::endl;
	std::cout << "Evaluation time:        " << "\t" << timeEval << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Decrypt(size_t size) {

	TimeVar t1, t_total; //for TIC TOC

	TIC(t_total);

	double timeDec(0.0), timeSer(0.0), timeTotal(0.0);

	TIC(t1);

	CryptoContext<DCRTPoly> cryptoContext = DeserializeContext("demoData/cryptocontext.txt");

	const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cryptoContext->GetCryptoParameters();
	const auto encodingParams = cryptoParams->GetEncodingParams();
	size_t batchSize = encodingParams->GetBatchSize();
	usint ptm = cryptoParams->GetPlaintextModulus();

	size_t height = size;
	size_t width = size;

	string privKeyLoc = "demoData/PRI.txt";
	Serialized kser;
	if(SerializableHelper::ReadSerializationFromFile(privKeyLoc, &kser) == false) {
		cerr << "Could not read privatekey" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPrivateKey<DCRTPoly> sk = cryptoContext->deserializeSecretKey(kser);

    int ciphertextCount;

    if (width*height < batchSize)
    		ciphertextCount = 1;
    else
    		ciphertextCount = ceil((double)batchSize/((double)(height+2)*width));

    std::cout << "Deserializing ciphertexts..." ;

    vector<Ciphertext<DCRTPoly>> image2(ciphertextCount);

	for(int i = 0; i < ciphertextCount; i++)
	{

		string ciphertextname = "demoData/ciphertext-result-" + to_string(i+1) + ".txt";

		Serialized kser;
		if(SerializableHelper::ReadSerializationFromFile(ciphertextname, &kser) == false) {
				cerr << "Could not read ciphertext" << endl;
				return;
			}

		Ciphertext<DCRTPoly> ct = cryptoContext->deserializeCiphertext(kser);
		if(ct == NULL) {
			cerr << "Could not deserialize ciphertext" << endl;
			return;
		}
		else{
			image2[i] = ct;
		}

	}

	std::cout << "Completed" << std::endl;

	timeSer = TOC(t1);

    std::cout << "Decrypting..." ;

   	vector<Plaintext> result(image2.size());

	TIC(t1);

	for(size_t i = 0; i < image2.size(); i++)
	{
		cryptoContext->Decrypt(sk, image2[i],&result[i]);
	}

	timeDec = TOC(t1);

	std::cout << "Completed" << std::endl;

	std::cout << "The result is" << std::endl;

	usint half = ptm >> 1;
	for(size_t i = 0; i < result.size(); i++)
	{
		vector<uint64_t> vectorRes = result[i]->GetPackedValue();

		std::cout << " [ ";
		for(size_t k = 0; k < std::min(batchSize,width*height); k++) {
			if (vectorRes[k] > half )
				std::cout << std::floor((int)(vectorRes[k]-ptm)/2) << " ";
			else
				std::cout << std::floor(vectorRes[k]/2) << " ";
		}
		std::cout << " ] " << std::endl;
	}

	timeTotal = TOC(t_total);

	string path = "demoData/Baboon" + to_string(size) + "OUT.png";
	const char *pathc = path.c_str();
	unsigned char *data = new unsigned char[height*width];
	for(size_t i = 0; i < height; i++)
	{
		vector<uint64_t> vectorRes = result[i]->GetPackedValue();
		for(size_t k = 0; k < width; k++) {
			if( vectorRes[k] > half )
				data[i*width + k] = std::floor((int)(vectorRes[k]-ptm)/2);
			else
				data[i*width + k] = std::floor(vectorRes[k]/2);
		}
	}

//	for(int i = 0; i < height; i++)
//	{
//		std::cout << " [ ";
//		for(int k = 0; k < width; k++) {
//			std::cout << (unsigned int)(unsigned char)data[i*width+k] << " ";
//			plaintext[i].push_back(cryptoContext->MakeFractionalPlaintext( (unsigned int)(unsigned char)data[i*width + k]));
//		}
//		std::cout << " ] " << std::endl;
//	}
	stbi_write_png( pathc, width, height, 1, data, width*1 );
	delete[] data;

	std::cout << "Number of ciphertexts: " << result.size() << std::endl;

	std::cout << "\nTiming Summary" << std::endl;
	std::cout << "Decryption time:        " << "\t" << timeDec << " ms" << std::endl;
	std::cout << "Serialization time: " << "\t" << timeSer << " ms" << std::endl;
	std::cout << "Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

}

void Sharpen() {

	std::cout << "\n===========SHARPENING DEMO===============: " << std::endl;

	std::cout << "\nThis code demonstrates the implementation of 8-neighbor Laplacian image sharpening algorithm using BFVrns. " << std::endl;

	usint ptm = 65537;
	double sigma = 3.19;
	double rootHermiteFactor = 1.004;

	EncodingParams encodingParams(new EncodingParamsImpl(ptm));

	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			encodingParams, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED,2,30,60);

	uint32_t m = cryptoContext->GetCyclotomicOrder();
	PackedEncoding::SetParams(m, encodingParams);
	uint32_t batchSize = m/4;
	encodingParams->SetBatchSize(batchSize);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB() << std::endl;

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	// Key generation
	LPKeyPair<DCRTPoly> keyPair;

	keyPair = cryptoContext->KeyGen();

	// Read the image file
	int width, height, bpp;
	unsigned char* data = stbi_load( "demoData/Baboon8.png", &width, &height, &bpp, 1 );

	// Rotations we are supporting
	vector<int32_t> indexList = {-1-width,-width,-width+1,-1,1,width-1,width,width+1};
	cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey,indexList);

	vector<Plaintext> plaintext;

	vector<uint64_t> ptxtVector(batchSize);
	vector<uint64_t> ptxtVectorTemp(batchSize);

	size_t counter = 0;

	size_t slack = 0;

	for(int i = 0; i < height; i++)
	{
		std::cout << " [ ";
		for(int k = 0; k < width; k++) {
			std::cout << (unsigned int)(unsigned char)data[i*width+k] << " ";
			ptxtVector[(i*width+k)%batchSize] = (unsigned int)(unsigned char)data[i*width+k];
			counter++;
			if (((i*width+k+slack)%batchSize==0)&&(i+k)>0) {
				plaintext.push_back(cryptoContext->MakePackedPlaintext(ptxtVector));
				ptxtVectorTemp = std::vector<uint64_t>(batchSize);
				for (int j = 0; j < 2*width; j++)
					ptxtVectorTemp[j] = ptxtVector[batchSize-2*width+j];
				slack += 2*width;
				ptxtVector = ptxtVectorTemp;
				counter = 0;
			}
		}
		std::cout << " ] " << std::endl;
	}

	if (counter > 0)
		plaintext.push_back(cryptoContext->MakePackedPlaintext(ptxtVector));

	vector<Ciphertext<DCRTPoly>> image(plaintext.size());

	for(size_t i = 0; i < plaintext.size(); i++)
		image[i] = cryptoContext->Encrypt(keyPair.publicKey, plaintext[i]);

	vector<uint64_t> eight(batchSize,8);
	Plaintext ptxtEight = cryptoContext->MakePackedPlaintext(eight);

	vector<uint64_t> two(batchSize,2);
	Plaintext ptxtTwo = cryptoContext->MakePackedPlaintext(two);

	vector<uint64_t> one(batchSize,1);
	Plaintext ptxtOne = cryptoContext->MakePackedPlaintext(one);

	vector<uint64_t> mask(batchSize);
	for (size_t i = 0; i < batchSize; i++)
	{
		if ((i>(size_t)width)&&(i<batchSize-width)&&(i%width!=0)&&(i%width!=(size_t)width-1))
			mask[i]=1;
	}
	Plaintext ptxtMask = cryptoContext->MakePackedPlaintext(mask);

	vector<Ciphertext<DCRTPoly>> pixel_value(image.size());
	vector<Ciphertext<DCRTPoly>> image2(image.size());

	for (size_t k = 0; k < image.size(); k++) {
		for(size_t i = 0; i < indexList.size(); i++) {
			if (i == 0) {
				pixel_value[k] = cryptoContext->EvalAtIndex(image[k],indexList[i]);
			}
			else
				pixel_value[k] = cryptoContext->EvalAdd(pixel_value[k],cryptoContext->EvalAtIndex(image[k],indexList[i]));
		}
		pixel_value[k] = cryptoContext->EvalSub(pixel_value[k],cryptoContext->EvalMult(image[k],ptxtEight));
		pixel_value[k] = cryptoContext->EvalMult(pixel_value[k],ptxtMask);
		image2[k] = cryptoContext->EvalMult(image[k],ptxtTwo);
		image2[k] = cryptoContext->EvalAdd(image2[k],ptxtOne);
		image2[k] = cryptoContext->EvalSub(image2[k],pixel_value[k]);
	}

	vector<Plaintext> result(image2.size());

	for(size_t i = 0; i < image2.size(); i++)
	{
		cryptoContext->Decrypt(keyPair.secretKey, image2[i],&result[i]);
	}

	std::cout << "The result is" << std::endl;

	for(size_t i = 0; i < result.size(); i++)
	{
		vector<uint64_t> vectorRes = result[i]->GetPackedValue();

		usint half = ptm >> 1;

		std::cout << " [ ";
		for(size_t k = 0; k < (size_t)std::min((int)batchSize,width*height); k++) {
			if (vectorRes[k] > half )
				std::cout << std::floor((int)(vectorRes[k]-ptm)/2) << " ";
			else
				std::cout << std::floor(vectorRes[k]/2) << " ";
		}
		std::cout << " ] " << std::endl;
	}

	std::cout << "Number of ciphertexts: " << result.size() << std::endl;

}
