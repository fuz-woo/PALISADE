/*
 * @file demo-cross-correlation.cpp Code that demonstrates the use of serialization, DCRT, arbitrary cyclotomics, and packed encoding for an application that computes cross-correlation using inner products.
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


#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"
#include "math/matrix.h"
#include "math/matrix.cpp"

using namespace std;
using namespace lbcrypto;

#include <iterator>

void KeyGen();
void Encrypt();
void Compute();
void Decrypt();
CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName);
NativeInteger CRTInterpolate(const std::vector<Plaintext> &crtVector);
template<typename T> ostream& operator<<(ostream& output, const vector<T>& vector);

// number of primitive prime plaintext moduli in the CRT representation of plaintext
const size_t SIZE = 3;
const size_t VECTORS = 30;
const std::string DATAFOLDER = "demoData";


int main(int argc, char* argv[]) {

	if (argc < 2) { // called with no arguments
		std::cout << "Usage is `" << argv[0] << " arg1 ' where: " << std::endl;
		std::cout << "  arg1 can be one of the following: keygen, encrypt, compute, or decrypt" << std::endl;
	}


	if (argc == 2) {

		if (std::string(argv[1]) == "keygen")
			KeyGen();
		else {
			if (std::string(argv[1]) == "encrypt")
				Encrypt();
			else if (std::string(argv[1]) == "compute")
				Compute();
			else if (std::string(argv[1]) == "decrypt")
				Decrypt();
			else {
				std::cerr << "the argument is invalid";
				return 1;
			}
		}
	}

	PackedEncoding::Destroy();

	return 0;
}


void KeyGen()
{

	for (size_t k = 0; k < SIZE; k++) {

		size_t batchSize = 1024;

		usint init_size = 3;
		usint dcrtBits = 24;
		usint dcrtBitsBig = 58;

		usint m;

		switch (k) {
		case 0:
			m = 1811;
			break;
		case 1:
			m = 1889;
			break;
		case 2:
			m = 1901;
			break;
		case 3:
			m = 1931;
			break;
		}

		PlaintextModulus p = 2 * m + 1;
		BigInteger modulusP(p);

		std::cout << "\nKEY GENERATION AND SERIALIZATION FOR p = " << p << "\n" << std::endl;

		usint mArb = 2 * m;
		usint mNTT = pow(2, ceil(log2(2 * m - 1)));

		// populate the towers for the small modulus

		vector<NativeInteger> init_moduli(init_size);
		vector<NativeInteger> init_rootsOfUnity(init_size);

		NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, mArb);
		init_moduli[0] = q;
		init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

		for (usint i = 1; i < init_size; i++) {
			q = lbcrypto::NextPrime(q, mArb);
			init_moduli[i] = q;
			init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		}

		// populate the towers for the big modulus

		vector<NativeInteger> init_moduli_NTT(init_size);
		vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

		q = FirstPrime<NativeInteger>(dcrtBitsBig, mNTT);
		init_moduli_NTT[0] = q;
		init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

		for (usint i = 1; i < init_size; i++) {
			q = lbcrypto::NextPrime(q, mNTT);
			init_moduli_NTT[i] = q;
			init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		}

		shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

		EncodingParams encodingParams(new EncodingParamsImpl(p));

		PackedEncoding::SetParams(m, encodingParams);
		encodingParams->SetBatchSize(batchSize);

		float stdDev = 4;

		CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGV(paramsDCRT, encodingParams, 24, stdDev);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		////////////////////////////////////////////////////////////
		//Key Generation and Serialization
		////////////////////////////////////////////////////////////

		std::cout << "Generating public and private keys...";
		LPKeyPair<DCRTPoly> kp = cc->KeyGen();

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing public and private keys...";

		if (kp.publicKey && kp.secretKey) {
			Serialized pubK, privK;

			if (kp.publicKey->Serialize(&pubK)) {
				if (!SerializableHelper::WriteSerializationToFile(pubK, DATAFOLDER + "/" + "key-public" + std::to_string(k) + ".txt")) {
					cerr << "Error writing serialization of public key to key-public" + std::to_string(k) + ".txt" << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing public key" << endl;
				return;
			}

			if (kp.secretKey->Serialize(&privK)) {
				if (!SerializableHelper::WriteSerializationToFile(privK, DATAFOLDER + "/" +"key-private" + std::to_string(k) + ".txt")) {
					cerr << "Error writing serialization of private key to key-private" + std::to_string(k) + ".txt" << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing private key" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating private and public keys" << endl;
		}
		std::cout << "Completed" << std::endl;

		// EvalMultKey

		std::cout << "Generating multiplication evaluation key...";

		cc->EvalMultKeyGen(kp.secretKey);

		std::cout << "Completed" << std::endl;

		// EvalSumKey

		std::cout << "Generating summation evaluation keys...";

		cc->EvalSumKeyGen(kp.secretKey);

		std::cout << "Completed" << std::endl;

		// CryptoContext

		std::cout << "Serializing crypto context...";

		Serialized ctxt;

		if (cc->Serialize(&ctxt)) {
			if (!SerializableHelper::WriteSerializationToFile(ctxt, DATAFOLDER + "/" + "cryptocontext" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of the crypto context to cryptocontext" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing the crypto context" << endl;
			return;
		}

		std::cout << "Serializing evaluation keys...";

		Serialized emKeys, esKeys;

		if (cc->SerializeEvalMultKey(&emKeys)) {
			if (!SerializableHelper::WriteSerializationToFile(emKeys, DATAFOLDER + "/" + "key-eval-mult" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of the eval mult keys to key-eval-mult" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing eval mult keys" << endl;
			return;
		}

		if (cc->SerializeEvalSumKey(&esKeys)) {
			if (!SerializableHelper::WriteSerializationToFile(esKeys, DATAFOLDER + "/" + "key-eval-sum" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of the eval sum keys to key-eval-sum" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing eval sum keys" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}

}

void Encrypt() {

	size_t batchSize = 1024;

	auto singleAlloc = [=]() { return lbcrypto::make_unique<uint64_t>(); };

	Matrix<uint64_t> x(singleAlloc, VECTORS, batchSize);
	Matrix<uint64_t> y(singleAlloc, VECTORS, batchSize);

	DiscreteUniformGenerator dug;
	dug.SetModulus(BigInteger(255));

	//create the dataset for processing
	for (size_t i = 0; i < VECTORS; i++)
	{
		BigVector randomVectorX = dug.GenerateVector(batchSize);
		BigVector randomVectorY = dug.GenerateVector(batchSize);
		for (size_t j = 0; j < batchSize; j++) {
			x(i, j) = randomVectorX.at(j).ConvertToInt();
			y(i, j) = randomVectorY.at(j).ConvertToInt();
		}
	}

	auto product = x * y.Transpose();
	uint64_t result = 0;

	for (size_t i = 0; i < VECTORS; i++)
	{
		result += product(i,i);
	}

	std::cout << "Result of plaintext computation is " << result << std::endl;

	// Key deserialization is done here

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nDESERIALIZATION/ENCRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = "key-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = "key-eval-sum" + std::to_string(k) + ".txt";
		string pkFileName = "key-public" + std::to_string(k) + ".txt";

		// Deserialize the crypto context
		Serialized ccSer;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + ccFileName, &ccSer) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + ccFileName << endl;
			return;
		}

		Serialized ccEmk;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + emFileName, &ccEmk) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + emFileName << endl;
			return;
		}

		Serialized ccEsk;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + esFileName, &ccEsk) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + esFileName << endl;
			return;
		}

		CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);
		cc->DeserializeEvalMultKey(ccEmk);
		cc->DeserializeEvalSumKey(ccEsk);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		const auto encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		
		usint m = elementParams->GetCyclotomicOrder();

		PackedEncoding::SetParams(m, encodingParams);

		//std::cout << "plaintext modulus = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;

		// Deserialize the public key

		std::cout << "Deserializing the public key...";

		Serialized	pkSer;
		if (SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + pkFileName, &pkSer) == false) {
			cerr << "Could not read public key" << endl;
			return;
		}

		LPPublicKey<DCRTPoly> pk = cc->deserializePublicKey(pkSer);

		if (!pk) {
			cerr << "Could not deserialize public key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		std::cout << "Encoding the data...";

		auto zeroAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(cc->MakePackedPlaintext({0})); };

		Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, VECTORS, 1);
		Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, VECTORS, 1);

		for (size_t i = 0; i < VECTORS; i++)
		{
			std::vector<uint64_t> tempX(batchSize);
			std::vector<uint64_t> tempY(batchSize);
			for (size_t j = 0; j < batchSize; j++)
			{
				tempX[j] = x(i, j);
				tempY[j] = y(i, j);
			}
			xP(i,0) = cc->MakePackedPlaintext(tempX);
			yP(i,0) = cc->MakePackedPlaintext(tempY);
		}

		std::cout << "Completed" << std::endl;

		// Packing and encryption

		std::cout << "Batching/encrypting X...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xC = cc->EncryptMatrix(pk, xP);

		std::cout << "Completed" << std::endl;

		std::cout << "Batching/encrypting Y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yC = cc->EncryptMatrix(pk, yP);

		std::cout << "Completed" << std::endl;

		//Serialization

		Serialized ctxtSer;
		ctxtSer.SetObject();

		std::cout << "Serializing X...";

		if (xC->Serialize(&ctxtSer)) {
			if (!SerializableHelper::WriteSerializationToFile(ctxtSer, DATAFOLDER + "/" + "ciphertext-x-" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of ciphertext X to " << "ciphertext-x-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing ciphertext X" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing y...";

		if (yC->Serialize(&ctxtSer)) {
			if (!SerializableHelper::WriteSerializationToFile(ctxtSer, DATAFOLDER + "/" + "ciphertext-y-" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of ciphertext y to " << "ciphertext-y-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing ciphertext y" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}


}

void Compute() {

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nCOMPUTATION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = "key-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = "key-eval-sum" + std::to_string(k) + ".txt";

		// Deserialize the crypto context

		Serialized ccSer;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + ccFileName, &ccSer) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + ccFileName << endl;
			return;
		}

		Serialized ccEmk;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + emFileName, &ccEmk) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + emFileName << endl;
			return;
		}

		Serialized ccEsk;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + esFileName, &ccEsk) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + esFileName << endl;
			return;
		}

		CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);
		cc->DeserializeEvalMultKey(ccEmk);
		cc->DeserializeEvalSumKey(ccEsk);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		const auto encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		
		usint m = elementParams->GetCyclotomicOrder();

		PackedEncoding::SetParams(m, encodingParams);

		usint batchSize = encodingParams->GetBatchSize();

		// Deserialize X

		string xFileName = DATAFOLDER + "/" +  "ciphertext-x-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing vector x...";

		Serialized	xSer;
		if (SerializableHelper::ReadSerializationFromFile(xFileName, &xSer) == false) {
			cerr << "Could not read ciphertext X" << endl;
			return;
		}

		auto zeroAlloc = [=]() { return lbcrypto::make_unique<RationalCiphertext<DCRTPoly>>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> x(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (!x->Deserialize(xSer)) {
			cerr << "Could not deserialize ciphertext x" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize y

		string yFileName = DATAFOLDER + "/" +  "ciphertext-y-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing vector y...";

		Serialized	ySer;
		if (SerializableHelper::ReadSerializationFromFile(yFileName, &ySer) == false) {
			cerr << "Could not read ciphertext y" << endl;
			return;
		}

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> y(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (!y->Deserialize(ySer)) {
			cerr << "Could not deserialize ciphertext y" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Compute cross-correlation

		std::cout << "Computing the cross-correlation ...";

		double start, finish;

		start = currentDateTime();

		Ciphertext<DCRTPoly> result = cc->EvalCrossCorrelation(x,y,batchSize);

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "Cross-correlation computation time: " << "\t" << (finish - start) << " ms" << std::endl;

		std::cout << "Average inner product computation time: " << "\t" << (finish - start)/VECTORS << " ms" << std::endl;

		// Serialize cross-correlation

		Serialized crossSer;
		crossSer.SetObject();

		std::cout << "Serializing cross-correlation...";

		if (result->Serialize(&crossSer)) {
			if (!SerializableHelper::WriteSerializationToFile(crossSer, DATAFOLDER + "/" + "ciphertext-cc-" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of cross-correlation ciphertext to " << "ciphertext-cc-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing ciphertext cross-correlation" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}

}

void Decrypt() {

	std::vector<Plaintext> crossCorr;

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nDESERIALIZATION/DECRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = "key-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = "key-eval-sum" + std::to_string(k) + ".txt";
		string skFileName = "key-private" + std::to_string(k) + ".txt";

		// Deserialize the crypto context

		Serialized ccSer;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + ccFileName, &ccSer) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + ccFileName << endl;
			return;
		}

		Serialized ccEmk;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + emFileName, &ccEmk) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + emFileName << endl;
			return;
		}

		Serialized ccEsk;
		if ( !SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + esFileName, &ccEsk) ) {
			cerr << "I cannot read serialization from " << DATAFOLDER + "/" + esFileName << endl;
			return;
		}

		CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);
		cc->DeserializeEvalMultKey(ccEmk);
		cc->DeserializeEvalSumKey(ccEsk);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		const auto encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		
		usint m = elementParams->GetCyclotomicOrder();

		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the private key

		std::cout << "Deserializing the private key...";

		Serialized	skSer;
		if (SerializableHelper::ReadSerializationFromFile(DATAFOLDER + "/" + skFileName, &skSer) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		LPPrivateKey<DCRTPoly> sk = cc->deserializeSecretKey(skSer);

		if (!sk) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize cross-correlation

		string cFileName = DATAFOLDER + "/" + "ciphertext-cc-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing cross-correlation..";

		Serialized	cSer;
		if (SerializableHelper::ReadSerializationFromFile(cFileName, &cSer) == false) {
			cerr << "Could not read ciphertext" << endl;
			return;
		}


		Ciphertext<DCRTPoly> c((new CiphertextImpl<DCRTPoly>(cc)));

		if (!c->Deserialize(cSer)) {
			cerr << "Could not deserialize ciphertext" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Decrypt cross-correlation

		std::cout << "Decrypting cross-correlation...";

		Plaintext ccResult;

		cc->Decrypt(sk, c, &ccResult);

		std::cout << "Completed" << std::endl;

		crossCorr.push_back(ccResult);

	}

	// Convert back to large plaintext modulus

	std::cout << "\nCLEARTEXT OPERATIONS\n" << std::endl;

	std::cout << "CRT Interpolation to transform to large plainext modulus...";

	NativeInteger result = CRTInterpolate(crossCorr);

	std::cout << "Completed" << std::endl;

	std::cout << "Ciphertext result: " << result << std::endl;

}

CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName, const string& emFileName, const string& esFileName)
{

	std::cout << "Deserializing the crypto context...";

	Serialized	ccSer, emSer, esSer;
	if (SerializableHelper::ReadSerializationFromFile(ccFileName, &ccSer) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	if (SerializableHelper::ReadSerializationFromFile(emFileName, &emSer) == false) {
		cerr << "Could not read the eval mult key file " << endl;
		return 0;
	}

	if (SerializableHelper::ReadSerializationFromFile(esFileName, &esSer) == false) {
		cerr << "Could not read the eval sum key file" << endl;
		return 0;
	}

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);

	if( cc->DeserializeEvalMultKey(emSer) == false ) {
		cerr << "Could not deserialize the eval mult key file" << endl;
		return 0;
	}

	if( cc->DeserializeEvalSumKey(esSer) == false ) {
		cerr << "Could not deserialize the eval sum key file" << endl;
		return 0;
	}

	std::cout << "Completed" << std::endl;

	return cc;
}

NativeInteger CRTInterpolate(const std::vector<Plaintext> &crtVector) {

	NativeInteger result(0);

	std::vector<NativeInteger> q = { 3623,3779,3803,3863 };

	NativeInteger Q(1);

	for (size_t i = 0; i < crtVector.size(); i++) {
		Q = Q*q[i];
	}

	std::vector<NativeInteger> qInverse;

	for (size_t i = 0; i < crtVector.size(); i++) {

		qInverse.push_back((Q / q[i]).ModInverse(q[i]));
		//std::cout << qInverse[i];
	}

	for (size_t i = 0; i < crtVector.size(); i++) {
		result += ((NativeInteger(crtVector[i]->GetPackedValue()[0])*qInverse[i]).Mod(q[i])*Q / q[i]).Mod(Q);
	}
	
	return result.Mod(Q);

}

template<typename T> ostream& operator<<(ostream& output, const vector<T>& vector) {

	output << "[";

	for (unsigned int i = 0; i < vector.size(); i++) {

		if (i > 0) {
			output << ", ";
		}

		output << vector[i];
	}

	output << "]";
	return output;
}
