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
This code exercises the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.
In this code we:
- Generate a key pair.
- Encrypt a string of data.
- Decrypt the data.
- Generate a new key pair.
- Generate a proxy re-encryption key.
- Re-Encrypt the encrypted data.
- Decrypt the re-encrypted data.
We configured parameters (namely the ring dimension and ciphertext modulus) to provide a level of security roughly equivalent to a root hermite factor of 1.007 which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor and may be closer to AES-256.

*/

#include <iostream>
#include <fstream>


#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"


using namespace std;
using namespace lbcrypto;


#include <iterator>

void LTVPlaintextPKE();
void BVPlaintextPKE();
void FVPlaintextPKE();
void LTVEvalMultPlain();
void BVEvalMultPlain();
void FVEvalMultPlain();


int main() {

	std::cout << "\n===========LTV TESTS (PLAINTEXT PKE)===============: " << std::endl;

	LTVPlaintextPKE();

	std::cout << "\n===========BV TESTS (PLAINTEXT PKE)===============: " << std::endl;

	BVPlaintextPKE();

	std::cout << "\n===========FV TESTS (PLAINTEXT PKE)===============: " << std::endl;

	FVPlaintextPKE();

	std::cout << "\n===========LTV TESTS (CIPHERTEXT-PLAINTEXT MULTIPLICATION)===============: " << std::endl;

	LTVEvalMultPlain();

	std::cout << "\n===========BV TESTS (CIPHERTEXT-PLAINTEXT MULTIPLICATION)===============: " << std::endl;

	BVEvalMultPlain();

	std::cout << "\n===========FV TESTS (CIPHERTEXT-PLAINTEXT MULTIPLICATION)===============: " << std::endl;

	FVEvalMultPlain();

	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}

void LTVPlaintextPKE() {

	//Set the parameters

	usint m = 22;
	usint p = 89;
	BigInteger modulusP(p);

	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");

	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);
	
	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	//Create the context

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, encodingParams, 8, stdDev);
	
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false, false);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Decrypted array: " << intArrayNew << std::endl;

}

void BVPlaintextPKE() {

	//Set the parameters

	usint m = 22;
	usint p = 16787;

	BigInteger modulusP(p);

	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");

	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);
	
	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	//Create the context

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false, false);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Decrypted array: " << intArrayNew << std::endl;

}

void FVPlaintextPKE() {

	//Set the parameters

	usint m = 22;
	usint p = 23;
	BigInteger modulusP(p);

	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");

	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	//Create the context

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(
		params, encodingParams,
		8, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false, false);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Decrypted array: " << intArrayNew << std::endl;

}

void LTVEvalMultPlain() {

	//Set the parameters

	usint m = 22;
	usint p = 89;
	BigInteger modulusP(p);

	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");

	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	//Create the context

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextResult;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::cout << "Input array 1\n\t" << intArray1 << std::endl;

	std::vector<usint> vectorOfInts2 = { 1,2,3,2,2,1,2,2,3,4 };
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	std::cout << "Input array 2\n\t" << intArray2 << std::endl;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1, false);

	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false, false);

	auto ciphertextMult = cc->EvalMultPlain(ciphertext1.at(0), ciphertext2.at(0));
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextMult);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);

	std::cout << "Decrypted array: " << intArrayNew << std::endl;
	
}

void BVEvalMultPlain() {

	//Set the parameters

	usint m = 22;
	usint p = 16787;

	BigInteger modulusP(p);

	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");

	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	//Create the context

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextResult;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::cout << "Input array 1\n\t" << intArray1 << std::endl;

	std::vector<usint> vectorOfInts2 = { 1,2,3,2,2,1,2,2,3,4 };
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	std::cout << "Input array 2\n\t" << intArray2 << std::endl;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1, false);

	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false, false);

	auto ciphertextMult = cc->EvalMultPlain(ciphertext1.at(0), ciphertext2.at(0));
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextMult);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);

	std::cout << "Decrypted array: " << intArrayNew << std::endl;

}

void FVEvalMultPlain() {

	//Set the parameters

	usint m = 22;
	usint p = 89; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("72385066601");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("69414828251");
	BigInteger bigmodulus("77302754575416994210914689");
	BigInteger bigroot("76686504597021638023705542");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigInteger bigEvalMultModulus("37778931862957161710549");
	BigInteger bigEvalMultRootOfUnity("7161758688665914206613");
	BigInteger bigEvalMultModulusAlt("1461501637330902918203684832716283019655932547329");
	BigInteger bigEvalMultRootOfUnityAlt("570268124029534407621996591794583635795426001824");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigVector, BigInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	//Create the context

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(params, encodingParams, 1, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextResult;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::cout << "Input array 1\n\t" << intArray1 << std::endl;

	std::vector<usint> vectorOfInts2 = { 1,2,3,2,2,1,2,2,3,4 };
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	std::cout << "Input array 2\n\t" << intArray2 << std::endl;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1, false);

	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false, false);

	auto ciphertextMult = cc->EvalMultPlain(ciphertext1.at(0), ciphertext2.at(0));
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextMult);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);

	std::cout << "Decrypted array: " << intArrayNew << std::endl;

}
