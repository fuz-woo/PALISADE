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
Description:
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

//Poly tests
//void LTVAutomorphismIntArray();
void LTVAutomorphismPackedArray(usint i);
void ArbLTVAutomorphismPackedArray(usint i);
void BVAutomorphismPackedArray(usint i);
void ArbBVAutomorphismPackedArray(usint i);
void FVAutomorphismPackedArray(usint i);
void ArbFVAutomorphismPackedArray(usint i);
void ArbNullAutomorphismPackedArray(usint i);

int main() {

	//LTVAutomorphismIntArray();
	usint m = 22;
	std::vector<usint> totientList = GetTotientList(m);

	std::cout << "\n===========LTV TESTS (EVALAUTOMORPHISM)===============: " << std::endl;

	PackedIntPlaintextEncoding::Destroy();
	for (usint index = 3; index < 16; index = index + 2)
		LTVAutomorphismPackedArray(index);

	std::cout << "\n===========LTV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedIntPlaintextEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbLTVAutomorphismPackedArray(totientList[index]);
	}

	std::cout << "\n===========BV TESTS (EVALAUTOMORPHISM)===============: " << std::endl;

	PackedIntPlaintextEncoding::Destroy();
	for (usint index = 3; index < 16; index = index + 2)
		BVAutomorphismPackedArray(index);

	std::cout << "\n===========BV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedIntPlaintextEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbBVAutomorphismPackedArray(totientList[index]);
	}

	std::cout << "\n==============FV TESTS (EVALAUTOMORPHISM)================: " << std::endl;

	PackedIntPlaintextEncoding::Destroy();
	for (usint index = 3; index < 16; index = index + 2)
		FVAutomorphismPackedArray(index);

	std::cout << "\n===========FV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedIntPlaintextEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbFVAutomorphismPackedArray(totientList[index]);
	}

	std::cout << "\n===========NULL TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedIntPlaintextEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbNullAutomorphismPackedArray(totientList[index]);
	}

	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}

void LTVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	shared_ptr<ILParams> params( new ILParams(m, q, rootOfUnity) );

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, plaintextModulus, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = {3,5,7,9,11,13,15};

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}


void BVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	shared_ptr<ILParams> params( new ILParams(m, q, rootOfUnity) );

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, plaintextModulus, 1, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
		//std::cout << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void FVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;
	usint relWindow = 1;
	float stdDev = 4;

	BigInteger BBIPlaintextModulus(plaintextModulus);
	BigInteger delta(q.DividedBy(BBIPlaintextModulus));

	shared_ptr<ILParams> params( new ILParams(m, q, rootOfUnity) );

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(
		params, plaintextModulus,
		relWindow, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };
	
	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void ArbBVAutomorphismPackedArray(usint i) {

	usint m = 22;
	usint p = 16787;
	//usint p = 23;
	BigInteger modulusP(p);
	/*BigInteger modulusQ("577325471560727734926295560417311036005875689");
	BigInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	//BigInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, p, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}


void ArbLTVAutomorphismPackedArray(usint i) {

	usint m = 22;
	usint p = 89;
	BigInteger modulusP(p);
	/*BigInteger modulusQ("577325471560727734926295560417311036005875689");
	BigInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	//BigInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, p, 8, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void ArbFVAutomorphismPackedArray(usint i) {

	usint m = 22;
	usint p = 23;
	BigInteger modulusP(p);
	/*BigInteger modulusQ("577325471560727734926295560417311036005875689");
	BigInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	//BigInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(
		params, p,
		8, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10};
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}


void ArbNullAutomorphismPackedArray(usint i) {

	usint m = 22;
	usint p = 23;
	BigInteger modulusP(p);
	/*BigInteger modulusQ("577325471560727734926295560417311036005875689");
	BigInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	//BigInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	usint batchSize = 8;

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextNull(
		params, encodingParams);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey,  permutedCiphertext, &intArrayNew, false);
	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}
