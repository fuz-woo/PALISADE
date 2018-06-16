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
This code shows how the automorphism operation works for different plaintext encodings and cyclotomic rings (both power-of-two and cyclic)

*/

#include <iostream>
#include <fstream>


#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

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
void BGVAutomorphismPackedArray(usint i);
void ArbBGVAutomorphismPackedArray(usint i);
void BFVAutomorphismPackedArray(usint i);
void ArbBFVAutomorphismPackedArray(usint i);
void ArbBFVAutomorphismCoeffArray(usint i);
void ArbBFVAutomorphismPackedArray2n(usint i);
void ArbBFVAutomorphismCoeffArray2n(usint i);
void ArbNullAutomorphismPackedArray(usint i);
void ArbNullAutomorphismCoeffArray2n(usint i);
void ArbNullAutomorphismCoeffArray(usint i);
void ArbNullAutomorphismPackedArray2n(usint i);

int main() {

	std::cout << "\nThis code shows how the automorphism operation works for different plaintext encodings and cyclotomic rings (both power-of-two and cyclic).\n" << std::endl;

	//LTVAutomorphismIntArray();
	usint m = 22;
	std::vector<usint> totientList = GetTotientList(m);

	std::cout << "\n===========LTV TESTS (EVALAUTOMORPHISM)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 3; index < 16; index = index + 2)
		LTVAutomorphismPackedArray(index);

	std::cout << "\n===========LTV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbLTVAutomorphismPackedArray(totientList[index]);
	}

	std::cout << "\n===========BGV TESTS (EVALAUTOMORPHISM)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 3; index < 16; index = index + 2)
		BGVAutomorphismPackedArray(index);

	std::cout << "\n===========BGV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbBGVAutomorphismPackedArray(totientList[index]);
	}

	std::cout << "\n==============BFV TESTS (EVALAUTOMORPHISM)================: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 3; index < 16; index = index + 2)
		BFVAutomorphismPackedArray(index);

	std::cout << "\n===========BFV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbBFVAutomorphismPackedArray(totientList[index]);
	}

	std::cout << "\n===========BFV TESTS (EVALAUTOMORPHISM-POWER-OF-TWO)===============: " << std::endl;

	PackedEncoding::Destroy();
	usint m2n = 32;
	std::vector<usint> totientList2n = GetTotientList(m2n);

	for (usint index = 1; index < 16; index++) {
		ArbBFVAutomorphismPackedArray2n(totientList2n[index]);
	}

	std::cout << "\n===========NULL TESTS (EVALAUTOMORPHISM-POWER-OF-TWO)===============: " << std::endl;

	for (usint index = 1; index < 16; index++) {
		ArbNullAutomorphismPackedArray2n(totientList2n[index]);
	}

	std::cout << "\n===========BFV TESTS (EVALAUTOMORPHISM-POWER-OF-TWO-COEFF-ENCODING)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbBFVAutomorphismCoeffArray2n(totientList[index]);
	}

	std::cout << "\n===========NULL TESTS (EVALAUTOMORPHISM-POWER-OF-TWO-COEFF-ENCODING)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbNullAutomorphismCoeffArray2n(totientList[index]);
	}

	std::cout << "\n===========BFV TESTS (EVALAUTOMORPHISM-ARB-COEFF-ENCODING)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbBFVAutomorphismCoeffArray(totientList[index]);
	}

	/*std::cout << "\n===========NULL TESTS (EVALAUTOMORPHISM-ARB-COEFF-ENCODING)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbNullAutomorphismCoeffArray(totientList[index]);
	}

	std::cout << "\n===========NULL TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedEncoding::Destroy();
	for (usint index = 1; index < 10; index++) {
		ArbNullAutomorphismPackedArray(totientList[index]);
	}
	*/
	//cin.get();
	return 0;
}

void LTVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	shared_ptr<ILParams> params( new ILParams(m, q, rootOfUnity) );

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, plaintextModulus, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = {3,5,7,9,11,13,15};

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}


void BGVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	shared_ptr<ILParams> params( new ILParams(m, q, rootOfUnity) );

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, plaintextModulus, 1, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

void BFVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;
	usint relWindow = 1;
	float stdDev = 4;

	BigInteger BBIPlaintextModulus(plaintextModulus);
	BigInteger delta(q.DividedBy(BBIPlaintextModulus));

	shared_ptr<ILParams> params( new ILParams(m, q, rootOfUnity) );

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
		params, plaintextModulus,
		relWindow, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };
	
	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

void ArbBGVAutomorphismPackedArray(usint i) {

	usint m = 22;
	usint p = 2333;
	BigInteger modulusP(p);
	
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	
	//usint n = GetTotient(m);
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");


	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, p, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
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
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, p, 8, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

void ArbBFVAutomorphismPackedArray(usint i) {

	usint m = 22;
	usint p = 2333;
	BigInteger modulusP(p);
	
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	
	//usint n = GetTotient(m);
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");


	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
		params, p,
		8, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10};
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

void ArbBFVAutomorphismCoeffArray(usint i) {

	usint m = 22;
	usint p = 2333;
	BigInteger modulusP(p);

	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");

	//usint n = GetTotient(m);
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");


	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
		params, p,
		8, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10};
	Plaintext intArray = cc->MakeCoefPackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}


void ArbNullAutomorphismPackedArray(usint i) {

	usint m = 22;
	PlaintextModulus p = 89;
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
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, encodingParams);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey,  permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

void ArbNullAutomorphismCoeffArray(usint i) {

	usint m = 22;
	PlaintextModulus p = 89;
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
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, encodingParams);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10 };
	Plaintext intArray = cc->MakeCoefPackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey,  permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

void ArbBFVAutomorphismPackedArray2n(usint i) {


	usint m = 32;
	//usint phim = 1024;
	PlaintextModulus p = 193; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusP(p);

	usint batchSize = 16;
	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	BigInteger modulusQ("4809848800078200833");
	BigInteger rootOfUnity("1512511313188104877");
	BigInteger delta(modulusQ.DividedBy(modulusP));
	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity));

	BigInteger EvalMultModulus("1182196001696382977");
	BigInteger EvalMultRootOfUnity("105268544709215333");

	usint relinWindow = 1;
	float stdDev = 4;
	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
			params, encodingParams, relinWindow, stdDev, delta.ToString(), OPTIMIZED,
			EvalMultModulus.ToString(), EvalMultRootOfUnity.ToString(), 0, 9, 1.006
		);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10, 11, 12, 13, 14, 15, 16};
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

void ArbNullAutomorphismPackedArray2n(usint i) {


	usint m = 32;
	//usint phim = 1024;
	PlaintextModulus p = 193; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusP(p);

	usint batchSize = 16;
	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	BigInteger modulusQ("4809848800078200833");
	BigInteger rootOfUnity("1512511313188104877");
	BigInteger delta(modulusQ.DividedBy(modulusP));
	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity));

	BigInteger EvalMultModulus("1182196001696382977");
	BigInteger EvalMultRootOfUnity("105268544709215333");

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, p);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10, 11, 12, 13, 14, 15, 16};
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}


void ArbBFVAutomorphismCoeffArray2n(usint i) {


	usint m = 32;
	//usint phim = 1024;
	PlaintextModulus p = 193; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusP(p);

	//usint batchSize = 16;
	//EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	BigInteger modulusQ("4809848800078200833");
	BigInteger rootOfUnity("1512511313188104877");
	BigInteger delta(modulusQ.DividedBy(modulusP));
	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity));

	BigInteger EvalMultModulus("1182196001696382977");
	BigInteger EvalMultRootOfUnity("105268544709215333");

	usint relinWindow = 1;
	float stdDev = 4;
	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
			params, p, relinWindow, stdDev, delta.ToString(), OPTIMIZED,
			EvalMultModulus.ToString(), EvalMultRootOfUnity.ToString(), 0, 9, 1.006
		);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	PackedEncoding::SetParams(m, cc->GetEncodingParams());

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10, 11, 12, 13, 14, 15, 16};
	Plaintext intArray = cc->MakeCoefPackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

void ArbNullAutomorphismCoeffArray2n(usint i) {


	usint m = 32;
	//usint phim = 1024;
	PlaintextModulus p = 193; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusP(p);

	//usint batchSize = 16;
	//EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	BigInteger modulusQ("4809848800078200833");
	BigInteger rootOfUnity("1512511313188104877");
	BigInteger delta(modulusQ.DividedBy(modulusP));
	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity));

	BigInteger EvalMultModulus("1182196001696382977");
	BigInteger EvalMultRootOfUnity("105268544709215333");

	//usint relinWindow = 1;
	//float stdDev = 4;
	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, p);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	PackedEncoding::SetParams(m, cc->GetEncodingParams());

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts = { 1,2,3,4,5,6,7,8, 9, 10, 11, 12, 13, 14, 15, 16};
	Plaintext intArray = cc->MakeCoefPackedPlaintext(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << *intArray << std::endl;

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto permutedCiphertext = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << *intArrayNew << std::endl;
}

