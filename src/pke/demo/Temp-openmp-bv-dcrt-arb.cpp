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

#include <omp.h> //open MP header


using namespace std;
using namespace lbcrypto;


#include <iterator>

//Poly tests
void EvalMult();
void ArbBVAutomorphismPackedArray(usint i);
void ArbNullAutomorphismPackedArray(usint i);
void ArbBVInnerProductPackedArray();

int main() {

	std::cerr  <<"Running with "<< omp_get_num_procs() << " processors." << std::endl;

	int nthreads, tid;

	// Fork a team of threads giving them their own copies of variables
	//so we can see how many threads we have to work with
    #pragma omp parallel private(nthreads, tid)
	{

		/* Obtain thread number */
		tid = omp_get_thread_num();

		/* Only master thread does this */
		if (tid == 0)
		{
			nthreads = omp_get_num_threads();
			std::cout << "Number of threads = " << nthreads << std::endl;
		}
	}


	//LTVAutomorphismIntArray();
	usint m = 22;
	std::vector<usint> totientList = GetTotientList(m);

	std::cout << "\n===========BV TESTS (EVALMULT-ARBITRARY)===============: " << std::endl;
	EvalMult();

	std::cout << "\n===========BV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;
	ArbBVAutomorphismPackedArray(3);

	std::cout << "\n===========NULL TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;
	ArbNullAutomorphismPackedArray(3);

	std::cout << "\n===========BV TESTS (EVALINNER-PRODUCT-ARBITRARY)===============: " << std::endl;
	ArbBVInnerProductPackedArray();

	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}


void ArbBVAutomorphismPackedArray(usint i) {

	usint m = 22;

	usint init_size = 7;
	usint dcrtBits = 10;
	usint dcrtBitsBig = 28;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<native_int::BigInteger> init_moduli(init_size);
	vector<native_int::BigInteger> init_rootsOfUnity(init_size);

	native_int::BigInteger q = FirstPrime<native_int::BigInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BigVector, native_int::BigInteger>(m, q);
		ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
	}

	// populate the towers for the big modulus

	vector<native_int::BigInteger> init_moduli_NTT(init_size);
	vector<native_int::BigInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<native_int::BigInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BigVector, native_int::BigInteger>(m, q);
		ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	//usint m = 22;
	usint p = 89;

	BigInteger modulusP(p);

	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");

	//BigInteger bigmodulus("80899135611688102162227204937217");
	//BigInteger bigroot("77936753846653065954043047918387");

	//auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBV(paramsDCRT, p, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<DCRTPoly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	//cc->EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<DCRTPoly>>> permutedCiphertext;

	shared_ptr<Ciphertext<DCRTPoly>> p1;

	//p1 = cc->EvalMult(ciphertext[0],ciphertext2[0]);

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	
	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Input array\n\t" << intArray << std::endl;

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void EvalMult() {

	usint m = 22;

	usint init_size = 7;
	usint dcrtBits = 10;
	usint dcrtBitsBig = 28;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<native_int::BigInteger> init_moduli(init_size);
	vector<native_int::BigInteger> init_rootsOfUnity(init_size);

	native_int::BigInteger q = FirstPrime<native_int::BigInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BigVector, native_int::BigInteger>(m, q);
		ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
	}

	// populate the towers for the big modulus

	vector<native_int::BigInteger> init_moduli_NTT(init_size);
	vector<native_int::BigInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<native_int::BigInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	BigInteger modulus_NTT(1);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BigVector, native_int::BigInteger>(m, q);
		ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	//usint m = 22;
	usint p = 16633;

	BigInteger modulusP(p);

	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");

	//BigInteger bigmodulus("80899135611688102162227204937217");
	//BigInteger bigroot("77936753846653065954043047918387");

	//auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBV(paramsDCRT, p, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<DCRTPoly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	vector<shared_ptr<Ciphertext<DCRTPoly>>> ciphertext2;

	std::vector<usint> vectorOfInts2 = { 2,3,4,4,5,6,7,8,9,101 };
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	//auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	cc->EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<DCRTPoly>>> permutedCiphertext;

	shared_ptr<Ciphertext<DCRTPoly>> p1;

	p1 = cc->EvalMult(ciphertext[0], ciphertext2[0]);

	//p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);

	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Input array\n\t" << intArray << std::endl;

	std::cout << "Input array 2\n\t" << intArray2 << std::endl;

	std::cout << "SIMD product\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void ArbNullAutomorphismPackedArray(usint i) {

	usint m = 22;

	usint init_size = 7;
	usint dcrtBits = 10;
	usint dcrtBitsBig = 28;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<native_int::BigInteger> init_moduli(init_size);
	vector<native_int::BigInteger> init_rootsOfUnity(init_size);

	native_int::BigInteger q = FirstPrime<native_int::BigInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BigVector, native_int::BigInteger>(m, q);
		ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
	}

	// populate the towers for the big modulus

	vector<native_int::BigInteger> init_moduli_NTT(init_size);
	vector<native_int::BigInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<native_int::BigInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BigVector, native_int::BigInteger>(m, q);
		ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	//usint m = 22;
	usint p = 89;

	BigInteger modulusP(p);

	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");

	//BigInteger bigmodulus("80899135611688102162227204937217");
	//BigInteger bigroot("77936753846653065954043047918387");

	//auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);


	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextNull(paramsDCRT, p);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<DCRTPoly>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	//cc->EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<DCRTPoly>>> permutedCiphertext;

	shared_ptr<Ciphertext<DCRTPoly>> p1;

	//p1 = cc->EvalMult(ciphertext[0],ciphertext2[0]);

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);

	//cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Input array\n\t" << intArray << std::endl;

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void ArbBVInnerProductPackedArray() {

	float stdDev = 4;

	usint batchSize = 8;


	usint m = 22;
	usint p = 89;

	usint init_size = 7;
	usint dcrtBits = 10;
	usint dcrtBitsBig = 28;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<native_int::BigInteger> init_moduli(init_size);
	vector<native_int::BigInteger> init_rootsOfUnity(init_size);

	native_int::BigInteger q = FirstPrime<native_int::BigInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BigVector, native_int::BigInteger>(m, q);
		ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
	}

	// populate the towers for the big modulus

	vector<native_int::BigInteger> init_moduli_NTT(init_size);
	vector<native_int::BigInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<native_int::BigInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BigVector, native_int::BigInteger>(m, q);
		ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	BigInteger modulusP(p);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBV(paramsDCRT, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<DCRTPoly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<DCRTPoly>>> ciphertext2;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::cout << "Input array 1 \n\t" << intArray1 << std::endl;


	std::vector<usint> vectorOfInts2 = { 1,2,3,2,1,2,1,2,0,0 };
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false);

	auto result = cc->EvalInnerProduct(ciphertext1[0], ciphertext2[0], batchSize);

	vector<shared_ptr<Ciphertext<DCRTPoly>>> ciphertextSum;

	ciphertextSum.push_back(result);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	std::cout << "Sum = " << intArrayNew[0] << std::endl;

	std::cout << "All components (other slots randomized) = " << intArrayNew << std::endl;

}

