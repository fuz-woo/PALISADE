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

void ArbLTVEvalSumPackedArray();
void ArbBVEvalSumPackedArray();
void ArbFVEvalSumPackedArray();

int main() {

	//LTVAutomorphismIntArray();

	std::cout << "\n===========LTV TESTS (EVALSUM-ARBITRARY)===============: " << std::endl;

	ArbLTVEvalSumPackedArray();

	std::cout << "\n===========BV TESTS (EVALSUM-ARBITRARY)===============: " << std::endl;

	ArbBVEvalSumPackedArray();

	std::cout << "\n===========FV TESTS (EVALSUM-ARBITRARY)===============: " << std::endl;

	ArbFVEvalSumPackedArray();

	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}

void ArbBVEvalSumPackedArray() {

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

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP,PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP),batchSize));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	cc->EvalSumKeyGen(kp.secretKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc->EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	std::cout << "Sum = " << intArrayNew[0] << std::endl;

}


void ArbLTVEvalSumPackedArray() {

	usint m = 22;
	usint p = 89;
	BigInteger modulusP(p);
	/*BigInteger modulusQ("577325471560727734926295560417311036005875689");
	BigInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");
	BigInteger modulusQ("1152921504606847009");
	BigInteger squareRootOfRoot("1147559132892757400");

	//BigInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	//BigInteger bigmodulus("80899135611688102162227204937217");
	//BigInteger bigroot("77936753846653065954043047918387");
	BigInteger bigmodulus("1361129467683753853853498429727072847489");
	BigInteger bigroot("574170933302565148884487552139817611806");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, encodingParams, 16, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	cc->EvalSumKeyGen(kp.secretKey,kp.publicKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc->EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	std::cout << "Sum = " << intArrayNew[0] << std::endl;

}


void ArbFVEvalSumPackedArray() {

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

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(
		params, encodingParams,
		8, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	cc->EvalSumKeyGen(kp.secretKey);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc->EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	std::cout << "Sum = " << intArrayNew[0] << std::endl;

}
