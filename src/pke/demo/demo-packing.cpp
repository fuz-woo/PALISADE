/*
 * @file demo-bit-packing.cpp This code shows multiple demonstrations of how to use packing features in PALISADE.
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
#include <random>
#include <iterator>
#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/debug.h"
#include "encoding/encodings.h"
#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;

void ArbLTVInnerProductPackedArray();
void ArbBGVInnerProductPackedArray();
void ArbBFVInnerProductPackedArray();
void ArbBFVEvalMultPackedArray();

int main() {

	std::cout << "\nThis code demonstrates the use of packing on the BFV, BGV and LTV schemes. " << std::endl;
	std::cout << "We show inner product operations for all schemes and a bit-packed EvalMult for the BFV scheme. " << std::endl;
	std::cout << "This code shows how parameters can be manually set in our library. " << std::endl;
	std::cout << "We do not generally recommend the use of the LTV scheme due to security concerns. " << std::endl;

	std::cout << "\n=========== In this code block we demonstrate inner product operations using the BFV scheme. ===============: " << std::endl;

	ArbBFVInnerProductPackedArray();

	std::cout << "\n=========== In this code block we demonstrate EvalMult operations using the BFV scheme. ===============: " << std::endl;

	ArbBFVEvalMultPackedArray();


	std::cout << "\n=========== In this code block we demonstrate inner product operations using the LTV scheme. ===============: " << std::endl;

	ArbLTVInnerProductPackedArray();

	std::cout << "\n=========== In this code block we demonstrate inner product operations using the BGV scheme. ===============: " << std::endl;

	ArbBGVInnerProductPackedArray();


	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}

void ArbBGVInnerProductPackedArray() {

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

	PackedEncoding::SetParams(m, p);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

	std::cout << "Input array 1 \n\t" << intArray1 << std::endl;

	std::vector<uint64_t> vectorOfInts2 = { 1,2,3,2,1,2,1,2,0,0 };
	Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	auto ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	auto result = cc->EvalInnerProduct(ciphertext1, ciphertext2, batchSize);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, result, &intArrayNew);

	std::cout << "Sum = " << intArrayNew->GetPackedValue()[0] << std::endl;

	std::cout << "All components (other slots randomized) = " << intArrayNew << std::endl;

}


void ArbLTVInnerProductPackedArray() {

	usint m = 22;
	PlaintextModulus p = 89;
	BigInteger modulusP(p);
	/*BigInteger modulusQ("577325471560727734926295560417311036005875689");
	BigInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");
	BigInteger modulusQ("1267650600228229401496703214121");
	BigInteger squareRootOfRoot("498618454049802547396506932253");

	//BigInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	//BigInteger bigmodulus("80899135611688102162227204937217");
	//BigInteger bigroot("77936753846653065954043047918387");
	BigInteger bigmodulus("1645504557321206042154969182557350504982735865633579863348616321");
	BigInteger bigroot("201473555181182026164891698186176997440470643522932663932844212");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedEncoding::SetParams(m, p);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, encodingParams, 16, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

	std::cout << "Input array 1 \n\t" << intArray1 << std::endl;


	std::vector<uint64_t> vectorOfInts2 = { 1,2,3,2,1,2,1,2,0,0 };
	Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	cc->EvalSumKeyGen(kp.secretKey,kp.publicKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	auto ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	auto result = cc->EvalInnerProduct(ciphertext1, ciphertext2, batchSize);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, result, &intArrayNew);

	std::cout << "Sum = " << intArrayNew->GetPackedValue()[0] << std::endl;

	std::cout << "All components (other slots randomized) = " << intArrayNew << std::endl;

}

void ArbBFVInnerProductPackedArray() {

	usint m = 22;
	PlaintextModulus p = 2333; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("1152921504606847009");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("1147559132892757400");

	BigInteger bigmodulus("42535295865117307932921825928971026753");
	BigInteger bigroot("13201431150704581233041184864526870950");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigInteger bigEvalMultModulus("42535295865117307932921825928971026753");
	BigInteger bigEvalMultRootOfUnity("22649103892665819561201725524201801241");
	BigInteger bigEvalMultModulusAlt("115792089237316195423570985008687907853269984665640564039457584007913129642241");
	BigInteger bigEvalMultRootOfUnityAlt("37861550304274465568523443986246841530644847113781666728121717722285667862085");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigVector, BigInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedEncoding::SetParams(m, p);

	usint batchSize = 8;

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextBFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(params, encodingParams, 1, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

	std::cout << "Input array 1 \n\t" << intArray1 << std::endl;


	std::vector<uint64_t> vectorOfInts2 = { 1,2,3,2,1,2,1,2,0,0 };
	Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	auto ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	auto result = cc->EvalInnerProduct(ciphertext1, ciphertext2, batchSize);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, result, &intArrayNew);

	std::cout << "Sum = " << intArrayNew->GetPackedValue()[0] << std::endl;

	std::cout << "All components (other slots randomized) = " << intArrayNew << std::endl;

}


void ArbBFVEvalMultPackedArray() {

	PackedEncoding::Destroy();

	usint m = 22;
	PlaintextModulus p = 89; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("72385066601");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("69414828251");
	BigInteger bigmodulus("77302754575416994210914689");
	BigInteger bigroot("76686504597021638023705542");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigInteger bigEvalMultModulus("37778931862957161710549");
	BigInteger bigEvalMultRootOfUnity("7161758688665914206613");
	BigInteger bigEvalMultModulusAlt("1461501637330902918203684832716283019655932547329");
	BigInteger bigEvalMultRootOfUnityAlt("570268124029534407621996591794583635795426001824");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigVector, BigInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedEncoding::SetParams(m, p);

	usint batchSize = 8;

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextBFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(params, encodingParams, 1, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,9,10 };
	Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

	std::vector<uint64_t> vectorOfInts2 = { 10,9,8,7,6,5,4,3,2,1 };
	Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::vector<uint64_t> vectorOfIntsMult;
	std::transform(vectorOfInts1.begin(), vectorOfInts1.end(), vectorOfInts2.begin(), std::back_inserter(vectorOfIntsMult), std::multiplies<usint>());
	Plaintext intArrayMult = cc->MakePackedPlaintext(vectorOfIntsMult);

	auto ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	auto ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	cc->EvalMultKeyGen(kp.secretKey);

	auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext2);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextMult, &intArrayNew);

	std::cout << "Actual = " << intArrayNew << std::endl;

	std::cout << "Expected = " << intArrayMult << std::endl;

}
