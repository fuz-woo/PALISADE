/*
 * @file demo-linregress.cpp This code shows multiple demonstrations of how to perform linear regression in PALISADE.
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
#include <random>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

#include "math/nbtheory.h"
#include "math/matrix.h"
#include "math/matrix.cpp"

using namespace std;
using namespace lbcrypto;



void ArbBGVLinearRegressionPackedArray();
void ArbBFVLinearRegressionPackedArray();

int main() {

	std::cout << "\nThis code demonstrates the use of packing for linear regression using the BGV and BFV schemes. " << std::endl;
	std::cout << "This code shows how parameters can be manually set in our library. " << std::endl;
	
	std::cout << "\n===========BGV TESTS (LINEAR-REGRESSION-ARBITRARY)===============: " << std::endl;

	ArbBGVLinearRegressionPackedArray();

	std::cout << "\n===========BFV TESTS (INNER-PRODUCT-ARBITRARY)===============: " << std::endl;

	ArbBFVLinearRegressionPackedArray();

	std::cout << "Please press any key to continue..." << std::endl;

	std::cin.get();
	return 0;
}

void ArbBGVLinearRegressionPackedArray() {

	PackedEncoding::Destroy();

	usint m = 22;
	//usint p = 524591;
	PlaintextModulus p = 2333;
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

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 8, stdDev, OPTIMIZED);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	std::cout << "Starting key generation" << std::endl;

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	// Compute evaluation keys
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(cc->MakePackedPlaintext({0})); };

	Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 1, 2);

	xP(0, 0) = cc->MakePackedPlaintext({ 0, 2, 1, 3, 2, 2, 1, 2 });
	xP(0, 1) = cc->MakePackedPlaintext({ 1, 1, 2, 1, 1, 1, 3, 2 });

	std::cout << "Input array X0 \n\t" << xP(0, 0) << std::endl;
	std::cout << "Input array X1 \n\t" << xP(0, 1) << std::endl;

	Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

	yP(0, 0) = cc->MakePackedPlaintext({ 0, 1, 2, 6, 1, 2, 3, 4});
	std::cout << "Input array Y \n\t" << yP(0, 0) << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	std::cout << "Starting encryption of x" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<Poly>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	std::cout << "Starting encryption of y" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<Poly>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegressBatched(x, y, 8);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	std::cout << (*numerator)(0, 0)->GetPackedValue()[0] << "," << (*numerator)(1, 0)->GetPackedValue()[0] << std::endl;
	std::cout << (*denominator)(0, 0)->GetPackedValue()[0] << "," << (*denominator)(1, 0)->GetPackedValue()[0] << std::endl;

}

void ArbBFVLinearRegressionPackedArray() {

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

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	std::cout << "Starting key generation" << std::endl;

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	// Compute evaluation keys
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<Plaintext>(cc->MakePackedPlaintext({0})); };

	Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 1, 2);

	xP(0, 0) = cc->MakePackedPlaintext({ 0, 2, 1, 3,  2,  2, 1, 2 });
	xP(0, 1) = cc->MakePackedPlaintext({ 1 , 1 , 2 , 1 , 1 , 1, 3 , 2 });

	std::cout << "Input array X0 \n\t" << xP(0, 0) << std::endl;
	std::cout << "Input array X1 \n\t" << xP(0, 1) << std::endl;

	Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

	yP(0, 0) = cc->MakePackedPlaintext({ 0, 1, 2, 6, 1, 2, 3, 4 });
	std::cout << "Input array Y \n\t" << yP(0, 0) << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	std::cout << "Starting encryption of x" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<Poly>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	std::cout << "Starting encryption of y" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<Poly>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegressBatched(x, y, 8);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	std::cout << (*numerator)(0, 0)->GetPackedValue()[0] << "," << (*numerator)(1, 0)->GetPackedValue()[0] << std::endl;
	std::cout << (*denominator)(0, 0)->GetPackedValue()[0] << "," << (*denominator)(1, 0)->GetPackedValue()[0] << std::endl;

}
