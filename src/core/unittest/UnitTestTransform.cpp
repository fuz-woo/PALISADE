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
	This code tests the transform feature of the PALISADE lattice encryption library.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "../lib/lattice/dcrtpoly.h"
#include "math/backend.h"
#include "../lib/math/transfrm.h"
#include "../lib/math/transfrm.cpp"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilelement.h"
#include "utils/utilities.h"
#include "utils/debug.h"
#include "random"

using namespace std;
using namespace lbcrypto;

class UnitTestTransform : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/*---------------------------------------	TESTING METHODS OF TRANSFORM	  --------------------------------------------*/

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM

TEST(UTTransform, CRT_polynomial_multiplication){

	BigInteger primeModulus("113"); //65537
	usint cycloOrder = 8;
	usint n = cycloOrder / 2;

	BigInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(cycloOrder, primeModulus);

	BigVector a(n, primeModulus);
	a.SetValAtIndex(0, "1");
	a.SetValAtIndex(1, "2");
	a.SetValAtIndex(2, "4");
	a.SetValAtIndex(3, "1");
	BigVector b(a);

	BigVector A = ChineseRemainderTransformFTT<BigInteger,BigVector>::GetInstance().ForwardTransform(a, primitiveRootOfUnity, cycloOrder);
	BigVector B = ChineseRemainderTransformFTT<BigInteger,BigVector>::GetInstance().ForwardTransform(b, primitiveRootOfUnity, cycloOrder);

	BigVector AB = A*B;

	BigVector InverseFFTAB = ChineseRemainderTransformFTT<BigInteger,BigVector>::GetInstance().InverseTransform(AB, primitiveRootOfUnity, cycloOrder);

	BigVector expectedResult(n, primeModulus);
	expectedResult.SetValAtIndex(0, "94");
	expectedResult.SetValAtIndex(1, "109");
	expectedResult.SetValAtIndex(2, "11");
	expectedResult.SetValAtIndex(3, "18");

	EXPECT_EQ(expectedResult, InverseFFTAB);

}

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION IN ARBITRARY CYCLOTOMIC FILED USING CHINESE REMAINDER THEOREM

TEST(UTTransform, CRT_polynomial_multiplication_small) {

	bool dbg_flag = false;

	usint m = 22;
	BigInteger squareRootOfRoot(3750);
	BigInteger modulus(4621);
	BigInteger bigModulus("32043581647489");
	BigInteger bigRoot("31971887649898");
	usint n = GetTotient(m);

	DEBUG("m is " << m << " and n is " << n);
	auto cycloPoly =  GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulus);
	DEBUG("2");

	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly,modulus);
	DEBUG("3");

	BigVector a(n, modulus);
	a = { 1,2,3,4,5,6,7,8,9,10 };
	auto A = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(a, squareRootOfRoot, bigModulus, bigRoot, m);
	DEBUG("4");

	BigVector b(n, modulus);
	b = { 5,6,7,8,9,10,11,12,13,14 };
	auto B = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(b, squareRootOfRoot, bigModulus, bigRoot, m);
	DEBUG("5");

	auto C = A*B;
	DEBUG("6");

	auto c = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().InverseTransform(C, squareRootOfRoot, bigModulus, bigRoot, m);

	DEBUG("7");
	auto cCheck = PolynomialMultiplication(a, b);

	DEBUG("8");
	cCheck = PolyMod(cCheck, cycloPoly, modulus);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(cCheck.GetValAtIndex(i), c.GetValAtIndex(i));
	}

}


// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION IN ARBITRARY CYCLOTOMIC FILED USING CHINESE REMAINDER THEOREM

TEST(UTTransform, CRT_polynomial_multiplication_big_ring) {

	usint m = 1800;

	BigInteger modulus(14401);
	BigInteger bigModulus("1045889179649");
	BigInteger bigRoot("864331722621");
	BigInteger squareRootOfRoot("972");
	usint n = GetTotient(m);
	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulus);

	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly,modulus);

	BigVector a(n, modulus);
	a = { 1,2,3,4,5,6,7,8,9,10 };
	auto A = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(a, squareRootOfRoot,bigModulus,bigRoot, m);

	BigVector b(n, modulus);
	b = { 5,6,7,8,9,10,11,12,13,14 };
	auto B = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(b, squareRootOfRoot,bigModulus,bigRoot, m);

	auto C = A*B;

	auto c = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().InverseTransform(C, squareRootOfRoot,bigModulus,bigRoot, m);

	auto cCheck = PolynomialMultiplication(a, b);

	cCheck = PolyMod(cCheck, cycloPoly, modulus);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(cCheck.GetValAtIndex(i), c.GetValAtIndex(i));
	}

}

TEST(UTTransform, CRT_polynomial_multiplication_big_ring_prime_cyclotomics) {


	//usint m = 1733;
	//usint p = 2 * m + 1;
	//BigInteger modulusP(p);

	//BigInteger modulusQ("1152921504606909071");
	//BigInteger squareRootOfRoot("44343872016735288");

	//BigInteger bigmodulus("10889035741470030830827987437816582848513");
	//BigInteger bigroot("5879632101734955395039618227388702592012");

	usint m = 1733;

	BigInteger modulus("1152921504606909071");
	BigInteger bigModulus("10889035741470030830827987437816582848513");
	BigInteger bigRoot("5879632101734955395039618227388702592012");
	BigInteger squareRootOfRoot("44343872016735288");
	usint n = GetTotient(m);
	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulus);

	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);

	BigVector a(n, modulus);
	a = { 1,2,3,4,5,6,7,8,9,10 };
	auto A = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(a, squareRootOfRoot, bigModulus, bigRoot, m);

	BigVector b(n, modulus);
	b = { 5,6,7,8,9,10,11,12,13,14 };
	auto B = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(b, squareRootOfRoot, bigModulus, bigRoot, m);

	auto C = A*B;

	auto c = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().InverseTransform(C, squareRootOfRoot, bigModulus, bigRoot, m);

	auto cCheck = PolynomialMultiplication(a, b);

	cCheck = PolyMod(cCheck, cycloPoly, modulus);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(cCheck.GetValAtIndex(i), c.GetValAtIndex(i));
	}

}


// TEST CASE TO TEST FORWARD AND INVERSE TRANSFORM IN ARBITRARY CYCLOTOMIC FILED.
//CHECKING IF INVERSET-TRANSFORM(FORWARD-TRANSFORM(A)) = A.

TEST(UTTransform, CRT_CHECK_small_ring) {

	usint m = 22;
	BigInteger squareRootOfRoot(3750);
	BigInteger modulus(4621);
	BigInteger bigModulus("32043581647489");
	BigInteger bigRoot("31971887649898");
	usint n = GetTotient(m);

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulus);

	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly,modulus);

	BigVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };
	auto INPUT = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(input, squareRootOfRoot,bigModulus,bigRoot, m);


	auto inputCheck = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot,bigModulus,bigRoot, m);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(input.GetValAtIndex(i), inputCheck.GetValAtIndex(i));
	}

}

// TEST CASE TO TEST FORWARD AND INVERSE TRANSFORM IN ARBITRARY CYCLOTOMIC FILED.
//CHECKING IF INVERSET-TRANSFORM(FORWARD-TRANSFORM(A)) = A.

TEST(UTTransform, CRT_CHECK_big_ring) {

	usint m = 1800;

	BigInteger modulus(14401);
	BigInteger squareRootOfRoot("972");
	BigInteger bigModulus("1045889179649");
	BigInteger bigRoot("864331722621");
	usint n = GetTotient(m);
	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulus);

	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly,modulus);


	BigVector input(n, modulus);
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<> dis(0, 100); //generates a number in [0,100]
	for (usint i = 0; i < n; i++) {
		input.SetValAtIndex(i, BigInteger(dis(gen)));
	}
	
	auto output = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(input, squareRootOfRoot,bigModulus,bigRoot, m);

	auto recOut = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().InverseTransform(output, squareRootOfRoot,bigModulus,bigRoot, m);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(input.GetValAtIndex(i), recOut.GetValAtIndex(i));
	}

}

TEST(UTTransform, CRT_CHECK_small_ring_precomputed) {

	usint m = 22;
	BigInteger squareRootOfRoot(3750);
	BigInteger modulus(4621);
	usint n = GetTotient(m);

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulus);
	BigInteger nttmodulus("32043581647489");
	BigInteger nttroot("31971887649898");

	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulus);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetPreComputedNTTModulus(m, modulus, nttmodulus, nttroot);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);

	BigVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };

	auto INPUT = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(input, squareRootOfRoot,nttmodulus,nttroot, m);

	auto inputCheck = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, nttmodulus,nttroot, m);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(input.GetValAtIndex(i), inputCheck.GetValAtIndex(i));
	}

}

TEST(UTTransform, CRT_CHECK_very_big_ring_precomputed) {
	bool dbg_flag = false;
	usint m = 8422;
	DEBUG("1");
	BigInteger modulus("619578785044668429129510602549015713");//find a modulus that has 2*8422 root of unity and is 120 bit long
	BigInteger squareRootOfRoot("204851043665385327685783246012876507");
	usint n = GetTotient(m);
	DEBUG("UT GetTotient("<<m<<")= "<<n);

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulus);
	BigInteger nttmodulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041");
	BigInteger nttroot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");

	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().PreCompute(m, modulus);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetPreComputedNTTModulus(m, modulus, nttmodulus, nttroot);
	DEBUG("2");
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);
	DEBUG("3");
	BigVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };
	DEBUG("4");
	auto INPUT = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, nttmodulus, nttroot, m);
	DEBUG("5");
	auto inputCheck = ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, nttmodulus, nttroot, m);
	DEBUG("6");
	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(input.GetValAtIndex(i), inputCheck.GetValAtIndex(i));
	}

}
