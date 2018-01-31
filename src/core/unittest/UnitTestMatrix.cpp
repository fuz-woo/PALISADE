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
  This code exercises the math libraries of the PALISADE lattice encryption library.
*/


#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include "math/matrix.h"
#include "math/matrixstrassen.cpp"

//using namespace std;
using namespace lbcrypto;


class UnitTestMatrix : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/************************************************/
/*	TESTING METHODS OF BININT CLASS		*/
/************************************************/

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/

static function<unique_ptr<Poly>()> secureIL2nAlloc() {
    BigInteger secureModulus("8590983169");
    BigInteger secureRootOfUnity("4810681236");
    return Poly::MakeAllocator(
        shared_ptr<ILParams>( new ILParams(
        2048, secureModulus, secureRootOfUnity) ),
        EVALUATION
        );
}

static function<unique_ptr<Poly>()> fastIL2nAlloc() {
	usint m = 16;
	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");
    return Poly::MakeAllocator(
        shared_ptr<ILParams>( new ILParams(
        m, modulus, rootOfUnity) ),
        EVALUATION
        );
}

static function<unique_ptr<Poly>()> fastUniformIL2nAlloc() {
	usint m = 16;
	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");
	return Poly::MakeDiscreteUniformAllocator(
		shared_ptr<ILParams>(new ILParams(
			m, modulus, rootOfUnity)),
		EVALUATION
	);
}

TEST(UTMatrix,serializer) {
	Matrix<int32_t> m([](){return make_unique<int32_t>();}, 3, 5);
}

TEST(UTMatrix,basic_il2n_math){
    Matrix<Poly> z(secureIL2nAlloc(), 2,2);
    Matrix<Poly> n = Matrix<Poly>(secureIL2nAlloc(), 2, 2).Ones();
    Matrix<Poly> I = Matrix<Poly>(secureIL2nAlloc(), 2, 2).Identity();
    I.SetFormat(COEFFICIENT);
    I.SetFormat(EVALUATION);
    EXPECT_EQ(n, I*n);

    n -= n;
    EXPECT_EQ(n, z);

    //Matrix<Poly> m = Matrix<Poly>(secureIL2nAlloc(), 2, 2).Ones();
    //m.Fill(2);
    //n.Fill(1);
    //n = n + n;
    //EXPECT_EQ(n, m);
}

TEST(UTMatrix,basic_int_math){
    Matrix<BigInteger> z(BigInteger::Allocator, 2,2);
    Matrix<BigInteger> n = Matrix<BigInteger>(BigInteger::Allocator, 2, 2).Ones();
    Matrix<BigInteger> I = Matrix<BigInteger>(BigInteger::Allocator, 2, 2).Identity();
    EXPECT_EQ(n, I*n);
    n -= n;
    EXPECT_EQ(n, z);
}

TEST(UTMatrix,basic_intvec_math){

  bool dbg_flag = false;

    BigInteger modulus("67108913");
    DEBUG("1");
    auto singleAlloc = [=](){ return make_unique<BigVector>(1, modulus); };
    DEBUG("2");
    Matrix<BigVector> z(singleAlloc, 2,2);
    DEBUG("3");
    Matrix<BigVector> n = Matrix<BigVector>(singleAlloc, 2, 2).Ones();
    DEBUG("4");
    Matrix<BigVector> I = Matrix<BigVector>(singleAlloc, 2, 2).Identity();
    DEBUG("5");
    DEBUG("z mod 00 "<<z(0,0).GetModulus().ToString());
    DEBUG("z mod 01 "<<z(0,1).GetModulus().ToString());
    DEBUG("z mod 10 "<<z(1,0).GetModulus().ToString());
    DEBUG("z mod 1 1 "<<z(1,1).GetModulus().ToString());
    DEBUG("n mod "<<n(0,0).GetModulus().ToString());
    DEBUG("I mod "<<I(0,0).GetModulus().ToString());
    EXPECT_EQ(n, I*n);
    DEBUG("6");
    n -= n;
    DEBUG("7");
    EXPECT_EQ(n, z);
    DEBUG("8");
}

TEST(UTMatrix, transpose){
    Matrix<Poly> n = Matrix<Poly>(secureIL2nAlloc(), 4, 2).Ones();
    Matrix<Poly> nT = Matrix<Poly>(n).Transpose();
    Matrix<Poly> I = Matrix<Poly>(secureIL2nAlloc(), 2, 2).Identity();
    EXPECT_EQ(nT, I*nT);
}

TEST(UTMatrix, scalar_mult){
    Matrix<Poly> n = Matrix<Poly>(secureIL2nAlloc(), 4, 2).Ones();
    auto one = secureIL2nAlloc()();
    *one = 1;
    EXPECT_EQ(n, *one*n);
    EXPECT_EQ(n, n**one);

    //auto two = secureIL2nAlloc()();
    //Matrix<Poly> twos = Matrix<Poly>(secureIL2nAlloc(), 4, 2).Fill(2);
    //*two = 2;
    //EXPECT_EQ(*two*n, twos);
    //EXPECT_EQ(n**two, twos);
}

TEST(UTMatrix, Poly_mult_square_matrix) {

	int32_t dimension = 8;

	Matrix<Poly> A = Matrix<Poly>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	Matrix<Poly> B = Matrix<Poly>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	Matrix<Poly> C = Matrix<Poly>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	Matrix<Poly> I = Matrix<Poly>(fastIL2nAlloc(), dimension, dimension).Identity();

	EXPECT_EQ(A, A*I) << "Matrix multiplication of two Poly2Ns: A = AI - failed.\n";
	EXPECT_EQ(A, I*A) << "Matrix multiplication of two Poly2Ns: A = IA - failed.\n";

	EXPECT_EQ((A*B).Transpose(), B.Transpose()*A.Transpose()) << "Matrix multiplication of two Poly2Ns: (A*B)^T = B^T*A^T - failed.\n";

	EXPECT_EQ(A*B*C, A*(B*C)) << "Matrix multiplication of two Poly2Ns: A*B*C = A*(B*C) - failed.\n";
	EXPECT_EQ(A*B*C, (A*B)*C) << "Matrix multiplication of two Poly2Ns: A*B*C = (A*B)*C - failed.\n";

}



TEST(UTMatrix, Poly_mult_square_matrix_caps) {

	int32_t dimension = 16;

	MatrixStrassen<Poly> A = MatrixStrassen<Poly>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	MatrixStrassen<Poly> B = MatrixStrassen<Poly>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	MatrixStrassen<Poly> C = MatrixStrassen<Poly>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	MatrixStrassen<Poly> I = MatrixStrassen<Poly>(fastIL2nAlloc(), dimension, dimension).Identity();

	//EXPECT_EQ((A.Mult(B))(0, 0), (A.MultiplyCAPS(B, 2))(0, 0)) << "CAPS matrix multiplication of two Poly2Ns doesn't agree with Mult: A.Mult(B), A.MultiplyCAPS(B,2) - failed.\n";
	EXPECT_EQ(A, A.Mult(I, 2)) << "CAPS matrix multiplication of two Poly2Ns: A = AI - failed.\n";
	EXPECT_EQ(A, I.Mult(A, 2)) << "Matrix multiplication of two Poly2Ns: A = IA - failed.\n";

	EXPECT_EQ((A.Mult(B, 2)).Transpose(), B.Transpose().Mult(A.Transpose(), 2)) << "Matrix multiplication of two Poly2Ns: (A.MultiplyCAPS(B,2)).Transpose(), B.Transpose().MultiplyCAPS(A.Transpose(),2) - failed.\n";

	EXPECT_EQ(A.Mult(B, 2).Mult(C, 2), A.Mult((B.Mult(C, 2)), 2)) << "Matrix multiplication of two Poly2Ns: A.MultiplyCAPS(B,2).MultiplyCAPS(C,2), A.MultiplyCAPS((B.MultiplyCAPS(C,2)),2) - failed.\n";
	EXPECT_EQ(A.Mult(B, 2).Mult(C, 2), (A.Mult(B, 2)).Mult(C, 2)) << "Matrix multiplication of two Poly2Ns: A.MultiplyCAPS(B,2).MultiplyCAPS(C,2), (A.MultiplyCAPS(B,2)).MultiplyCAPS(C,2) - failed.\n";

}


inline void expect_close(double a, double b) {
	EXPECT_LE(fabs(a - b), 10e-8);
}

TEST(UTMatrix, cholesky) {
        bool dbg_flag = false;
        Matrix<int32_t> m([]() { return make_unique<int32_t>(); }, 2, 2);
	m(0, 0) = 20;
	m(0, 1) = 4;
	m(1, 0) = 4;
	m(1, 1) = 10;

	auto c = Cholesky(m);
	DEBUGEXP(c);
	EXPECT_LE(fabs(4.47213595 - c(0, 0)), 1e-8);
	EXPECT_LE(fabs(0 - c(0, 1)), 1e-8);
	EXPECT_LE(fabs(.89442719 - c(1, 0)), 1e-8);
	EXPECT_LE(fabs(3.03315018 - c(1, 1)), 1e-8);
	auto cc = c*c.Transpose();
	EXPECT_LE(fabs(m(0, 0) - cc(0, 0)), 1e-8);
	EXPECT_LE(fabs(m(0, 1) - cc(0, 1)), 1e-8);
	EXPECT_LE(fabs(m(1, 0) - cc(1, 0)), 1e-8);
	EXPECT_LE(fabs(m(1, 1) - cc(1, 1)), 1e-8);
	DEBUGEXP(cc);
}

TEST(UTMatrix, gadget_vector) {
    Matrix<Poly> n = Matrix<Poly>(secureIL2nAlloc(), 1, 4).GadgetVector();
	auto v = secureIL2nAlloc()();
	*v = 1;
    EXPECT_EQ(*v, n(0,0));
	*v = 2;
    EXPECT_EQ(*v, n(0,1));
	*v = 4;
    EXPECT_EQ(*v, n(0,2));
	*v = 8;
    EXPECT_EQ(*v, n(0,3));
}

TEST(UTMatrix, rotate_vec_result) {
    Matrix<Poly> n = Matrix<Poly>(fastIL2nAlloc(), 1, 2).Ones();
    const Poly::Integer& modulus = n(0,0).GetModulus();
    n.SetFormat(COEFFICIENT);
    n(0,0).at(2)= 1;
    Matrix<Poly::Vector> R = RotateVecResult(n);
	EXPECT_EQ(8U, R.GetRows());
	EXPECT_EQ(16U, R.GetCols());
	EXPECT_EQ(Poly::Vector::Single(1, modulus), R(0,0));

	Poly::Integer negOne = n(0,0).GetModulus() - Poly::Integer(1);
	Poly::Vector negOneVec = Poly::Vector::Single(negOne, modulus);
	EXPECT_EQ(negOneVec, R(0,6));
	EXPECT_EQ(negOneVec, R(1,7));

    auto singleAlloc = [=](){ return make_unique<Poly::Vector>(1, modulus); };
	EXPECT_EQ(*singleAlloc(), R(0,6 + 8));
	EXPECT_EQ(*singleAlloc(), R(1,7 + 8));

}

TEST(UTMatrix, rotate) {
    Matrix<Poly> n = Matrix<Poly>(fastIL2nAlloc(), 1, 2).Ones();

    n.SetFormat(COEFFICIENT);
    n(0,0).at(2)= 1;
    Matrix<Poly::Integer> R = Rotate(n);
	EXPECT_EQ(8U, R.GetRows());
	EXPECT_EQ(16U, R.GetCols());
	EXPECT_EQ(BigInteger(1), R(0,0));

	Poly::Integer negOne = n(0,0).GetModulus() - Poly::Integer(1);
	EXPECT_EQ(negOne, R(0,6));
	EXPECT_EQ(negOne, R(1,7));

	EXPECT_EQ(BigInteger(0), R(0,6 + 8));
	EXPECT_EQ(BigInteger(0), R(1,7 + 8));

}

TEST(UTMatrix, vstack) {
    Matrix<Poly> n = Matrix<Poly>(secureIL2nAlloc(), 4, 2).Ones();
    Matrix<Poly> m = Matrix<Poly>(secureIL2nAlloc(), 8, 2).Ones();
    EXPECT_EQ(m, n.VStack(n));
}

TEST(UTMatrix, hstack) {
    Matrix<Poly> n = Matrix<Poly>(secureIL2nAlloc(), 2, 2).Ones();
    Matrix<Poly> m = Matrix<Poly>(secureIL2nAlloc(), 2, 4).Ones();
    EXPECT_EQ(m, n.HStack(n));
}

TEST(UTMatrix, norm) {
    Matrix<Poly> n = Matrix<Poly>(secureIL2nAlloc(), 2, 2).Ones();
    EXPECT_EQ(1.0, n.Norm());
    Matrix<Poly> m = Matrix<Poly>(secureIL2nAlloc(), 2, 2).Identity();
    EXPECT_EQ(1.0, m.Norm());
}

// Checks the implementantation of determinant based on a 3x3 matrix
TEST(UTMatrix, determinant) {
	
	Matrix<int32_t> m([]() { return make_unique<int32_t>(); }, 3, 3);
	m(0, 0) = 1;
	m(0, 1) = 2;
	m(0, 2) = 1;
	m(1, 0) = -1;
	m(1, 1) = 1;
	m(1, 2) = 1;
	m(2, 0) = 1;
	m(2, 1) = 2;
	m(2, 2) = 3;

	//int32_t determinant = m.Determinant();
	int32_t determinant = 0;
	m.Determinant(&determinant);
	EXPECT_EQ(6, determinant);

}

// Checks the implementantation of cofactor matrix based on a 3x3 matrix
TEST(UTMatrix, cofactorMatrix) {

	Matrix<int32_t> m([]() { return make_unique<int32_t>(); }, 3, 3);
	m(0, 0) = 1;
	m(0, 1) = 2;
	m(0, 2) = 0;
	m(1, 0) = -1;
	m(1, 1) = 1;
	m(1, 2) = 1;
	m(2, 0) = 1;
	m(2, 1) = 2;
	m(2, 2) = 3;

	Matrix<int32_t> r([]() { return make_unique<int32_t>(); }, 3, 3);
	r(0, 0) = 1;
	r(0, 1) = 4;
	r(0, 2) = -3;
	r(1, 0) = -6;
	r(1, 1) = 3;
	r(1, 2) = 0;
	r(2, 0) = 2;
	r(2, 1) = -1;
	r(2, 2) = 3;

	EXPECT_EQ(r, m.CofactorMatrix());

}
