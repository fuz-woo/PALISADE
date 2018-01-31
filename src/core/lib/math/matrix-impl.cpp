/*
 * @file matrix-impl.cpp - matrix class implementations and type specific implementations
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

#ifndef _SRC_LIB_CORE_MATH_MATRIX_IMPL_CPP
#define _SRC_LIB_CORE_MATH_MATRIX_IMPL_CPP

#include "../utils/serializablehelper.h"
#include "../lattice/field2n.h"
#include "matrix.cpp"
#include "matrixstrassen.h"
using std::invalid_argument;

// this is the implementation of matrixes of things that are in core
// and that need template specializations

namespace lbcrypto {

  template class Matrix<Poly>;
  template class Matrix<NativePoly>;
  template class Matrix<BigInteger>;
  template class Matrix<BigVector>;
  template class Matrix<double>;
  template class Matrix<int>;
  template class Matrix<int64_t>;

  //Macros for convenient definitions of class implementations of special functions

  //Matrix<T>& Matrix<T>::Ones()
#define ONES_FOR_TYPE(T)			\
  template<>					\
  Matrix<T>& Matrix<T>::Ones() {		\
    for (size_t row = 0; row < rows; ++row) {	\
      for (size_t col = 0; col < cols; ++col) { \
	*data[row][col] = 1;			\
      }						\
    }						\
    return *this;				\
  }

  ONES_FOR_TYPE(int32_t)
  ONES_FOR_TYPE(double)
  ONES_FOR_TYPE(Poly)
  ONES_FOR_TYPE(NativePoly)
  ONES_FOR_TYPE(BigInteger)
  ONES_FOR_TYPE(BigVector)

  ONES_FOR_TYPE(Field2n)

//template<>
//Matrix<Plaintext>& Matrix<Plaintext>::Ones() {
//	Plaintext One( { 1 } );
//    for (size_t row = 0; row < rows; ++row) {
//        for (size_t col = 0; col < cols; ++col) {
//            *data[row][col] = One;
//        }
//    }
//    return *this;
//}

#define IDENTITY_FOR_TYPE(T)			\
  template<>					\
  Matrix<T>& Matrix<T>::Identity() {		\
    for (size_t row = 0; row < rows; ++row) {	\
      for (size_t col = 0; col < cols; ++col) { \
	if (row == col) {			\
	  *data[row][col] = 1;			\
	} else {				\
	  *data[row][col] = 0;			\
	}					\
      }						\
    }						\
    return *this;				\
  }

  IDENTITY_FOR_TYPE(int32_t)
  IDENTITY_FOR_TYPE(double)
  IDENTITY_FOR_TYPE(Poly)
  IDENTITY_FOR_TYPE(NativePoly)
  IDENTITY_FOR_TYPE(BigInteger)
  IDENTITY_FOR_TYPE(BigVector)
  IDENTITY_FOR_TYPE(Field2n)

  //Matrix<T> Matrix<T>::GadgetVector(int64_t base)
#define GADGET_FOR_TYPE(T)					\
  template<>							\
  Matrix<T> Matrix<T>::GadgetVector(int64_t base) const {	\
    Matrix<T> g(allocZero, rows, cols);				\
    auto base_matrix = allocZero();				\
    *base_matrix = base;					\
    g(0, 0) = 1;						\
    for (size_t col = 1; col < cols; ++col) {			\
      g(0, col) = g(0, col-1) * *base_matrix;			\
    }								\
    return g;							\
  }

  GADGET_FOR_TYPE(int32_t)
  GADGET_FOR_TYPE(int64_t)
  GADGET_FOR_TYPE(double)
  GADGET_FOR_TYPE(Poly)
  GADGET_FOR_TYPE(NativePoly)
  GADGET_FOR_TYPE(DCRTPoly)
  GADGET_FOR_TYPE(BigInteger)
  GADGET_FOR_TYPE(BigVector)
  GADGET_FOR_TYPE(Field2n)

  //template Matrix<T>::Norm() for types that have a norm
#define NORM_FOR_TYPE(T)			\
  template<>					\
  double Matrix<T>::Norm() const {		\
    double retVal = 0.0;			\
    double locVal = 0.0;			\
    for (size_t row = 0; row < rows; ++row) {	\
      for (size_t col = 0; col < cols; ++col) { \
	locVal = data[row][col]->Norm();	\
	if (locVal > retVal) {			\
	  retVal = locVal;			\
	}					\
      }						\
    }						\
    return retVal;				\
  }

  NORM_FOR_TYPE(Poly)
  NORM_FOR_TYPE(NativePoly)
  NORM_FOR_TYPE(DCRTPoly)

  //template Matrix<T>::Norm() for types that have NO norm
#define NONORM_FOR_TYPE(T)					\
  template<>							\
  double Matrix<T>::Norm() const {				\
    throw std::logic_error("Norm not defined for this type");	\
  }

  NONORM_FOR_TYPE(int32_t)
  NONORM_FOR_TYPE(double)
  NONORM_FOR_TYPE(BigInteger)
  NONORM_FOR_TYPE(BigVector)
  NONORM_FOR_TYPE(Field2n)


  //  split a vector of int32_t into a vector of ring elements with ring dimension n
#define SPLIT64_FOR_TYPE(T)						\
  template<>								\
  Matrix<T> SplitInt64IntoElements(Matrix<int64_t> const& other, size_t n, const shared_ptr<typename T::Params> params) { \
    auto zero_alloc = T::MakeAllocator(params, COEFFICIENT);		\
    size_t rows = other.GetRows() / n;					\
    Matrix<T> result(zero_alloc, rows, 1);				\
    for (size_t row = 0; row < rows; ++row) {				\
      std::vector<int64_t> values(n);					\
      for (size_t i = 0; i < n; ++i)					\
	values[i] = other(row*n + i, 0);				\
      result(row, 0) = values;						\
    }									\
    return result;							\
  }

  SPLIT64_FOR_TYPE(Poly)
  SPLIT64_FOR_TYPE(NativePoly)
  SPLIT64_FOR_TYPE(DCRTPoly)

  //  split a vector of BigInteger into a vector of ring elements with ring dimension n
#define SPLIT32ALT_FOR_TYPE(T)						\
  template<>								\
  Matrix<T> SplitInt32AltIntoElements(Matrix<int32_t> const& other, size_t n, const shared_ptr<typename T::Params> params) { \
  auto zero_alloc = T::MakeAllocator(params, COEFFICIENT);		\
  size_t rows = other.GetRows();					\
  Matrix<T> result(zero_alloc, rows, 1);				\
  for (size_t row = 0; row < rows; ++row) {				\
  std::vector<int32_t> values(n);					\
  for (size_t i = 0; i < n; ++i)					\
    values[i] = other(row, i);						\
  result(row, 0) = values;						\
}									\
  return result;							\
}

  SPLIT32ALT_FOR_TYPE(Poly)
  SPLIT32ALT_FOR_TYPE(NativePoly)
  SPLIT32ALT_FOR_TYPE(DCRTPoly)

  //  split a vector of BigInteger into a vector of ring elements with ring dimension n
#define SPLIT64ALT_FOR_TYPE(T)						\
  template<>								\
  Matrix<T> SplitInt64AltIntoElements(Matrix<int64_t> const& other, size_t n, const shared_ptr<typename T::Params> params) { \
  auto zero_alloc = T::MakeAllocator(params, COEFFICIENT);		\
  size_t rows = other.GetRows();					\
  Matrix<T> result(zero_alloc, rows, 1);				\
  for (size_t row = 0; row < rows; ++row) {				\
  std::vector<int64_t> values(n);					\
  for (size_t i = 0; i < n; ++i)					\
    values[i] = other(row, i);						\
  result(row, 0) = values;						\
}									\
  return result;							\
}

  SPLIT64ALT_FOR_TYPE(Poly)
  SPLIT64ALT_FOR_TYPE(NativePoly)
  SPLIT64ALT_FOR_TYPE(DCRTPoly)

  template<>
  void Matrix<Poly>::SetFormat(Format format) {
    for (size_t row = 0; row < rows; ++row) {
      for (size_t col = 0; col < cols; ++col) {
	data[row][col]->SetFormat(format);
      }
    }
  }

  template<>
  void Matrix<NativePoly>::SetFormat(Format format) {
    for (size_t row = 0; row < rows; ++row) {
      for (size_t col = 0; col < cols; ++col) {
	data[row][col]->SetFormat(format);
      }
    }
  }

  Matrix<BigInteger> Rotate(Matrix<Poly> const& inMat) {
    Matrix<Poly> mat(inMat);
    mat.SetFormat(COEFFICIENT);
    size_t n = mat(0,0).GetLength();
    BigInteger const& modulus = mat(0,0).GetModulus();
    size_t rows = mat.GetRows() * n;
    size_t cols = mat.GetCols() * n;
    Matrix<BigInteger> result(BigInteger::Allocator, rows, cols);
    for (size_t row = 0; row < mat.GetRows(); ++row) {
      for (size_t col = 0; col < mat.GetCols(); ++col) {
	for (size_t rotRow = 0; rotRow < n; ++rotRow) {
	  for (size_t rotCol = 0; rotCol < n; ++rotCol) {
	    result(row*n + rotRow, col*n + rotCol) =
                        mat(row, col).GetValues().at(
						      (rotRow - rotCol + n) % n
						      );
	    //  negate (mod q) upper-right triangle to account for
	    //  (mod x^n + 1)
	    if (rotRow < rotCol) {
	      result(row*n + rotRow, col*n + rotCol) = modulus.ModSub(result(row*n + rotRow, col*n + rotCol), modulus);
	    }
	  }
	}
      }
    }
    return result;
  }

  /**
   *  Each element becomes a square matrix with columns of that element's
   *  rotations in coefficient form.
   */
  Matrix<BigVector> RotateVecResult(Matrix<Poly> const& inMat) {
    Matrix<Poly> mat(inMat);
    mat.SetFormat(COEFFICIENT);
    size_t n = mat(0,0).GetLength();
    BigInteger const& modulus = mat(0,0).GetModulus();
    BigVector zero(1, modulus);
    size_t rows = mat.GetRows() * n;
    size_t cols = mat.GetCols() * n;
    auto singleElemBinVecAlloc = [=](){ return make_unique<BigVector>(1, modulus); };
    Matrix<BigVector> result(singleElemBinVecAlloc, rows, cols);
    for (size_t row = 0; row < mat.GetRows(); ++row) {
      for (size_t col = 0; col < mat.GetCols(); ++col) {
	for (size_t rotRow = 0; rotRow < n; ++rotRow) {
	  for (size_t rotCol = 0; rotCol < n; ++rotCol) {
	    BigVector& elem = result(row*n + rotRow, col*n + rotCol);
                    elem.at(0)=
		      mat(row, col).GetValues().at((rotRow - rotCol + n) % n);
	    //  negate (mod q) upper-right triangle to account for
	    //  (mod x^n + 1)
	    if (rotRow < rotCol) {
	      result(row*n + rotRow, col*n + rotCol) = zero.ModSub(elem);
	    }
	  }
	}
      }
    }
    return result;
  }

  template<>
  void Matrix<Poly>::SwitchFormat() {

    if (rows == 1)
      {
	for (size_t row = 0; row < rows; ++row) {
#ifdef OMP
#pragma omp parallel for
#endif
	  for (size_t col = 0; col < cols; ++col) {
	    data[row][col]->SwitchFormat();
	  }
	}
      }
    else
      {
	for (size_t col = 0; col < cols; ++col) {
#ifdef OMP
#pragma omp parallel for
#endif
	  for (size_t row = 0; row < rows; ++row) {
	    data[row][col]->SwitchFormat();
	  }
	}
      }
  }

  template<>
  void Matrix<NativePoly>::SwitchFormat() {

	if (rows == 1)
	{
		for (size_t row = 0; row < rows; ++row) {
#ifdef OMP
#pragma omp parallel for
#endif
			for (size_t col = 0; col < cols; ++col) {
				data[row][col]->SwitchFormat();
			}
		}
	}
	else
	{
		for (size_t col = 0; col < cols; ++col) {
#ifdef OMP
#pragma omp parallel for
#endif
			for (size_t row = 0; row < rows; ++row) {
				data[row][col]->SwitchFormat();
			}
		}
	}
}

template<>
  void Matrix<DCRTPoly>::SwitchFormat() {

    if (rows == 1)
      {
	for (size_t row = 0; row < rows; ++row) {
#ifdef OMP
#pragma omp parallel for
#endif
	  for (size_t col = 0; col < cols; ++col) {
	    data[row][col]->SwitchFormat();
	  }
	}
      }
    else
      {
	for (size_t col = 0; col < cols; ++col) {
#ifdef OMP
#pragma omp parallel for
#endif
	  for (size_t row = 0; row < rows; ++row) {
	    data[row][col]->SwitchFormat();
	  }
	}
      }
  }

  // YSP removed the Matrix class because it is not defined for all possible data types
  // needs to be checked to make sure input matrix is used in the right places
  // the assumption is that covariance matrix does not have large coefficients because it is formed by
  // discrete gaussians e and s; this implies int32_t can be used
  // This algorithm can be further improved - see the Darmstadt paper section 4.4
  Matrix<double> Cholesky(const Matrix<int32_t> &input) {
    //  http://eprint.iacr.org/2013/297.pdf
    if (input.GetRows() != input.GetCols()) {
      throw invalid_argument("not square");
    }
    size_t rows = input.GetRows();
    Matrix<double> result([]() { return make_unique<double>(); }, rows, rows);

    for (size_t i = 0; i < rows; ++i) {
      for (size_t j = 0; j < rows; ++j) {
	result(i, j) = input(i, j);
      }
    }

    for (size_t k = 0; k < rows; ++k) {
      result(k, k) = sqrt(result(k, k));
      //result(k, k) = sqrt(input(k, k));
      for (size_t i = k + 1; i < rows; ++i) {
	//result(i, k) = input(i, k) / result(k, k);
	result(i, k) = result(i, k) / result(k, k);
	//  zero upper-right triangle
	result(k, i) = 0;
      }
      for (size_t j = k + 1; j < rows; ++j) {
	for (size_t i = j; i < rows; ++i) {
	  if (result(i, k) != 0 && result(j, k) != 0) {
	    result(i, j) = result(i, j) - result(i, k) * result(j, k);
	    //result(i, j) = input(i, j) - result(i, k) * result(j, k);

	  }
	}
      }
    }
    return result;
  }

  void Cholesky(const Matrix<int32_t> &input, Matrix<double> &result) {
    //  http://eprint.iacr.org/2013/297.pdf
    if (input.GetRows() != input.GetCols()) {
      throw invalid_argument("not square");
    }
    size_t rows = input.GetRows();
    //	Matrix<LargeFloat> result([]() { return make_unique<LargeFloat>(); }, rows, rows);

    for (size_t i = 0; i < rows; ++i) {
      for (size_t j = 0; j < rows; ++j) {
	result(i, j) = input(i, j);
      }
    }

    for (size_t k = 0; k < rows; ++k) {

      result(k, k) = sqrt(input(k, k));

      for (size_t i = k + 1; i < rows; ++i) {
	//result(i, k) = input(i, k) / result(k, k);
	result(i, k) = result(i, k) / result(k, k);
	//  zero upper-right triangle
	result(k, i) = 0;
      }
      for (size_t j = k + 1; j < rows; ++j) {
	for (size_t i = j; i < rows; ++i) {
	  if (result(i, k) != 0 && result(j, k) != 0) {
	    result(i, j) = result(i, j) - result(i, k) * result(j, k);
	    //result(i, j) = input(i, j) - result(i, k) * result(j, k);

	  }
	}
      }
    }
  }


  //  Convert from Z_q to [-q/2, q/2]
  Matrix<int32_t> ConvertToInt32(const Matrix<BigInteger> &input, const BigInteger& modulus) {
    size_t rows = input.GetRows();
    size_t cols = input.GetCols();
    BigInteger negativeThreshold(modulus / BigInteger(2));
    Matrix<int32_t> result([](){ return make_unique<int32_t>(); }, rows, cols);
    for (size_t i = 0; i < rows; ++i) {
      for (size_t j = 0; j < cols; ++j) {
	if (input(i,j) > negativeThreshold) {
	  result(i,j) = -1 *(modulus - input(i,j)).ConvertToInt();
	} else {
	  result(i,j) = input(i,j).ConvertToInt();
	}
      }
    }
    return result;
  }

  Matrix<int32_t> ConvertToInt32(const Matrix<BigVector> &input, const BigInteger& modulus) {
    size_t rows = input.GetRows();
    size_t cols = input.GetCols();
    BigInteger negativeThreshold(modulus / BigInteger(2));
    Matrix<int32_t> result([](){ return make_unique<int32_t>(); }, rows, cols);
    for (size_t i = 0; i < rows; ++i) {
      for (size_t j = 0; j < cols; ++j) {
            const BigInteger& elem = input(i,j).at(0);
	if (elem > negativeThreshold) {
	  result(i,j) = -1*(modulus - elem).ConvertToInt();
	} else {
	  result(i,j) = elem.ConvertToInt();
	}
      }
    }
    return result;
  }

}

#endif
