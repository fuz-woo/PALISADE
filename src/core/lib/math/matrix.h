/**
 * @file matrix.h This code provide a templated matrix implementation
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

#ifndef LBCRYPTO_MATH_MATRIX_H
#define LBCRYPTO_MATH_MATRIX_H

#include <iostream>
#include <functional>
#include <cmath>
#include <stdexcept>
#include <omp.h>
//using std::function;

#include "../math/backend.h"
#include "../math/nbtheory.h"
#include "../math/distrgen.h"
#include "../lattice/poly.h"
#include "../lattice/dcrtpoly.h"
#include "../encoding/encodings.h"
#include "../utils/inttypes.h"
#include "../utils/utilities.h"
#include "../utils/memory.h"
using std::invalid_argument;

namespace lbcrypto {

template<class Element>
class Matrix : public Serializable {
public:
	typedef vector<vector<unique_ptr<Element>>> data_t;
	typedef vector<unique_ptr<Element>> data_row_t;
	typedef std::function<unique_ptr<Element>(void)> alloc_func;


	/**
	 * Constructor that initializes matrix values using a zero allocator
	 *
	 * @param &allocZero lambda function for zero initialization.
	 * @param &rows number of rows.
	 * @param &rows number of columns.
	 */
	Matrix(alloc_func allocZero, size_t rows, size_t cols) : data(), rows(rows), cols(cols), allocZero(allocZero) {
		data.resize(rows);
		for (auto row = data.begin(); row != data.end(); ++row) {
			for (size_t col = 0; col < cols; ++col) {
				row->push_back(allocZero());
			}
		}
	}

	//TODO: add Clear();

	/**
	 * Constructor that initializes matrix values using a distribution generation allocator
	 *
	 * @param &allocZero lambda function for zero initialization (used for initializing derived matrix objects)
	 * @param &rows number of rows.
	 * @param &rows number of columns.
	 * @param &allocGen lambda function for intialization using a distribution generator.
	 */
	Matrix(alloc_func allocZero, size_t rows, size_t cols, alloc_func allocGen);

	/**
	 * Constructor of an empty matrix; SetSize must be called on this matrix to use it
	 * Basically this exists to support deserializing
	 *
	 * @param &allocZero lambda function for zero initialization.
	 */
	Matrix(alloc_func allocZero) : data(), rows(0), cols(0), allocZero(allocZero) {}
	/**
	 * Set the size of a matrix, elements are zeroed out
	 *
	 * @param rows number of rows
	 * @param cols number of colums
	 */

	void SetSize(size_t rows, size_t cols) {
		if( this->rows != 0 || this->cols != 0 )
			throw std::logic_error("You cannot SetSize on a non-empty matrix");

		this->rows = rows;
		this->cols = cols;

		data.resize(rows);
		for (auto row = data.begin(); row != data.end(); ++row) {
			for (size_t col = 0; col < cols; ++col) {
				row->push_back(allocZero());
			}
		}
	}

	/**
	 * Copy constructor
	 *
	 * @param &other the matrix object to be copied
	 */
	Matrix(const Matrix<Element>& other) : data(), rows(other.rows), cols(other.cols), allocZero(other.allocZero) {
		deepCopyData(other.data);
	}

	/**
	 * Assignment operator
	 *
	 * @param &other the matrix object whose values are to be copied
	 * @return the resulting matrix
	 */
	Matrix<Element>& operator=(const Matrix<Element>& other);

	/**
	 * In-place change of the current matrix to a matrix of all ones
	 *
	 * @return the resulting matrix
	 */
	Matrix<Element>& Ones();

	/**
	 * Fill matrix using the same element
	 *
	 * @param &val the element the matrix is filled by
	 *
	 * @return the resulting matrix
	 */
	Matrix<Element>& Fill(const Element &val);

	/**
	 * In-place change of the current matrix to Identity matrix
	 *
	 * @return the resulting matrix
	 */
	Matrix<Element>& Identity();

	/**
	 * Sets the first row to be powers of two for when the base is two
	 *
	 * @param base is the base the digits of the matrix are represented in
	 * @return the resulting matrix
	 */
	Matrix<Element> GadgetVector(int64_t base = 2) const;

	/**
	 * Computes the infinity norm
	 *
	 * @return the norm in double format
	 */
	double Norm() const;

	/**
	 * Matrix multiplication
	 *
	 * @param &other the multiplier matrix
	 * @return the result of multiplication
	 */
	Matrix<Element> Mult(Matrix<Element> const& other) const;

	/**
	 * Operator for matrix multiplication
	 *
	 * @param &other the multiplier matrix
	 * @return the result of multiplication
	 */
	Matrix<Element> operator*(Matrix<Element> const& other) const {
		return Mult(other);
	}

	/**
	 * Multiplication of matrix by a scalar
	 *
	 * @param &other the multiplier element
	 * @return the result of multiplication
	 */
	Matrix<Element> ScalarMult(Element const& other) const {
		Matrix<Element> result(*this);
#pragma omp parallel for
		for (size_t col = 0; col < result.cols; ++col) {
			for (size_t row = 0; row < result.rows; ++row) {
				*result.data[row][col] = *result.data[row][col] * other;
			}
		}

		return result;
	}

	/**
	 * Operator for scalar multiplication
	 *
	 * @param &other the multiplier element
	 * @return the result of multiplication
	 */
	Matrix<Element> operator*(Element const& other) const {
		return ScalarMult(other);
	}

	/**
	 * Equality check
	 *
	 * @param &other the matrix object to compare to
	 * @return the boolean result
	 */
	bool Equal(Matrix<Element> const& other) const {
		if (rows != other.rows || cols != other.cols) {
			return false;
		}

		for (size_t i = 0; i < rows; ++i) {
			for (size_t j = 0; j < cols; ++j) {
				if (*data[i][j] != *other.data[i][j]) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Operator for equality check
	 *
	 * @param &other the matrix object to compare to
	 * @return the boolean result
	 */
	bool operator==(Matrix<Element> const& other) const {
		return Equal(other);
	}

	/**
	 * Operator for non-equality check
	 *
	 * @param &other the matrix object to compare to
	 * @return the boolean result
	 */
	bool operator!=(Matrix<Element> const& other) const {
		return !Equal(other);
	}

	/**
	 * Get property to access the data as a vector of vectors
	 *
	 * @return the data as vector of vectors
	 */
	const data_t& GetData() const {
		return data;
	}

	/**
	 * Get property to access the number of rows in the matrix
	 *
	 * @return the number of rows
	 */
	size_t GetRows() const {
		return rows;
	}

	/**
	 * Get property to access the number of columns in the matrix
	 *
	 * @return the number of columns
	 */
	size_t GetCols() const {
		return cols;
	}

	/**
	 * Get property to access the zero allocator for the matrix
	 *
	 * @return the lambda function corresponding to the element zero allocator
	 */
	alloc_func GetAllocator() const {
		return allocZero;
	}

	/**
	 * Sets the evaluation or coefficient representation for all ring elements that support the SetFormat method
	 *
	 * @param &format the enum value corresponding to coefficient or evaluation representation
	 */
	void SetFormat(Format format);


	/**
	 * Matrix addition
	 *
	 * @param &other the matrix to be added
	 * @return the resulting matrix
	 */
	Matrix<Element> Add(Matrix<Element> const& other) const {
		if (rows != other.rows || cols != other.cols) {
			throw invalid_argument("Addition operands have incompatible dimensions");
		}
		Matrix<Element> result(*this);
#pragma omp parallel for
		for (size_t j = 0; j < cols; ++j) {
			for (size_t i = 0; i < rows; ++i) {
				*result.data[i][j] += *other.data[i][j];
			}
		}
		return result;
	}


	/**
	 * Operator for matrix addition
	 *
	 * @param &other the matrix to be added
	 * @return the resulting matrix
	 */
	Matrix<Element> operator+(Matrix<Element> const& other) const {
		return this->Add(other);
	}

	/**
	 * Operator for in-place addition
	 *
	 * @param &other the matrix to be added
	 * @return the resulting matrix (same object)
	 */
	Matrix<Element>& operator+=(Matrix<Element> const& other);

	/**
	 * Matrix substraction
	 *
	 * @param &other the matrix to be substracted
	 * @return the resulting matrix
	 */
	Matrix<Element> Sub(Matrix<Element> const& other) const {
		if (rows != other.rows || cols != other.cols) {
			throw invalid_argument("Subtraction operands have incompatible dimensions");
		}
		Matrix<Element> result(allocZero, rows, other.cols);
#pragma omp parallel for
		for (size_t j = 0; j < cols; ++j) {
			for (size_t i = 0; i < rows; ++i) {
				*result.data[i][j] = *data[i][j] - *other.data[i][j];
			}
		}

		return result;
	}

	/**
	 * Operator for matrix substraction
	 *
	 * @param &other the matrix to be substracted
	 * @return the resulting matrix
	 */
	Matrix<Element> operator-(Matrix<Element> const& other) const {
		return this->Sub(other);
	}

	/**
	 * Operator for in-place matrix substraction
	 *
	 * @param &other the matrix to be substracted
	 * @return the resulting matrix (same object)
	 */
	Matrix<Element>& operator-=(Matrix<Element> const& other);

	/**
	 * Matrix transposition
	 *
	 * @return the resulting matrix
	 */
	Matrix<Element> Transpose() const;

	// YSP The signature of this method needs to be changed in the future
	/**
	 * Matrix determinant - found using Laplace formula with complexity O(d!), where d is the dimension
	 *
	 * @param *result where the result is stored
	 */
	void Determinant(Element *result) const;
	//Element Determinant() const;

	/**
	 * Cofactor matrix - the matrix of determinants of the minors A_{ij} multiplied by -1^{i+j}
	 *
	 * @return the cofactor matrix for the given matrix
	 */
	Matrix<Element> CofactorMatrix() const;

	/**
	 * Add rows to bottom of the matrix
	 *
	 * @param &other the matrix to be added to the bottom of current matrix
	 * @return the resulting matrix
	 */
	Matrix<Element>& VStack(Matrix<Element> const& other);

	/**
	 * Add columns the right of the matrix
	 *
	 * @param &other the matrix to be added to the right of current matrix
	 * @return the resulting matrix
	 */
	Matrix<Element>& HStack(Matrix<Element> const& other);

	/**
	 * Matrix indexing operator - writeable instance of the element
	 *
	 * @param &row row index
	 * @param &col column index
	 * @return the element at the index
	 */
	Element& operator()(size_t row, size_t col) {
		return *data[row][col];
	}

	/**
	 * Matrix indexing operator - read-only instance of the element
	 *
	 * @param &row row index
	 * @param &col column index
	 * @return the element at the index
	 */
	Element const& operator()(size_t row, size_t col) const {
		return *data[row][col];
	}

	/**
	 * Matrix row extractor
	 *
	 * @param &row row index
	 * @return the row at the index
	 */
	Matrix<Element> ExtractRow(size_t row) const {
		Matrix<Element> result(this->allocZero,1,this->cols);
		int i = 0;
		for (auto elem = this->GetData()[row].begin(); elem != this->GetData()[row].end(); ++elem) {
			result(0,i) = **elem;
			i++;
		}
		return result;
		//return *this;
	}

	/**
	 * Matrix rows extractor in a range from row_start to row_and; inclusive
	 *
	 * @param &row_start &row_end row indices
	 * @return the rows in the range delimited by indices inclusive
	 */
	inline Matrix<Element> ExtractRows(size_t row_start, size_t row_end) const {
		Matrix<Element> result(this->allocZero,row_end-row_start+1,this->cols);

		for(usint row=row_start; row<row_end+1; row++) {
			int i = 0;

			for (auto elem = this->GetData()[row].begin(); elem != this->GetData()[row].end(); ++elem) {
				result(row-row_start,i) = **elem;
				i++;
			}
		}

		return result;

	}

	friend std::ostream& operator<<(std::ostream& os, const Matrix<Element>& m) {
	    os << "[ ";
	    for (size_t row = 0; row < m.GetRows(); ++row) {
	        os << "[ ";
	        for (size_t col = 0; col < m.GetCols(); ++col) {
	            os << *m.GetData()[row][col] << " ";
	        }
	        os << "]\n";
	    }
	    os << " ]\n";
	    return os;
	}

	/**
	 * Call switch format for each (ring) element
	 *
	 */
	void SwitchFormat();


	/*
	 * Multiply the matrix by a vector whose elements are all 1's.  This causes the elements of each
	 * row of the matrix to be added and placed into the corresponding position in the output vector.
	 */
	Matrix<Element> MultByUnityVector() const;

	/*
	 * Multiply the matrix by a vector of random 1's and 0's, which is the same as adding select
	 * elements in each row together.
	 * Return a vector that is a rows x 1 matrix.
	 */
	Matrix<Element> MultByRandomVector(std::vector<int> ranvec) const;

	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const;

	/**
	 * Populate the object from the deserialization of the Serialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj);


private:
	data_t data;
	size_t rows;
	size_t cols;
	alloc_func allocZero;
	//mutable int NUM_THREADS = 1;

	//deep copy of data - used for copy constructor
	void deepCopyData(data_t const& src);

};


/**
 * Operator for scalar multiplication of matrix
 *
 * @param &e element
 * @param &M matrix
 * @return the resulting matrix
 */
template<class Element>
Matrix<Element> operator*(Element const& e, Matrix<Element> const& M) {
	return M.ScalarMult(e);
}

/**
 * Generates a matrix of rotations. See pages 7-8 of https://eprint.iacr.org/2013/297
 *
 * @param &inMat the matrix of power-of-2 cyclotomic ring elements to be rotated
 * @return the resulting matrix of big binary integers
 */
Matrix<BigInteger> Rotate(Matrix<Poly> const& inMat);

/**
 *  Each element becomes a square matrix with columns of that element's
 *  rotations in coefficient form. See pages 7-8 of https://eprint.iacr.org/2013/297
 *
 * @param &inMat the matrix of power-of-2 cyclotomic ring elements to be rotated
 * @return the resulting matrix of big binary integers
 */
Matrix<BigVector> RotateVecResult(Matrix<Poly> const& inMat);

/**
 *  Stream output operator
 *
 * @param &os stream
 * @param &m matrix to be outputted
 * @return the chained stream
 */
template<class Element>
std::ostream& operator<<(std::ostream& os, const Matrix<Element>& m);

/**
 * Gives the Choleshky decomposition of the input matrix.
 * The assumption is that covariance matrix does not have large coefficients because it is formed by
 * discrete gaussians e and s; this implies int32_t can be used
 * This algorithm can be further improved - see the Darmstadt paper section 4.4
 *  http://eprint.iacr.org/2013/297.pdf
 *
 * @param &input the matrix for which the Cholesky decomposition is to be computed
 * @return the resulting matrix of floating-point numbers
 */
Matrix<double> Cholesky(const Matrix<int32_t> &input);

void Cholesky(const Matrix<int32_t> &input, Matrix<double> &result);

/**
 * Convert a matrix of integers from BigInteger to int32_t
 * Convert from Z_q to [-q/2, q/2]
 *
 * @param &input the input matrix
 * @param &modulus the ring modulus
 * @return the resulting matrix of int32_t
 */
Matrix<int32_t> ConvertToInt32(const Matrix<BigInteger> &input, const BigInteger& modulus);

/**
 * Convert a matrix of BigVector to int32_t
 * Convert from Z_q to [-q/2, q/2]
 *
 * @param &input the input matrix
 * @param &modulus the ring modulus
 * @return the resulting matrix of int32_t
 */
Matrix<int32_t> ConvertToInt32(const Matrix<BigVector> &input, const BigInteger& modulus);

/**
 * Split a vector of int32_t into a vector of ring elements with ring dimension n
 *
 * @param &other the input matrix
 * @param &n the ring dimension
 * @param &params Poly element params
 * @return the resulting matrix of Poly
 */
template<typename Element>
Matrix<Element> SplitInt64IntoElements(Matrix<int64_t> const& other, size_t n, const shared_ptr<typename Element::Params> params);

/**
 * Another method for splitting a vector of int32_t into a vector of ring elements with ring dimension n
 *
 * @param &other the input matrix
 * @param &n the ring dimension
 * @param &params Poly element params
 * @return the resulting matrix of Poly
 */
template<typename Element>
Matrix<Element> SplitInt32AltIntoElements(Matrix<int32_t> const& other, size_t n, const shared_ptr<typename Element::Params> params);

/**
 * Split a vector of int64_t into a vector of ring elements with ring dimension n
 *
 * @param &other the input matrix
 * @param &n the ring dimension
 * @param &params Poly element params
 * @return the resulting matrix of Poly
 */
template<typename Element>
Matrix<Element> SplitInt64AltIntoElements(Matrix<int64_t> const& other, size_t n, const shared_ptr<typename Element::Params> params);
}
#endif // LBCRYPTO_MATH_MATRIX_H
