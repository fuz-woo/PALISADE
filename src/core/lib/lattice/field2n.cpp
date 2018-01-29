/*
 * @file field2n.cpp - implementation of the power-of-2 fields.
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
#include "field2n.h"

namespace lbcrypto
{

//Constructor from ring element
Field2n::Field2n(const Poly & element)
{
	if (element.GetFormat() != COEFFICIENT) {
		throw std::logic_error("Poly not in coefficient representation");
	} else {
		// the value of element.at(i) is usually small - so a 64-bit integer is more than enough
		// this approach is much faster than BigInteger::ConvertToDouble
		BigInteger negativeThreshold(element.GetModulus() / Poly::Integer(2));
		for (size_t i = 0; i < element.GetLength(); i++) {
			if (element.at(i) > negativeThreshold)
				this->push_back((double)(int64_t)(-1 * (element.GetModulus() - element.at(i)).ConvertToInt()));
			//this->push_back(-(element.GetModulus() - element.at(i)).ConvertToDouble());
			else
				this->push_back((double)(int64_t)(element.at(i).ConvertToInt()));
			//this->push_back(element.at(i).ConvertToDouble());
		}
		this->format = COEFFICIENT;
	}
}

//Constructor from ring element
Field2n::Field2n(const NativePoly & element)
{
	if (element.GetFormat() != COEFFICIENT) {
		throw std::logic_error("Poly not in coefficient representation");
	} else {
		// the value of element.at(i) is usually small - so a 64-bit integer is more than enough
		// this approach is much faster than BigInteger::ConvertToDouble
		NativeInteger negativeThreshold(element.GetModulus()/ 2);
		for (size_t i = 0; i < element.GetLength(); i++) {
			if (element.at(i) > negativeThreshold)
				this->push_back((double)(int64_t)(-1 * (element.GetModulus() - element[i]).ConvertToInt()));
			else
				this->push_back((double)(int64_t)(element[i].ConvertToInt()));
		}
		this->format = COEFFICIENT;
	}
}

//Constructor from DCRTPoly ring element
Field2n::Field2n(const DCRTPoly & DCRTelement)
{
	if (DCRTelement.GetFormat() != COEFFICIENT) {
		throw std::logic_error("DCRTPoly not in coefficient representation");
	}
	else {
		// the value of element.at(i) is usually small - so a 64-bit integer is more than enough
		// Also it is assumed that the prime moduli are large enough (60 bits or more) - so the CRT interpolation is not needed
		// this approach is much faster than BigInteger::ConvertToDouble
		typename DCRTPoly::PolyType element = DCRTelement.GetElementAtIndex(0);
		NativeInteger negativeThreshold(element.GetModulus() / 2);
		for (size_t i = 0; i < element.GetLength(); i++) {
			if (element.at(i) > negativeThreshold)
				this->push_back((double)(int64_t)(-1 * (element.GetModulus() - element.at(i)).ConvertToInt()));
			//this->push_back(-(element.GetModulus() - element.at(i)).ConvertToDouble());
			else
				this->push_back((double)(int64_t)(element.at(i).ConvertToInt()));
			//this->push_back(element.at(i).ConvertToDouble());
		}
		this->format = COEFFICIENT;
	}
}

//Constructor from a ring element matrix
Field2n::Field2n(const Matrix<int64_t> &element)
{
	for (size_t i = 0; i < element.GetRows(); i++) {
		this->push_back(element(i, 0));
	}
	this->format = COEFFICIENT;
}

//Inverse operation for the field elements
Field2n Field2n::Inverse() const
{
	if (format == COEFFICIENT) {
		throw std::logic_error("Polynomial not in evaluation representation");
	} else {
		Field2n inverse(this->size(), EVALUATION);
		for (size_t i = 0; i < this->size(); i++) {
			double quotient = this->at(i).real() * this->at(i).real() + this->at(i).imag() * this->at(i).imag();
			inverse.at(i) = std::complex<double>(this->at(i).real() / quotient, -this->at(i).imag() / quotient);
		}
		return inverse;
	}
}

//Addition operation for field elements
Field2n Field2n::Plus(const Field2n &rhs) const
{
	if (format == rhs.GetFormat()) {
		Field2n sum(this->size(), rhs.GetFormat());
		for (size_t i = 0; i < this->size(); i++) {
			sum.at(i) = this->at(i) + rhs.at(i);
		}
		return sum;
	} else {
		throw std::logic_error("Operands are not in the same format");
	}
}

//Scalar addition operation for field elements
Field2n Field2n::Plus(double scalar) const
{
	if (format == COEFFICIENT) {
		Field2n sum(*this);
		sum.at(0) = this->at(0) + scalar;
		return sum;
	} else {
		throw std::logic_error("Field2n scalar addition is currently supported only for coefficient representation");
	}
}

//Substraction operation for field elements
Field2n Field2n::Minus(const Field2n &rhs) const
{
	if (format == rhs.GetFormat()) {
		Field2n difference(this->size(), rhs.GetFormat());
		for (size_t i = 0; i < this->size(); i++) {
			difference.at(i) = this->at(i) - rhs.at(i);
		}
		return difference;
	} else {
		throw std::logic_error("Operands are not in the same format");
	}
}

//Multiplication operation for field elements
Field2n Field2n::Times(const Field2n & rhs) const
{
	if (format == EVALUATION && rhs.GetFormat() == EVALUATION) {
		Field2n result(rhs.size(), EVALUATION);
		for (size_t i = 0; i < rhs.size(); i++) {
			result.at(i) = this->at(i) * rhs.at(i);
		}
		return result;
	} else {
		throw std::logic_error("At least one of the polynomials is not in evaluation representation");
	}
}

//Right shift operation for the field element
Field2n Field2n::ShiftRight()
{
	if (this->format == COEFFICIENT) {
		Field2n result(this->size(), COEFFICIENT);
		std::complex<double> temp = std::complex<double>(-1, 0) * this->at(this->size() - 1);
		for (size_t i = 0; i < this->size() - 1; i++) {
			result.at(i + 1) = this->at(i);
		}
		result.at(0) = temp;
		return result;
	} else {
		throw std::logic_error("Polynomial not in coefficient representation");
	}
}

//Transpose operation defined in the paper of perturbation sampling
Field2n Field2n::AutomorphismTransform(size_t i) const
{
	if (this->format == EVALUATION) {

		if (i % 2 == 0)
			throw std::logic_error("automorphism index should be odd\n");
		else {
			Field2n result(*this);
			usint m = this->size() * 2;

			for (usint j = 1; j < m; j = j + 2) {
				//usint newIndex = (j*iInverse) % m;
				usint newIndex = (j*i) % m;
				result.at((newIndex + 1) / 2 - 1) = this->at((j + 1) / 2 - 1);
			}
			return result;
		}

	} else {
		throw std::logic_error("Field2n Automorphism is only implemented for Evaluation format");
	}
}

//Transpose operation defined in the paper of perturbation sampling
Field2n Field2n::Transpose() const
{
	if (this->format == COEFFICIENT) {
		Field2n transpose(this->size(), COEFFICIENT);
		for (size_t i = 1; i < this->size(); i++) {
			transpose.at(i) = std::complex<double>(-1, 0) * this->at(this->size() - i);
		}
		transpose.at(0) = this->at(0);
		return transpose;
	} else {
		usint m = this->size()*2;
		return AutomorphismTransform(m - 1);
	}
}

//Function for extracting odd factors of the field element
Field2n Field2n::ExtractOdd() const
{
	if (this->format == COEFFICIENT) {
		Field2n odds(this->size() / 2, COEFFICIENT, true);
		for (size_t i = 0; i < odds.size(); i++) {
			odds.at(i) = this->at(1 + 2 * i);
		}
		return odds;
	} else {
		throw std::logic_error("Polynomial not in coefficient representation");
	}
}

//Function for extracting even factors of the field element
Field2n Field2n::ExtractEven() const
{
	if (this->format == COEFFICIENT) {
		Field2n evens(this->size() / 2, COEFFICIENT, true);
		for (size_t i = 0; i < evens.size(); i++) {
			evens.at(i) = this->at(0 + 2 * i);
		}
		return evens;
	} else {
		throw std::logic_error("Polynomial not in coefficient representation");
	}
}

//Permutation operation defined in the paper
Field2n Field2n::Permute() const
{
	if (this->format == COEFFICIENT) {
		Field2n permuted(this->size(), COEFFICIENT, true);
		int evenPtr = 0;
		int oddPtr = this->size() / 2;
		for (size_t i = 0; i < this->size(); i++) {
			if (i % 2 == 0) {
				permuted.at(evenPtr) = this->at(i);
				evenPtr++;
			} else {
				permuted.at(oddPtr) = this->at(i);
				oddPtr++;
			}
		}
		return permuted;
	} else {
		throw std::logic_error("Polynomial not in coefficient representation");
	}
}

//Inverse operation for permutation operation defined in the paper
Field2n Field2n::InversePermute() const
{
	if (this->format == COEFFICIENT) {
		Field2n invpermuted(this->size(), COEFFICIENT, true);
		size_t evenPtr = 0;
		size_t oddPtr = this->size() / 2;
		for (size_t i = 0; evenPtr < this->size() / 2; i += 2) {
			invpermuted.at(i) = this->at(evenPtr);
			invpermuted.at(i + 1) = this->at(oddPtr);
			evenPtr++;
			oddPtr++;
		}
		return invpermuted;
	} else {
		throw std::logic_error("Polynomial not in coefficient representation");
	}
}

//Operation for scalar multiplication
Field2n Field2n::ScalarMult(double d)
{
	Field2n scaled(this->size(), this->GetFormat(), true);
	for (size_t i = 0; i < this->size(); i++) {
		scaled.at(i) = d * this->at(i);
	}
	return scaled;
}

//Method for switching format of the field elements
void Field2n::SwitchFormat()
{
	if (format == COEFFICIENT) {
		std::vector<std::complex<double>> r = DiscreteFourierTransform::ForwardTransform(*this);

		for (size_t i = 0; i < r.size(); i++) {
			this->at(i) = r.at(i);
		}

		format = EVALUATION;
	} else {
		std::vector<std::complex<double>> r = DiscreteFourierTransform::InverseTransform(*this);

		for (size_t i = 0; i < r.size(); i++) {
			this->at(i) = r.at(i);
		}
		format = COEFFICIENT;

	}
}
}
