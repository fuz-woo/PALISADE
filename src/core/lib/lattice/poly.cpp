/*
 * @file  poly.cpp - implementation of the integer lattice
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

#include "../lattice/backend.h"
#include <fstream>
#include <cmath>

#define DEMANGLER //used for the demangling type namefunction.

#ifdef DEMANGLER

#include <string>
#include <cstdlib>
#include <cxxabi.h>


template<typename T>
std::string type_name()
{
	int status;
	std::string tname = typeid(T).name();
	char *demangled_name = abi::__cxa_demangle(tname.c_str(), NULL, NULL, &status);
	if(status == 0) {
		tname = demangled_name;
		std::free(demangled_name);
	}
	return tname;
}


#endif

namespace lbcrypto
{

template<typename VecType>
PolyImpl<VecType>::PolyImpl() : m_values(nullptr), m_format(EVALUATION)
{
}

template<typename VecType>
PolyImpl<VecType>::PolyImpl(const shared_ptr<PolyImpl::Params> params, Format format, bool initializeElementToZero) : m_values(nullptr), m_format(format)
{
	m_params = params;

	if (initializeElementToZero) {
		this->SetValuesToZero();
	}
}

template<typename VecType>
PolyImpl<VecType>::PolyImpl(bool initializeElementToMax, const shared_ptr<PolyImpl::Params> params, Format format) : m_values(nullptr), m_format(format)
{
	m_params = params;

	if(initializeElementToMax) {
		this->SetValuesToMax();

	}
}

template<typename VecType>
PolyImpl<VecType>::PolyImpl(const DggType &dgg, const shared_ptr<PolyImpl::Params> params, Format format)
{

	m_params = params;

	usint vectorSize = params->GetRingDimension();
	m_values = make_unique<VecType>(dgg.GenerateVector(vectorSize, params->GetModulus()));
	(*m_values).SetModulus(params->GetModulus());
	m_format = COEFFICIENT;

	if (format == EVALUATION)
		this->SwitchFormat();

}

template<typename VecType>
PolyImpl<VecType>::PolyImpl( DiscreteUniformGeneratorImpl<VecType> &dug, const shared_ptr<PolyImpl::Params> params, Format format)
{

	m_params = params;

	usint vectorSize = params->GetRingDimension();
	dug.SetModulus(params->GetModulus());
	m_values = make_unique<VecType>(dug.GenerateVector(vectorSize));
	(*m_values).SetModulus(params->GetModulus());

	m_format = COEFFICIENT;

	if (format == EVALUATION)
		this->SwitchFormat();

}

template<typename VecType>
PolyImpl<VecType>::PolyImpl(const BinaryUniformGeneratorImpl<VecType> &bug, const shared_ptr<PolyImpl::Params> params, Format format)
{
	bool dbg_flag = false;
	m_params = params;

	usint vectorSize = params->GetRingDimension();
	m_values = make_unique<VecType>(bug.GenerateVector(vectorSize, params->GetModulus()));
	//(*m_values).SetModulus(ilParams.GetModulus());
	DEBUG("why does this have no modulus");
	m_format = COEFFICIENT;

	if (format == EVALUATION)
		this->SwitchFormat();
}

template<typename VecType>
PolyImpl<VecType>::PolyImpl(const TernaryUniformGeneratorImpl<VecType> &tug, const shared_ptr<PolyImpl::Params> params, Format format)
{

	m_params = params;

	usint vectorSize = params->GetRingDimension();
	m_values = make_unique<VecType>(tug.GenerateVector(vectorSize, params->GetModulus()));
	(*m_values).SetModulus(params->GetModulus());
	m_format = COEFFICIENT;

	if (format == EVALUATION)
		this->SwitchFormat();

}

template<typename VecType>
PolyImpl<VecType>::PolyImpl(const PolyImpl &element, shared_ptr<PolyImpl::Params>) : m_format(element.m_format), m_params(element.m_params)
{
	bool dbg_flag = false;
	if (!IsEmpty()){
		DEBUG("in ctor & m_values was "<<*m_values);
	} else {
		DEBUG("in ctor & m_values are empty ");
	}
	if (element.m_values == nullptr) {
		DEBUG("in ctor & m_values copy nullptr ");
		m_values = nullptr;
	} else {

		m_values = make_unique<VecType>(*element.m_values); //this is a copy
		DEBUG("in ctor & m_values now "<<*m_values);
	}
}

template<typename VecType>
PolyImpl<VecType>::PolyImpl(
		const PolyNative &rhs, Format format)
		{

	m_format = rhs.GetFormat();

	m_params = shared_ptr<PolyImpl::Params>(new PolyImpl::Params(rhs.GetParams()->GetCyclotomicOrder(),
			rhs.GetParams()->GetModulus().ConvertToInt(),rhs.GetParams()->GetRootOfUnity().ConvertToInt()));

	VecType temp(m_params->GetCyclotomicOrder() / 2);
	temp.SetModulus(m_params->GetModulus());

	for (size_t i = 0; i < rhs.GetLength(); i++)
		temp[i] = (rhs.GetValues())[i].ConvertToInt();

	this->SetValues(std::move(temp), rhs.GetFormat());

	if (format != rhs.GetFormat())
		SwitchFormat();

		}

//this is the move
template<typename VecType>
PolyImpl<VecType>::PolyImpl(PolyImpl &&element, shared_ptr<PolyImpl::Params>) : m_format(element.m_format), m_params(element.m_params)
//m_values(element.m_values) //note this becomes move below
{
	bool dbg_flag = false;
	if (!IsEmpty()){
		DEBUG("in ctor && m_values was "<<*m_values);
	}else{
		DEBUG("in ctor && m_values was empty");
	}
	if (!element.IsEmpty()) {
		m_values = std::move(element.m_values);
		DEBUG("in ctor && m_values was "<<*m_values);

	} else{
		DEBUG("in ctor && m_values remains empty");
		m_values = nullptr;
	}
}

template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(const PolyImpl &rhs)
{
	if (this != &rhs) {
		if (m_values == nullptr && rhs.m_values != nullptr) {
			m_values = make_unique<VecType>(*rhs.m_values);
		} else if (rhs.m_values != nullptr) {
			*this->m_values = *rhs.m_values; //this is a BBV copy
		}
		this->m_params = rhs.m_params;
		this->m_format = rhs.m_format;
	}

	return *this;
}

template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs)
{
	static Integer ZERO(0);
	usint len = rhs.size();
	if (!IsEmpty()) {
		usint vectorLength = this->m_values->GetLength();

		for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
			if (j < len) {
				this->operator[](j)= Integer(*(rhs.begin() + j));
			} else {
				this->operator[](j)= ZERO;
			}
		}

	} else {

		VecType temp(m_params->GetCyclotomicOrder() / 2);
		temp.SetModulus(m_params->GetModulus());
		temp = rhs;
		this->SetValues(std::move(temp), m_format);
	}
	return *this;
}

template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::vector<int64_t> rhs)
{
	static Integer ZERO(0);
	usint len = rhs.size();
	if (!IsEmpty()) {
		usint vectorLength = this->m_values->GetLength();

		for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
			if (j < len) {
				Integer tempBI;
				uint64_t tempInteger;
				if (*(rhs.begin() + j) < 0)
				{
					tempInteger = -*(rhs.begin() + j);
					tempBI = m_params->GetModulus() - Integer(tempInteger);
				}
				else
				{
					tempInteger = *(rhs.begin() + j);
					tempBI = Integer(tempInteger);
				}
				operator[](j)= tempBI;
			}
			else {
				operator[](j)= ZERO;
			}
		}

	}
	else {

		usint vectorLength = m_params->GetCyclotomicOrder() / 2;
		VecType temp(vectorLength);
		temp.SetModulus(m_params->GetModulus());
		for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
			if (j < len) {
				Integer tempBI;
				uint64_t tempInteger;
				if (*(rhs.begin() + j) < 0)
				{
					tempInteger = -*(rhs.begin() + j);
					tempBI = m_params->GetModulus() - Integer(tempInteger);
				}
				else
				{
					tempInteger = *(rhs.begin() + j);
					tempBI = Integer(tempInteger);
				}
				temp.operator[](j)= tempBI;
			}
			else {
				temp.operator[](j)= ZERO;
			}
		}
		this->SetValues(std::move(temp), m_format);
	}
	m_format = COEFFICIENT;
	return *this;
}

template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::vector<int32_t> rhs)
{
	static Integer ZERO(0);
	usint len = rhs.size();
	if (!IsEmpty()) {
		usint vectorLength = this->m_values->GetLength();

		for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
			if (j < len) {
				Integer tempBI;
				uint64_t tempInteger;
				if (*(rhs.begin() + j) < 0)
				{
					tempInteger = -*(rhs.begin() + j);
					tempBI = m_params->GetModulus() - Integer(tempInteger);
				}
				else
				{
					tempInteger = *(rhs.begin() + j);
					tempBI = Integer(tempInteger);
				}
				operator[](j)= tempBI;
			}
			else {
				operator[](j)= ZERO;
			}
		}

	}
	else {

		usint vectorLength = m_params->GetCyclotomicOrder() / 2;
		VecType temp(vectorLength);
		temp.SetModulus(m_params->GetModulus());
		for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
			if (j < len) {
				Integer tempBI;
				uint64_t tempInteger;
				if (*(rhs.begin() + j) < 0)
				{
					tempInteger = -*(rhs.begin() + j);
					tempBI = m_params->GetModulus() - Integer(tempInteger);
				}
				else
				{
					tempInteger = *(rhs.begin() + j);
					tempBI = Integer(tempInteger);
				}
				temp.operator[](j)= tempBI;
			}
			else {
				temp.operator[](j)= ZERO;
			}
		}
		this->SetValues(std::move(temp), m_format);
	}
	m_format = COEFFICIENT;
	return *this;
}

template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::initializer_list<std::string> rhs)
{
	static Integer ZERO(0);
	usint len = rhs.size();
	if (!IsEmpty()) {
		usint vectorLength = this->m_values->GetLength();

		for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
			if (j < len) {
				m_values->operator[](j)= *(rhs.begin() + j);
			} else {
				m_values->operator[](j)= ZERO;
			}
		}

	} else {

		VecType temp(m_params->GetRingDimension());
		temp.SetModulus(m_params->GetModulus());
		temp = rhs;
		this->SetValues(std::move(temp), m_format);
	}
	return *this;
}


template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(PolyImpl &&rhs)
{

	if (this != &rhs) {
		m_values = std::move(rhs.m_values);
		m_params = rhs.m_params;
		m_format = rhs.m_format;
	}

	return *this;
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::CloneParametersOnly() const
{
	PolyImpl<VecType> result(this->m_params, this->m_format);
	return result;
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType> &dgg, Format format) const
{
	PolyImpl<VecType> result(dgg, m_params, format);
	return result;
}

//If this is in EVALUATION then just set all the values = val
template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(uint64_t val)
{
	m_format = EVALUATION;
	if (m_values == nullptr){
		m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
	}
	for (size_t i = 0; i < m_values->GetLength(); ++i) {
		this->operator[](i)= Integer(val);
	}
	return *this;
}

template<typename VecType>
PolyImpl<VecType>::~PolyImpl()	{}

template<typename VecType>
const VecType &PolyImpl<VecType>::GetValues() const
{
	if (m_values == 0)
		throw std::logic_error("No values in PolyImpl");
	return *m_values;
}

template<typename VecType>
Format PolyImpl<VecType>::GetFormat() const
{
	return m_format;
}

template<typename VecType>
typename PolyImpl<VecType>::Integer& PolyImpl<VecType>::at(usint i)
{
	if (m_values == 0)
		throw std::logic_error("No values in PolyImpl");
	return m_values->at(i);
}

template<typename VecType>
const typename PolyImpl<VecType>::Integer& PolyImpl<VecType>::at(usint i) const
{
	if (m_values == 0)
		throw std::logic_error("No values in PolyImpl");
	return m_values->at(i);
}

template<typename VecType>
typename PolyImpl<VecType>::Integer& PolyImpl<VecType>::operator[](usint i)
{
	return (*m_values)[i];
}

template<typename VecType>
const typename PolyImpl<VecType>::Integer& PolyImpl<VecType>::operator[](usint i) const
{
	return (*m_values)[i];
}

template<typename VecType>
usint PolyImpl<VecType>::GetLength() const
{
	if (m_values == 0)
		throw std::logic_error("No values in PolyImpl");
	return m_values->GetLength();
}

template<typename VecType>
void PolyImpl<VecType>::SetValues(const VecType& values, Format format)
{
	if (m_params->GetRootOfUnity() == Integer(0)){
		PALISADE_THROW(type_error, "Polynomial has a 0 root of unity");
	}
	if (m_params->GetRingDimension() != values.GetLength() || m_params->GetModulus() != values.GetModulus()) {
		PALISADE_THROW(type_error, "Parameter mismatch on SetValues for Polynomial");
	}
	m_values = make_unique<VecType>(values);
	m_format = format;
}

template<typename VecType>
void PolyImpl<VecType>::SetValuesToZero()
{
	m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
}

template<typename VecType>
void PolyImpl<VecType>::SetValuesToMax()
{
	Integer max = m_params->GetModulus() - Integer(1);
	usint size = m_params->GetRingDimension();
	m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
	for (usint i = 0; i < size; i++) {
		m_values->operator[](i)= Integer(max);
	}

}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Plus(const Integer &element) const
{
	PolyImpl<VecType> tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().ModAddAtIndex(0, element), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Minus(const Integer &element) const
{
	PolyImpl<VecType> tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().ModSub(element), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(const Integer &element) const
{
	PolyImpl<VecType> tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().ModMul(element), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::MultiplyAndRound(const Integer &p, const Integer &q) const
{
	PolyImpl<VecType> tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().MultiplyAndRound(p, q), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::DivideAndRound(const Integer &q) const
{
	PolyImpl<VecType> tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().DivideAndRound(q), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Negate() const
{
	//		if (m_format != Format::EVALUATION)
	//			throw std::logic_error("Negate for PolyImpl is supported only in EVALUATION format.\n");

	PolyImpl<VecType> tmp( *this );
	*tmp.m_values = m_values->ModMul(this->m_params->GetModulus() - Integer(1));
	return std::move( tmp );
}

// VECTOR OPERATIONS

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Plus(const PolyImpl &element) const
{
	PolyImpl tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().ModAdd(*element.m_values), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Minus(const PolyImpl &element) const
{
	PolyImpl<VecType> tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().ModSub(*element.m_values), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(const PolyImpl &element) const
{
	if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
		throw std::logic_error("operator* for PolyImpl is supported only in EVALUATION format.\n");

	if (!(*this->m_params == *element.m_params))
		throw std::logic_error("operator* called on PolyImpl's with different params.");

	PolyImpl<VecType> tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().ModMul(*element.m_values), this->m_format );
	return std::move( tmp );
}

// TODO: check if the parms tests here should be done in regular op as well as op=? or in neither place?

template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator+=(const PolyImpl &element)
{
	bool dbg_flag = true;
	if (!(*this->m_params == *element.m_params)){
		DEBUGEXP(*this->m_params);
		DEBUGEXP(*element.m_params);
		throw std::logic_error("operator+= called on PolyImpl's with different params.");
	}
  
	if (m_values == nullptr) {
		// act as tho this is 0
		m_values = make_unique<VecType>(*element.m_values);
		return *this;
	}

	m_values->ModAddEq(*element.m_values);

	return *this;
}

template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator-=(const PolyImpl &element)
{
	if (!(*this->m_params == *element.m_params))
		throw std::logic_error("operator-= called on PolyImpl's with different params.");
	if (m_values == nullptr) {
		// act as tho this is 0
		m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
	}
	m_values->ModSubEq(*element.m_values);
	return *this;
}

template<typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator*=(const PolyImpl &element)
{
	if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
		throw std::logic_error("operator*= for PolyImpl is supported only in EVALUATION format.\n");

	if (!(*this->m_params == *element.m_params))
		throw std::logic_error("operator*= called on PolyImpl's with different params.");

	if (m_values == nullptr){
		// act as tho it's 0
		m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
		return *this;
	}

	m_values->ModMulEq(*element.m_values);

	return *this;
}

template<typename VecType>
void PolyImpl<VecType>::AddILElementOne()
{
	Integer tempValue;
	for (usint i = 0; i < m_params->GetRingDimension(); i++) {
		tempValue = GetValues().operator[](i) + Integer(1);
		tempValue = tempValue.Mod(m_params->GetModulus());
		m_values->operator[](i)= tempValue;
	}
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::AutomorphismTransform(const usint &k) const
{
	PolyImpl result(*this);

	usint m = this->m_params->GetCyclotomicOrder();
	usint n = this->m_params->GetRingDimension();

	if (this->m_format == EVALUATION) {

		if (m_params->OrderIsPowerOfTwo() == false) {

			//Add a test based on the inverse totient hash table
			//if (i % 2 == 0)
			//	throw std::runtime_error("automorphism index should be odd\n");

			const auto &modulus = this->m_params->GetModulus();

			// All automorphism operations are performed for k coprime to m, which are generated using GetTotientList(m)
			std::vector<usint> totientList = GetTotientList(m);

			// Temporary vector of size m is introduced
			// This step can be eliminated by using a hash table that looks up the ring index (between 0 and n - 1)
			// based on the totient index (between 0 and m - 1)
			VecType expanded(m, modulus);
			for (usint i = 0; i < n; i++) {
				expanded.operator[](totientList.operator[](i))= m_values->operator[](i);
			}

			for (usint i = 0; i < n; i++) {

				//determines which power of primitive root unity we should switch to
				usint idx = totientList.operator[](i)*k % m;

				result.m_values->operator[](i)= expanded.operator[](idx);

			}
		} else { // power of two cyclotomics
			if (k % 2 == 0)
				throw std::runtime_error("automorphism index should be odd\n");

			for (usint j = 1; j < m; j = j + 2) {

				//determines which power of primitive root unity we should switch to
				usint idx = (j*k) % m;
				result.m_values->operator[]((j + 1) / 2 - 1)= GetValues().operator[]((idx + 1) / 2 - 1);

			}

		}
	}
	else // automorphism in coefficient representation
	{
		if (m_params->OrderIsPowerOfTwo() == false) {

			PALISADE_THROW( lbcrypto::math_error, "Automorphism in coefficient representation is not currently supported for non-power-of-two polynomials");

		}
		else { // power of two cyclotomics
			if (k % 2 == 0)
				throw std::runtime_error("automorphism index should be odd\n");

			for (usint j = 1; j < n; j++) {

				usint temp = j*k;
				usint newIndex = temp % n;

				if ((temp/n) % 2 == 1)
					result.m_values->operator[](newIndex) = m_params->GetModulus() - m_values->operator[](j);
				else
					result.m_values->operator[](newIndex) = m_values->operator[](j);

			}
		}

	}

	return result;

}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Transpose() const
{
	if (m_format == COEFFICIENT)
		throw std::logic_error("PolyImpl element transposition is currently implemented only in the Evaluation representation.");
	else {
		usint m = m_params->GetCyclotomicOrder();
		return AutomorphismTransform(m - 1);
	}
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::MultiplicativeInverse() const
{
	PolyImpl tmp = CloneParametersOnly();
	if (InverseExists()) {
		tmp.SetValues( GetValues().ModInverse(), this->m_format );
		return std::move( tmp );
	} else {
		throw std::logic_error("PolyImpl has no inverse\n");
	}
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::ModByTwo() const
{
	PolyImpl tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().ModByTwo(), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Mod(const Integer & modulus) const
{
	PolyImpl tmp = CloneParametersOnly();
	tmp.SetValues( GetValues().Mod(modulus), this->m_format );
	return std::move( tmp );
}

template<typename VecType>
void PolyImpl<VecType>::SwitchModulus(const Integer &modulus, const Integer &rootOfUnity, const Integer &modulusArb,
		const Integer &rootOfUnityArb)
		{
	if (m_values) {
		m_values->SwitchModulus(modulus);
		m_params = shared_ptr<PolyImpl::Params>(new PolyImpl::Params(m_params->GetCyclotomicOrder(), modulus, rootOfUnity, modulusArb, rootOfUnityArb));
	}
		}

template<typename VecType>
void PolyImpl<VecType>::SwitchFormat()
{

	bool dbg_flag = false;
	if (m_values == nullptr) {
		std::string errMsg = "Poly switch format to empty values";
		throw std::runtime_error(errMsg);
	}

	if (m_params->OrderIsPowerOfTwo() == false ) {
		ArbitrarySwitchFormat();
		return;
	}

	VecType newValues(m_params->GetCyclotomicOrder()/ 2);

	if (m_format == COEFFICIENT) {
		m_format = EVALUATION;

		DEBUG("transform to evaluation m_values was"<< *m_values);

		ChineseRemainderTransformFTT<VecType>::ForwardTransform(*m_values, m_params->GetRootOfUnity(), m_params->GetCyclotomicOrder(), &newValues);
		DEBUG("m_values now "<< newValues);
	} else {
		m_format = COEFFICIENT;
		DEBUG("transform to coefficient m_values was"<< *m_values);

		ChineseRemainderTransformFTT<VecType>::InverseTransform(*m_values, m_params->GetRootOfUnity(), m_params->GetCyclotomicOrder(), &newValues);
		DEBUG("m_values now "<< newValues);
	}

	*m_values = newValues;
}

template<typename VecType>
void PolyImpl<VecType>::ArbitrarySwitchFormat()
{

	bool dbg_flag = false;
	if (m_values == nullptr) {
		std::string errMsg = "Poly switch format to empty values";
		throw std::runtime_error(errMsg);
	}

	if (m_format == COEFFICIENT) {
		m_format = EVALUATION;
		//todo:: does this have an extra copy?
		DEBUG("transform to evaluation m_values was"<< *m_values);

		m_values = make_unique<VecType>(ChineseRemainderTransformArb<VecType>::
				ForwardTransform(*m_values, m_params->GetRootOfUnity(),m_params->GetBigModulus(),
						m_params->GetBigRootOfUnity(), m_params->GetCyclotomicOrder()));
		DEBUG("m_values now "<< *m_values);
	} else {
		m_format = COEFFICIENT;
		DEBUG("transform to coefficient m_values was"<< *m_values);

		m_values = make_unique<VecType>(ChineseRemainderTransformArb<VecType>::
				InverseTransform(*m_values, m_params->GetRootOfUnity(), m_params->GetBigModulus(),
						m_params->GetBigRootOfUnity(), m_params->GetCyclotomicOrder()));
		DEBUG("m_values now "<< *m_values);
	}
}
template<typename VecType>
std::ostream& operator<<(std::ostream &os, const PolyImpl<VecType> & p)
{
	if (p.m_values != nullptr) {
		os << *(p.m_values);
		os << " mod:" << (p.m_values)->GetModulus() << std::endl;
	}
	if (p.m_params.get() != nullptr) {
		os << " rootOfUnity: " << p.GetRootOfUnity() << std::endl;
	} else {
		os << " something's odd: null m_params?!" << std::endl;
	}
	os << std::endl;
	return os;
}

template<typename VecType>
void PolyImpl<VecType>::MakeSparse(const uint32_t &wFactor)
{
	Integer modTemp;
	Integer tempValue;
	if (m_values != 0) {
		for (usint i = 0; i < m_params->GetRingDimension();i++) {
			if (i%wFactor != 0) {
				m_values->operator[](i)= Integer(0);
			}
		}
	}
}

// This function modifies PolyImpl to keep all the even indices. It reduces the ring dimension by half.
template<typename VecType>
void PolyImpl<VecType>::Decompose()
{

	if( m_params->OrderIsPowerOfTwo() == false ) {
		throw std::logic_error("Cannot decompose if cyclotomic order is not a power of 2");
	}

	Format format(m_format);

	if (format != Format::COEFFICIENT) {
		std::string errMsg = "PolyImpl not in COEFFICIENT format to perform Decompose.";
		throw std::runtime_error(errMsg);
	}

	usint decomposedCyclotomicOrder = m_params->GetCyclotomicOrder() / 2;
	//Using the halving lemma propety of roots of unity to calculate the root of unity at half the cyclotomic order

	m_params.reset(new PolyImpl::Params(decomposedCyclotomicOrder, m_params->GetModulus(), m_params->GetRootOfUnity()));

	//Interleaving operation.
	VecType decomposeValues(GetLength() / 2, GetModulus());
	for (usint i = 0; i < GetLength(); i = i + 2) {
		decomposeValues.operator[](i / 2)= GetValues().operator[](i);
	}

	SetValues(decomposeValues, m_format);
}

template<typename VecType>
bool PolyImpl<VecType>::IsEmpty() const
{
	if (m_values == nullptr)
		return true;

	return false;
}

template<typename VecType>
bool PolyImpl<VecType>::InverseExists() const
{
	for (usint i = 0; i < GetValues().GetLength(); i++) {
		if (m_values->operator[](i) == Integer(0))
			return false;
	}
	return true;
}

template<typename VecType>
double PolyImpl<VecType>::Norm() const
{
	Integer locVal;
	Integer retVal;
	const Integer &q = m_params->GetModulus();
	const Integer &half = m_params->GetModulus() >> 1;

	for (usint i = 0; i < GetValues().GetLength(); i++) {
		if (m_values->operator[](i) > half)
			locVal = q - (*m_values)[i];
		else
			locVal = m_values->operator[](i);

		if (locVal > retVal)
			retVal = locVal;
	}

	return retVal.ConvertToDouble();

}


// Write vector x(current value of the PolyImpl object) as \sum\limits{ i = 0 }^{\lfloor{ \log q / base } \rfloor} {(base^i u_i)} and
// return the vector of{ u_0, u_1,...,u_{ \lfloor{ \log q / base } \rfloor } } \in R_base^{ \lceil{ \log q / base } \rceil };
// used as a subroutine in the relinearization procedure
// baseBits is the number of bits in the base, i.e., base = 2^baseBits

template<typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const
{
	bool dbg_flag = false;

	DEBUG("PolyImpl::BaseDecompose" );
	usint nBits = m_params->GetModulus().GetLengthForBase(2);

	usint nWindows = nBits / baseBits;
	if (nBits % baseBits > 0)
		nWindows++;

	PolyImpl<VecType> xDigit(m_params);

	std::vector<PolyImpl<VecType>> result;
	result.reserve(nWindows);

	// convert the polynomial to coefficient representation
	PolyImpl<VecType> x(*this);
	x.SetFormat(COEFFICIENT);

	DEBUG("<x>" );
	//for( auto i : x ){
	DEBUG(x );
	//}
	DEBUG("</x>" );

	//TP: x is same for BACKEND 2 and 6


	for (usint i = 0; i < nWindows; ++i) {
		DEBUG("VecType is '" << type_name<VecType>() << "'" );

		xDigit.SetValues( x.GetValues().GetDigitAtIndexForBase(i+1, 1 << baseBits), x.GetFormat() );
		DEBUG("x.GetValue().GetDigitAtIndexForBase(i=" << i << ")" << std::endl << x.GetValues().GetDigitAtIndexForBase(i*baseBits + 1, 1 << baseBits) );
		DEBUG("x.GetFormat()" << x.GetFormat() );
		//TP: xDigit is all zeros for BACKEND=6, but not for BACKEND-2  *********************************************************
		DEBUG("<xDigit." << i << ">" << std::endl << xDigit << "</xDigit." << i << ">" );
		if( evalModeAnswer )
			xDigit.SwitchFormat();
		result.push_back(xDigit);
		DEBUG("<xDigit.SwitchFormat." << i << ">" << std::endl << xDigit << "</xDigit.SwitchFormat." << i << ">" );
	}

	DEBUG("<result>" );
	for( auto i : result){
		DEBUG(i );
	}
	DEBUG("</result>" );

	return std::move(result);
}

// Generate a vector of PolyImpl's as {x, base*x, base^2*x, ..., base^{\lfloor {\log q/base} \rfloor}*x, where x is the current PolyImpl object;
// used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element
// baseBits is the number of bits in the base, i.e., base = 2^baseBits

template<typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::PowersOfBase(usint baseBits) const
{

	static Integer TWO(2);
	std::vector<PolyImpl<VecType>> result;

	usint nBits = m_params->GetModulus().GetLengthForBase(2);

	usint nWindows = nBits / baseBits;
	if (nBits % baseBits > 0)
		nWindows++;

	result.reserve(nWindows);

	for (usint i = 0; i < nWindows; ++i) {
		Integer pI(TWO.ModExp(Integer(i*baseBits), m_params->GetModulus()));
		result.push_back(pI*(*this));
	}

	return std::move(result);

}

template<typename VecType>
typename PolyImpl<VecType>::PolyNative
PolyImpl<VecType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {

	auto smaller = this->Mod(ptm);

	typename PolyImpl<VecType>::PolyNative interp(
			shared_ptr<ILNativeParams>( new ILNativeParams(this->GetCyclotomicOrder(), ptm, 1) ),
															this->GetFormat(), true);

	for (usint i = 0; i<smaller.GetLength(); i++) {
		interp[i] = smaller[i].ConvertToInt();
	}

	return std::move( interp );
}

// JSON FACILITY - Serialize Operation
template<typename VecType>
bool PolyImpl<VecType>::Serialize(Serialized* serObj) const {
	bool dbg_flag = false;
	DEBUG("in PolyImpl<> Serialize");
	if( !serObj->IsObject() ){
	  serObj->SetObject();
	}
	Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
	if (!this->GetValues().Serialize(&obj)){
	        PALISADE_THROW(lbcrypto::serialize_error, "PolyImpl::Serialize Get values failed");
	}

	if (!m_params->Serialize(&obj)){
	        PALISADE_THROW(lbcrypto::serialize_error, "PolyImpl::Serialize m_[arams failed");
	}
	obj.AddMember("Format", std::to_string(this->GetFormat()), obj.GetAllocator());

	serObj->AddMember("PolyImpl", obj.Move(), serObj->GetAllocator());

	return true;
}

// JSON FACILITY - Deserialize Operation
template<typename VecType>
bool PolyImpl<VecType>::Deserialize(const Serialized& serObj) {
	bool dbg_flag= false;
	DEBUG("in PolyImpl<> Deserialize");

	Serialized::ConstMemberIterator iMap = serObj.FindMember("PolyImpl");
	if (iMap == serObj.MemberEnd()) {
		PALISADE_THROW(lbcrypto::deserialize_error, "PolyImpl::Deserialize could not find PolyImpl");
	}

	SerialItem::ConstMemberIterator pIt = iMap->value.FindMember("ILParams");
	if (pIt == iMap->value.MemberEnd()) {
		PALISADE_THROW(lbcrypto::deserialize_error, "PolyImpl::Deserialize could not find ILParams");
	}

	Serialized parm(rapidjson::kObjectType);
	parm.AddMember(SerialItem(pIt->name, parm.GetAllocator()), SerialItem(pIt->value, parm.GetAllocator()), parm.GetAllocator());

	shared_ptr<PolyImpl::Params> json_ilParams(new PolyImpl::Params());
	if (!json_ilParams->Deserialize(parm)){
		PALISADE_THROW(lbcrypto::deserialize_error, "PolyImpl::Deserialize could not deserialize Params");
	}
	m_params = json_ilParams;

	usint vectorLength = this->m_params->GetRingDimension();

	VecType vectorBBV = VecType(vectorLength, m_params->GetModulus());

	SerialItem::ConstMemberIterator vIt = iMap->value.FindMember("BigVectorImpl");
	if (vIt == iMap->value.MemberEnd()) {
		PALISADE_THROW(lbcrypto::deserialize_error, "PolyImpl::Deserialize could not find BigVectorImpl");
	}

	Serialized s(rapidjson::kObjectType);
	s.AddMember(SerialItem(vIt->name, s.GetAllocator()), SerialItem(vIt->value, s.GetAllocator()), s.GetAllocator());
	if (!vectorBBV.Deserialize(s)) {
		PALISADE_THROW(lbcrypto::deserialize_error, "PolyImpl::Deserialize could not deserialize s");
	}

	if ((vIt = iMap->value.FindMember("Format")) == iMap->value.MemberEnd()) {
		PALISADE_THROW(lbcrypto::deserialize_error, "PolyImpl::Deserialize could not find format");
	}
	this->SetValues(vectorBBV, Format(atoi(vIt->value.GetString())));

	return true;
}

} // namespace lbcrypto ends
