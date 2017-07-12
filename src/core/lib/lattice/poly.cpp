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

#include "poly.h"
#include <fstream>
#include <cmath>


namespace lbcrypto
{

	// static members
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	std::vector<PolyImpl<ModType, IntType,VecType,ParmType>> PolyImpl<ModType,IntType,VecType,ParmType>::m_dggSamples;

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	shared_ptr<ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::m_dggSamples_params;

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	std::vector<PolyImpl<ModType,IntType,VecType,ParmType>> PolyImpl<ModType,IntType,VecType,ParmType>::m_tugSamples;

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	shared_ptr<ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::m_tugSamples_params;

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl() : m_values(nullptr), m_format(EVALUATION)
{
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl(const shared_ptr<ParmType> params, Format format, bool initializeElementToZero) : m_values(nullptr), m_format(format)
{
		m_params = params;

		if (initializeElementToZero) {
			this->SetValuesToZero();
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl(bool initializeElementToMax, const shared_ptr<ParmType> params, Format format) : m_values(nullptr), m_format(format)
{
		m_params = params;

		if(initializeElementToMax) {
			this->SetValuesToMax();

		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl(const DggType &dgg, const shared_ptr<ParmType> params, Format format)
{

		m_params = params;

	if (format == COEFFICIENT) {
			usint vectorSize = params->GetRingDimension();
			m_values = make_unique<VecType>(dgg.GenerateVector(vectorSize, params->GetModulus()));
			(*m_values).SetModulus(params->GetModulus());
			m_format = COEFFICIENT;
	} else {

		usint vectorSize = params->GetRingDimension();
		m_values = make_unique<VecType>(dgg.GenerateVector(vectorSize, params->GetModulus()));
			(*m_values).SetModulus(params->GetModulus());
		m_format = COEFFICIENT;

		this->SwitchFormat();

		//PreComputeDggSamples(dgg, m_params);

		//const PolyImpl<ModType,IntType,VecType,ParmType> randomElement = GetPrecomputedVector();
		//m_values = make_unique<VecType>(*randomElement.m_values);
		//(*m_values).SetModulus(params->GetModulus());
		//m_format = EVALUATION;
		}
	}


	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl( DiscreteUniformGeneratorImpl<IntType,VecType> &dug, const shared_ptr<ParmType> params, Format format)
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

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl(const BinaryUniformGeneratorImpl<IntType,VecType> &bug, const shared_ptr<ParmType> params, Format format)
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

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl(const TernaryUniformGeneratorImpl<IntType,VecType> &tug, const shared_ptr<ParmType> params, Format format)
{

		m_params = params;

	if (format == COEFFICIENT) {
			usint vectorSize = params->GetRingDimension();
			m_values = make_unique<VecType>(tug.GenerateVector(vectorSize, params->GetModulus()));
			(*m_values).SetModulus(params->GetModulus());
			m_format = COEFFICIENT;
	} else {
		usint vectorSize = params->GetRingDimension();
		m_values = make_unique<VecType>(tug.GenerateVector(vectorSize, params->GetModulus()));
		(*m_values).SetModulus(params->GetModulus());
		m_format = COEFFICIENT;

		this->SwitchFormat();

		//PreComputeTugSamples(tug, m_params);

		//const PolyImpl randomElement = GetPrecomputedTugVector();
		//m_values = make_unique<VecType>(*randomElement.m_values);
		//(*m_values).SetModulus(params->GetModulus());
		//m_format = EVALUATION;
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl(const PolyImpl &element, shared_ptr<ParmType>) : m_format(element.m_format), m_params(element.m_params)
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

	//this is the move
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType>::PolyImpl(PolyImpl &&element, shared_ptr<ParmType>) : m_format(element.m_format), m_params(element.m_params)
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
    //element.m_values = nullptr; //remove the reference (actually unnecessary with smart pointers now.
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType>& PolyImpl<ModType,IntType,VecType,ParmType>::operator=(const PolyImpl &rhs)
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

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType>& PolyImpl<ModType,IntType,VecType,ParmType>::operator=(std::initializer_list<sint> rhs)
{
		static IntType ZERO(0);
		usint len = rhs.size();
		if (!IsEmpty()) {
			usint vectorLength = this->m_values->GetLength();

			for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
				if (j < len) {
					SetValAtIndex(j, IntType(*(rhs.begin() + j)));
			} else {
					SetValAtIndex(j, ZERO);
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


	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType>& PolyImpl<ModType,IntType,VecType,ParmType>::operator=(std::initializer_list<std::string> rhs)
{
		static IntType ZERO(0);
		usint len = rhs.size();
		if (!IsEmpty()) {
			usint vectorLength = this->m_values->GetLength();

			for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
				if (j < len) {
					SetValAtIndex(j, *(rhs.begin() + j));
			} else {
					SetValAtIndex(j, ZERO);
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


	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType>& PolyImpl<ModType,IntType,VecType,ParmType>::operator=(PolyImpl &&rhs)
{

		if (this != &rhs) {
			m_values = std::move(rhs.m_values);
			m_params = rhs.m_params;
			m_format = rhs.m_format;
		}

		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::CloneParametersOnly() const
{
		PolyImpl<ModType,IntType,VecType,ParmType> result(this->m_params, this->m_format);
		return std::move(result);//TODO should we instead rely on RVO? 
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, Format format) const
{
		PolyImpl<ModType,IntType,VecType,ParmType> result(dgg, m_params, format);
		return std::move(result);//TODO should we instead rely on RVO? 
	}

	//If this is in EVALUATION then just set all the values = val
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType>& PolyImpl<ModType,IntType,VecType,ParmType>::operator=(uint64_t val)
{
		m_format = EVALUATION;
		if (m_values == nullptr){
			m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
		}
		for (size_t i = 0; i < m_values->GetLength(); ++i) {
			this->SetValAtIndex(i, IntType(val));
		}
		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	PolyImpl<ModType,IntType,VecType,ParmType>::~PolyImpl()
	{
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const VecType &PolyImpl<ModType,IntType,VecType,ParmType>::GetValues() const
{
		if (m_values == 0)
			throw std::logic_error("No values in PolyImpl");
		return *m_values;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
Format PolyImpl<ModType,IntType,VecType,ParmType>::GetFormat() const
{
		return m_format;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const IntType PolyImpl<ModType,IntType,VecType,ParmType>::GetValAtIndex(usint i) const
	{
		if (m_values == 0)
			throw std::logic_error("No values in PolyImpl");
		return m_values->GetValAtIndex(i);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
usint PolyImpl<ModType,IntType,VecType,ParmType>::GetLength() const
{
		if (m_values == 0)
			throw std::logic_error("No values in PolyImpl");
		return m_values->GetLength();
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::SetValues(const VecType& values, Format format)
{
		if (m_params->GetRootOfUnity() == 0 || m_params->GetRingDimension() != values.GetLength() || m_params->GetModulus() != values.GetModulus()) {
		  std::cout<<"PolyImpl::SetValues warning, mismatch in parameters"<<std::endl;
		  if (m_params->GetRootOfUnity() == 0){
			std::cout<<"m_params->GetRootOfUnity "<<m_params->GetRootOfUnity()<<std::endl;
		}
		  if (m_params->GetRingDimension() != values.GetLength()){
		    std::cout<<"m_params->GetRingDimension() "<<m_params->GetRingDimension()<<std::endl;
		    std::cout<<"!= values.GetLength()"<< values.GetLength() <<std::endl;
		}
		  if ( m_params->GetModulus() != values.GetModulus()) {
		    std::cout<<"m_params->GetModulus() "<<m_params->GetModulus()<<std::endl;
		    std::cout<<"values->GetModulus() "<<values.GetModulus()<<std::endl;
		}
		  //throw std::logic_error("Exisiting m_params do not match with the input parameter IntType& values.\n");
		  // if (m_values != nullptr) { //dbc no need with smart pointers
		  //   delete m_values;
		  // }
		}
		m_values = make_unique<VecType>(values);
		m_format = format;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::SetValuesToZero()
{
	        m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::SetValuesToMax()
{
		IntType max = m_params->GetModulus() - 1;
		usint size = m_params->GetRingDimension();
		m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
		for (usint i = 0; i < size; i++) {
			m_values->SetValAtIndex(i, IntType(max));
		}

	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::Plus(const IntType &element) const
{
		PolyImpl<ModType,IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModAddAtIndex(0, element), this->m_format );
		return std::move( tmp );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::Minus(const IntType &element) const
{
		PolyImpl<ModType,IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModSub(element), this->m_format );
		return std::move( tmp );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::Times(const IntType &element) const
{
		PolyImpl<ModType,IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModMul(element), this->m_format );
		return std::move( tmp );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::MultiplyAndRound(const IntType &p, const IntType &q) const
{
		PolyImpl<ModType,IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().MultiplyAndRound(p, q), this->m_format );
		return std::move( tmp );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::DivideAndRound(const IntType &q) const
{
		PolyImpl<ModType,IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().DivideAndRound(q), this->m_format );
		return std::move( tmp );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::Negate() const
{
//		if (m_format != Format::EVALUATION)
//			throw std::logic_error("Negate for PolyImpl is supported only in EVALUATION format.\n");

		PolyImpl<ModType,IntType,VecType,ParmType> tmp( *this );
		*tmp.m_values = m_values->ModMul(this->m_params->GetModulus() - 1);
		return std::move( tmp );
	}

	// VECTOR OPERATIONS

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::Plus(const PolyImpl &element) const
{
		PolyImpl tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModAdd(*element.m_values), this->m_format );
		return std::move( tmp );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::Minus(const PolyImpl &element) const
{
		PolyImpl<ModType,IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModSub(*element.m_values), this->m_format );
		return std::move( tmp );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::Times(const PolyImpl &element) const
{
		if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
			throw std::logic_error("operator* for PolyImpl is supported only in EVALUATION format.\n");

		if (!(*this->m_params == *element.m_params))
			throw std::logic_error("operator* called on PolyImpl's with different params.");

		PolyImpl<ModType,IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModMul(*element.m_values), this->m_format );
		return std::move( tmp );
	}

	// FIXME: should the parms tests here be done in regular + as well as +=? or in neither place?
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType>& PolyImpl<ModType,IntType,VecType,ParmType>::operator+=(const PolyImpl &element)
{
		if (!(*this->m_params == *element.m_params))
			throw std::logic_error("operator+= called on PolyImpl's with different params.");

		if (m_values == nullptr) {
		        m_values = make_unique<VecType>(*element.m_values);
			return *this;
		}
		SetValues( m_values->ModAdd(*element.m_values), this->m_format );
		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType>& PolyImpl<ModType,IntType,VecType,ParmType>::operator-=(const PolyImpl &element)
{
		if (!(*this->m_params == *element.m_params))
			throw std::logic_error("operator-= called on PolyImpl's with different params.");
		if (m_values == nullptr) {

		        m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
			//TODO:: is this a bug? it is not the same as +=
		}
		SetValues( m_values->ModSub(*element.m_values), this->m_format );
		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType>& PolyImpl<ModType,IntType,VecType,ParmType>::operator*=(const PolyImpl &element)
{

		if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
			throw std::logic_error("operator*= for PolyImpl is supported only in EVALUATION format.\n");

		if (!(*this->m_params == *element.m_params))
			throw std::logic_error("operator*= called on PolyImpl's with different params.");

		if (m_values == nullptr){
                        m_values = make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
		}
		SetValues( m_values->ModMul(*element.m_values), this->m_format );
		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::AddILElementOne()
{
		IntType tempValue;
		for (usint i = 0; i < m_params->GetRingDimension(); i++) {
			tempValue = GetValues().GetValAtIndex(i) + 1;
			tempValue = tempValue.Mod(m_params->GetModulus());
			m_values->SetValAtIndex(i, tempValue);
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::AutomorphismTransform(const usint &k) const
{
		
			PolyImpl result(*this);

	usint m = this->m_params->GetCyclotomicOrder();
	usint n = this->m_params->GetRingDimension();

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
			expanded.SetValAtIndex(totientList.at(i), m_values->GetValAtIndex(i));
			}

		for (usint i = 0; i < n; i++) {

			//determines which power of primitive root unity we should switch to
			usint idx = totientList.at(i)*k % m;

			result.m_values->SetValAtIndex(i, expanded.GetValAtIndex(idx));

		}
	} else {
		if (k % 2 == 0)
			throw std::runtime_error("automorphism index should be odd\n");

		for (usint j = 1; j < m; j = j + 2) {

			//determines which power of primitive root unity we should switch to
			usint idx = (j*k) % m;
			result.m_values->SetValAtIndex((j + 1) / 2 - 1, GetValues().GetValAtIndex((idx + 1) / 2 - 1));

		}

	}

	return result;

	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::Transpose() const
{
		if (m_format == COEFFICIENT)
			throw std::logic_error("PolyImpl element transposition is currently implemented only in the Evaluation representation.");
	else {
			usint m = m_params->GetCyclotomicOrder();
			return AutomorphismTransform(2 * m - 1);
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::MultiplicativeInverse() const
{
		PolyImpl tmp = CloneParametersOnly();
		if (InverseExists()) {
			tmp.SetValues( GetValues().ModInverse(), this->m_format );
			return std::move( tmp );
	} else {
			throw std::logic_error("PolyImpl has no inverse\n");
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::ModByTwo() const
{
		PolyImpl tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModByTwo(), this->m_format );
		return std::move( tmp );
	}
  //TODO: why is this called Signed Mod, should BBV.Mod be called signed mod too?

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::SignedMod(const IntType & modulus) const
{
		PolyImpl tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().Mod(modulus), this->m_format );
		return std::move( tmp );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::SwitchModulus(const IntType &modulus, const IntType &rootOfUnity, const IntType &modulusArb,
        const IntType &rootOfUnityArb)
{
		if (m_values) {
			m_values->SwitchModulus(modulus);
		m_params = shared_ptr<ParmType>(new ParmType(m_params->GetCyclotomicOrder(), modulus, rootOfUnity, modulusArb, rootOfUnityArb));
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::SwitchFormat()
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
    
		if (m_format == COEFFICIENT) {
			m_format = EVALUATION;
			//todo:: does this have an extra copy? 
			DEBUG("transform to evaluation m_values was"<< *m_values);						  

			m_values = make_unique<VecType>(ChineseRemainderTransformFTT<IntType,VecType>::GetInstance()
							.ForwardTransform(*m_values, m_params->GetRootOfUnity(), 
									  m_params->GetCyclotomicOrder()));
			DEBUG("m_values now "<< *m_values);						  
	} else {
			m_format = COEFFICIENT;
			DEBUG("transform to coefficient m_values was"<< *m_values);						  

			m_values = make_unique<VecType>(ChineseRemainderTransformFTT<IntType,VecType>::GetInstance()
							.InverseTransform(*m_values, m_params->GetRootOfUnity(), 
									  m_params->GetCyclotomicOrder()));
			DEBUG("m_values now "<< *m_values);						  

		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::ArbitrarySwitchFormat()
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

			m_values = make_unique<VecType>(ChineseRemainderTransformArb<IntType,VecType>::GetInstance()
							.ForwardTransform(*m_values, m_params->GetRootOfUnity(),m_params->GetBigModulus(),
								m_params->GetBigRootOfUnity(), m_params->GetCyclotomicOrder()));
			DEBUG("m_values now "<< *m_values);
	} else {
			m_format = COEFFICIENT;
			DEBUG("transform to coefficient m_values was"<< *m_values);

			m_values = make_unique<VecType>(ChineseRemainderTransformArb<IntType,VecType>::GetInstance()
							.InverseTransform(*m_values, m_params->GetRootOfUnity(), m_params->GetBigModulus(),
								m_params->GetBigRootOfUnity(), m_params->GetCyclotomicOrder()));
			DEBUG("m_values now "<< *m_values);

		}
	}
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::PrintValues() const
{
		if (m_values != nullptr) {
			std::cout << *m_values;
			std::cout << " mod:" << m_values->GetModulus() << std::endl;
		}
		if (m_params.get() != nullptr) {
			std::cout << " rootOfUnity: " << this->GetRootOfUnity() << std::endl;
	} else {
			std::cout << " something's odd: null m_params?!" << std::endl;
		}
		std::cout << std::endl;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::MakeSparse(const uint32_t &wFactor)
{
		IntType modTemp;
		IntType tempValue;
		if (m_values != 0) {
			for (usint i = 0; i < m_params->GetRingDimension();i++) {
				if (i%wFactor != 0) {
					m_values->SetValAtIndex(i, IntType(0));
				}
			}
		}
	}

	// This function modifies PolyImpl to keep all the even indices. It reduces the ring dimension by half.
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::Decompose()
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

		m_params.reset(new ParmType(decomposedCyclotomicOrder, m_params->GetModulus(), m_params->GetRootOfUnity()));

		//Interleaving operation.
		VecType decomposeValues(GetLength() / 2, GetModulus());
		for (usint i = 0; i < GetLength(); i = i + 2) {
			decomposeValues.SetValAtIndex(i / 2, GetValues().GetValAtIndex(i));
		}

		SetValues(decomposeValues, m_format);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
bool PolyImpl<ModType,IntType,VecType,ParmType>::IsEmpty() const
{
		if (m_values == nullptr)
			return true;

		return false;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
bool PolyImpl<ModType,IntType,VecType,ParmType>::InverseExists() const
{
		for (usint i = 0; i < GetValues().GetLength(); i++) {
			if (m_values->GetValAtIndex(i) == 0)
				return false;
		}
		return true;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
double PolyImpl<ModType,IntType,VecType,ParmType>::Norm() const
{
		double retVal = 0.0;
		double locVal = 0.0;
		double q = m_params->GetModulus().ConvertToDouble();

		for (usint i = 0; i < GetValues().GetLength(); i++) {
		if (m_values->GetValAtIndex(i) > (m_params->GetModulus() >> 1)) {
				locVal = q - (m_values->GetValAtIndex(i)).ConvertToDouble();
		} else
				locVal = (m_values->GetValAtIndex(i)).ConvertToDouble();

			if (locVal > retVal)
				retVal = locVal;
		}
		return retVal;
	}

	// Write vector x(current value of the PolyImpl object) as \sum\limits{ i = 0 }^{\lfloor{ \log q / base } \rfloor} {(base^i u_i)} and
	// return the vector of{ u_0, u_1,...,u_{ \lfloor{ \log q / base } \rfloor } } \in R_base^{ \lceil{ \log q / base } \rceil };
	// used as a subroutine in the relinearization procedure
	// baseBits is the number of bits in the base, i.e., base = 2^baseBits

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
std::vector<PolyImpl<ModType,IntType,VecType,ParmType>> PolyImpl<ModType,IntType,VecType,ParmType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const
{
		
		usint nBits = m_params->GetModulus().GetLengthForBase(2);

		usint nWindows = nBits / baseBits;
		if (nBits % baseBits > 0)
			nWindows++;

		PolyImpl<ModType,IntType,VecType,ParmType> xDigit(m_params);

		std::vector<PolyImpl<ModType,IntType,VecType,ParmType>> result;
		result.reserve(nWindows);

		// convert the polynomial to coefficient representation
		PolyImpl<ModType,IntType,VecType,ParmType> x(*this);
		x.SetFormat(COEFFICIENT);


	for (usint i = 0; i < nWindows; ++i) {
			xDigit.SetValues( x.GetValues().GetDigitAtIndexForBase(i*baseBits + 1, 1 << baseBits), x.GetFormat() );
			if( evalModeAnswer )
				xDigit.SwitchFormat();
			result.push_back(xDigit);
		}

		return std::move(result);
	}

	// Generate a vector of PolyImpl's as {x, base*x, base^2*x, ..., base^{\lfloor {\log q/base} \rfloor}*x, where x is the current PolyImpl object;
	// used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element
	// baseBits is the number of bits in the base, i.e., base = 2^baseBits

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
std::vector<PolyImpl<ModType,IntType,VecType,ParmType>> PolyImpl<ModType,IntType,VecType,ParmType>::PowersOfBase(usint baseBits) const
{

		static IntType TWO(2);
		std::vector<PolyImpl<ModType,IntType,VecType,ParmType>> result;

		usint nBits = m_params->GetModulus().GetLengthForBase(2);

		usint nWindows = nBits / baseBits;
		if (nBits % baseBits > 0)
			nWindows++;

		result.reserve(nWindows);

	for (usint i = 0; i < nWindows; ++i) {
			IntType pI(TWO.ModExp(IntType(i*baseBits), m_params->GetModulus()));
			result.push_back(pI*(*this));
		}

		return std::move(result);

	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::PreComputeDggSamples(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, const shared_ptr<ParmType> params)
		{
	if (m_dggSamples.size() == 0 || m_dggSamples_params != params) {
			DestroyPreComputedSamples();
			m_dggSamples_params = params;
		for (usint i = 0; i < m_sampleSize; ++i) {
				PolyImpl current(m_dggSamples_params);
				usint vectorSize = m_dggSamples_params->GetRingDimension();
				current.m_values = make_unique<VecType>(dgg.GenerateVector(vectorSize, m_dggSamples_params->GetModulus()));
				current.m_values->SetModulus(m_dggSamples_params->GetModulus());
				current.m_format = COEFFICIENT;

				current.SwitchFormat();

				m_dggSamples.push_back(current);
			}
		}
	}

	//Select a precomputed vector randomly
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::GetPrecomputedVector()
{

		//std::default_random_engine generator;
		//std::uniform_real_distribution<int> distribution(0,SAMPLE_SIZE-1);
		//int randomIndex = distribution(generator);

		int randomIndex = rand() % SAMPLE_SIZE;
		return m_dggSamples[randomIndex];
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::PreComputeTugSamples(const TernaryUniformGeneratorImpl<IntType,VecType> &tug, const shared_ptr<ParmType> params)
		{
	if (m_tugSamples.size() == 0 || m_tugSamples_params != params) {
			DestroyPreComputedTugSamples();
			m_tugSamples_params = params;
		for (usint i = 0; i < m_sampleSize; ++i) {
				PolyImpl current(m_tugSamples_params);
				usint vectorSize = m_tugSamples_params->GetRingDimension();
				current.m_values = make_unique<VecType>(tug.GenerateVector(vectorSize, m_tugSamples_params->GetModulus()));
				current.m_values->SetModulus(m_tugSamples_params->GetModulus());
				current.m_format = COEFFICIENT;

				current.SwitchFormat();

				m_tugSamples.push_back(current);
			}
		}
	}

	//Select a precomputed vector randomly
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
const PolyImpl<ModType,IntType,VecType,ParmType> PolyImpl<ModType,IntType,VecType,ParmType>::GetPrecomputedTugVector()
{

		int randomIndex = rand() % SAMPLE_SIZE;
		return m_tugSamples[randomIndex];
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::DestroyPreComputedSamples()
{
		m_dggSamples.clear();
	}

	/**
	 * Clear the pre-computed ternary uniform samples.
	 */
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
void PolyImpl<ModType,IntType,VecType,ParmType>::DestroyPreComputedTugSamples()
{
		m_tugSamples.clear();
	}



	// JSON FACILITY - Serialize Operation
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool PolyImpl<ModType,IntType,VecType,ParmType>::Serialize(Serialized* serObj) const {
                bool dbg_flag = false;
		if( !serObj->IsObject() ){
		        DEBUG("PolyImpl::Serialize is obj failed");
			return false;
		}
		Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
		if (!this->GetValues().Serialize(&obj)){
		        DEBUG("PolyImpl::Serialize Get values failed");
			return false;
		}

		if (!m_params->Serialize(&obj)){
		        DEBUG("PolyImpl::Serialize m_[arams failed");
			return false;
		}
		obj.AddMember("Format", std::to_string(this->GetFormat()), obj.GetAllocator());

		serObj->AddMember("PolyImpl", obj.Move(), serObj->GetAllocator());

		return true;
	}

	// JSON FACILITY - Deserialize Operation
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool PolyImpl<ModType,IntType,VecType,ParmType>::Deserialize(const Serialized& serObj) {
                bool dbg_flag= false;
		Serialized::ConstMemberIterator iMap = serObj.FindMember("PolyImpl");
		if (iMap == serObj.MemberEnd()) {
		  DEBUG("PolyImpl::Deserialize could not find PolyImpl");
		  return false;
		}

		SerialItem::ConstMemberIterator pIt = iMap->value.FindMember("ILParams");
		if (pIt == iMap->value.MemberEnd()) {
		  DEBUG("PolyImpl::Deserialize could not find ILParams");
		  return false;
		}

		Serialized parm(rapidjson::kObjectType);
		parm.AddMember(SerialItem(pIt->name, parm.GetAllocator()), SerialItem(pIt->value, parm.GetAllocator()), parm.GetAllocator());

		shared_ptr<ParmType> json_ilParams(new ParmType());
		if (!json_ilParams->Deserialize(parm)){
		  DEBUG("PolyImpl::Deserialize could not deserialize Params");
			return false;
		}
		m_params = json_ilParams;

		usint vectorLength = this->m_params->GetRingDimension();

		VecType vectorBBV = VecType(vectorLength, m_params->GetModulus());

		SerialItem::ConstMemberIterator vIt = iMap->value.FindMember("BigVectorImpl");
		if (vIt == iMap->value.MemberEnd()) {
		  DEBUG("PolyImpl::Deserialize could not find BigVectorImpl");
			return false;
		}

		Serialized s(rapidjson::kObjectType);
		s.AddMember(SerialItem(vIt->name, s.GetAllocator()), SerialItem(vIt->value, s.GetAllocator()), s.GetAllocator());
		if (!vectorBBV.Deserialize(s)) {
		  DEBUG("PolyImpl::Deserialize could not deserialize s");
			return false;
		}

		if ((vIt = iMap->value.FindMember("Format")) == iMap->value.MemberEnd()) {
		  DEBUG("PolyImpl::Deserialize could not find format");
		  return false;
		}
		this->SetValues(vectorBBV, Format(atoi(vIt->value.GetString())));

		return true;
	}

} // namespace lbcrypto ends
