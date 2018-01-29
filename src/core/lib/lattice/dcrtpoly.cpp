/*
 * @file dcrtpoly.cpp - implementation of the integer lattice using double-CRT representations.
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

#include "dcrtpoly.h"
#include <fstream>
#include <memory>
using std::shared_ptr;
using std::string;
#include "../utils/serializablehelper.h"
#include "../utils/debug.h"

namespace lbcrypto
{

/*CONSTRUCTORS*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl()
{
	m_format = EVALUATION;
	m_params.reset( new ParmType(0,1) );
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl(const shared_ptr<ParmType> dcrtParams, Format format, bool initializeElementToZero)
{
	m_format = format;
	m_params = dcrtParams;

	size_t vecSize = dcrtParams->GetParams().size();
	m_vectors.reserve(vecSize);

	for (usint i = 0; i < vecSize; i++) {
		m_vectors.push_back(std::move(PolyType(dcrtParams->GetParams()[i],format,initializeElementToZero)));
	}
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl(const DCRTPolyImpl &element)
{
	m_format = element.m_format;
	m_vectors = element.m_vectors;
	m_params = element.m_params;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
const DCRTPolyImpl<ModType,IntType,VecType,ParmType>&
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator=(const PolyLargeType &element)
{

	if( element.GetModulus() > m_params->GetModulus() ) {
		throw std::logic_error("Modulus of element passed to constructor is bigger that DCRT big modulus");
	}

	size_t vecCount = m_params->GetParams().size();
	m_vectors.clear();
	m_vectors.reserve(vecCount);

	// fill up with vectors with the proper moduli
	for(usint i = 0; i < vecCount; i++ ) {
		PolyType newvec(m_params->GetParams()[i], m_format, true);
		m_vectors.push_back( std::move(newvec) );
	}

	// need big ints out of the little ints for the modulo operations, below
	std::vector<ModType> bigmods;
	bigmods.reserve(vecCount);
	for( usint i = 0; i < vecCount; i++ )
		bigmods.push_back( ModType(m_params->GetParams()[i]->GetModulus().ConvertToInt()) );

	// copy each coefficient mod the new modulus
	for(usint p = 0; p < element.GetLength(); p++ ) {
		for( usint v = 0; v < vecCount; v++ ) {

			IntType tmp = element.at(p) % bigmods[v];
			m_vectors[v].at(p)= tmp.ConvertToInt();
		}
	}

	return *this;
}

/* Construct from a single Poly. The format is derived from the passed in Poly.*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl(const PolyLargeType &element, const shared_ptr<ParmType> params)
{
	Format format;
	try {
		format = element.GetFormat();
	} catch (const std::exception& e) {
		throw std::logic_error("There is an issue with the format of the Poly passed to the constructor of DCRTPolyImpl");
	}

	if( element.GetCyclotomicOrder() != params->GetCyclotomicOrder() )
		throw std::logic_error("Cyclotomic order mismatch on input vector and parameters");

	m_format = format;
	m_params = params;

	*this = element;
}

/* Construct using a tower of vectors.
 * The params and format for the DCRTPolyImpl will be derived from the towers
 */
template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl(const std::vector<PolyType> &towers)
{
	usint cyclotomicOrder = towers.at(0).GetCyclotomicOrder();
	std::vector<std::shared_ptr<ILNativeParams>> parms;
	for (usint i = 0; i < towers.size(); i++) {
		if ( towers[i].GetCyclotomicOrder() != cyclotomicOrder ) {
			throw std::logic_error("Polys provided to constructor must have the same ring dimension");
		}
		parms.push_back( towers[i].GetParams() );
	}

	shared_ptr<ParmType> p( new ParmType(cyclotomicOrder, parms) );

	m_params = p;
	m_vectors = towers;
	m_format = m_vectors[0].GetFormat();
}

/*The dgg will be the seed to populate the towers of the DCRTPolyImpl with random numbers. The algorithm to populate the towers can be seen below.*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl(const DggType& dgg, const shared_ptr<ParmType> dcrtParams, Format format)
{
	m_format = format;
	m_params = dcrtParams;

	size_t vecSize = dcrtParams->GetParams().size();
	m_vectors.reserve(vecSize);

	//dgg generating random values
	std::shared_ptr<int32_t> dggValues = dgg.GenerateIntVector(dcrtParams->GetRingDimension());

	for(usint i = 0; i < vecSize; i++) {

		NativeVector ilDggValues(dcrtParams->GetRingDimension(), dcrtParams->GetParams()[i]->GetModulus());

		for(usint j = 0; j < dcrtParams->GetRingDimension(); j++) {
			uint64_t	entry;
			// if the random generated value is less than zero, then multiply it by (-1) and subtract the modulus of the current tower to set the coefficient
			int64_t k = (dggValues.get())[j];
			if(k < 0) {
				k *= (-1);
				entry = (uint64_t)dcrtParams->GetParams()[i]->GetModulus().ConvertToInt() - (uint64_t)k;
			}
			//if greater than or equal to zero, set it the value generated
			else {
				entry = k;
			}
			ilDggValues.at(j)=entry;
		}

		PolyType ilvector(dcrtParams->GetParams()[i]);
		ilvector.SetValues(ilDggValues, Format::COEFFICIENT); // the random values are set in coefficient format
		if(m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
			ilvector.SwitchFormat();
		}
		m_vectors.push_back(ilvector);
	}
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl(DugType& dug, const shared_ptr<ParmType> dcrtParams, Format format)
{

	m_format = format;
	m_params = dcrtParams;

	size_t numberOfTowers = dcrtParams->GetParams().size();
	m_vectors.reserve(numberOfTowers);

	for (usint i = 0; i < numberOfTowers; i++) {

		dug.SetModulus(dcrtParams->GetParams()[i]->GetModulus());
		NativeVector vals(dug.GenerateVector(dcrtParams->GetRingDimension()));
		PolyType ilvector(dcrtParams->GetParams()[i]);

		ilvector.SetValues(vals, Format::COEFFICIENT); // the random values are set in coefficient format
		if (m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
			ilvector.SwitchFormat();
		}
		m_vectors.push_back(ilvector);
	}
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl(const TugType& tug, const shared_ptr<ParmType> dcrtParams, Format format)
{

	m_format = format;
	m_params = dcrtParams;

	size_t numberOfTowers = dcrtParams->GetParams().size();
	m_vectors.reserve(numberOfTowers);

	//tug generating random values
	std::shared_ptr<int32_t> tugValues = tug.GenerateIntVector(dcrtParams->GetRingDimension());

	for (usint i = 0; i < numberOfTowers; i++) {

		NativeVector ilTugValues(dcrtParams->GetRingDimension(), dcrtParams->GetParams()[i]->GetModulus());

		for(usint j = 0; j < dcrtParams->GetRingDimension(); j++) {
			uint64_t	entry;
			// if the random generated value is less than zero, then multiply it by (-1) and subtract the modulus of the current tower to set the coefficient
			int64_t k = (tugValues.get())[j];
			if(k < 0) {
				k *= (-1);
				entry = (uint64_t)dcrtParams->GetParams()[i]->GetModulus().ConvertToInt() - (uint64_t)k;
			}
			//if greater than or equal to zero, set it the value generated
			else {
				entry = k;
			}
			ilTugValues.at(j)=entry;
		}

		PolyType ilvector(dcrtParams->GetParams()[i]);
		ilvector.SetValues(ilTugValues, Format::COEFFICIENT); // the random values are set in coefficient format
		if(m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
			ilvector.SwitchFormat();
		}
		m_vectors.push_back(ilvector);
	}

}

/*Move constructor*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DCRTPolyImpl(const DCRTPolyImpl &&element)
{
	m_format = element.m_format;
	m_vectors = std::move(element.m_vectors);
	m_params = std::move(element.m_params);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::CloneParametersOnly() const
{

	DCRTPolyImpl res(this->m_params, this->m_format);
	return std::move(res);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, Format format) const
{

	DCRTPolyImpl res = CloneParametersOnly();

	VecType randVec = dgg.GenerateVector(m_params->GetCyclotomicOrder() / 2, m_params->GetModulus());

	// create an Element to pull from
	// create a dummy parm to use in the Poly world
	shared_ptr<ILParamsImpl<IntType>> parm( new ILParamsImpl<IntType>(m_params->GetCyclotomicOrder(), m_params->GetModulus(), 1) );
	PolyLargeType element( parm );
	element.SetValues( randVec, m_format );

	res = element;

	return std::move(res);
}

// DESTRUCTORS

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::~DCRTPolyImpl() {}

// GET ACCESSORS
template<typename ModType, typename IntType, typename VecType, typename ParmType>
const typename DCRTPolyImpl<ModType,IntType,VecType,ParmType>::PolyType& DCRTPolyImpl<ModType,IntType,VecType,ParmType>::GetElementAtIndex (usint i) const
{
	if(m_vectors.empty())
		throw std::logic_error("DCRTPolyImpl's towers are not initialized.");
	if(i > m_vectors.size()-1)
		throw std::logic_error("Index: " + std::to_string(i) + " is out of range.");
	return m_vectors[i];
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
usint DCRTPolyImpl<ModType,IntType,VecType,ParmType>::GetNumOfElements() const
{
	return m_vectors.size();
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
const std::vector<typename DCRTPolyImpl<ModType,IntType,VecType,ParmType>::PolyType>& DCRTPolyImpl<ModType,IntType,VecType,ParmType>::GetAllElements() const
{
	return m_vectors;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
Format DCRTPolyImpl<ModType,IntType,VecType,ParmType>::GetFormat() const
{
	return m_format;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
std::vector<DCRTPolyImpl<ModType,IntType,VecType,ParmType>> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const
{
	bool dbg_flag = false;
	DEBUG("...::BaseDecompose" );
	DEBUG("baseBits=" << baseBits );

	PolyLargeType v( CRTInterpolate() );

	DEBUG("<v>" << std::endl << v << "</v>" );

	std::vector<PolyLargeType> bdV = v.BaseDecompose(baseBits, false);

	DEBUG("<bdV>" );
	for( auto i : bdV )
		DEBUG(i );
	DEBUG("</bdV>" );

	std::vector<DCRTPolyImpl<ModType,IntType,VecType,ParmType>> result;

	// populate the result by converting each of the big vectors into a VectorArray
	for( usint i=0; i<bdV.size(); i++ ) {
		DCRTPolyImpl<ModType,IntType,VecType,ParmType> dv(bdV[i], this->GetParams());
		if( evalModeAnswer )
			dv.SwitchFormat();
		result.push_back( std::move(dv) );
	}

	DEBUG("<BaseDecompose.result>" );
	for( auto i : result )
		DEBUG(i );
	DEBUG("</BaseDecompose.result>" );

	return std::move(result);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
std::vector<DCRTPolyImpl<ModType,IntType,VecType,ParmType>> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::CRTDecompose(
		const std::vector<NativeInteger> &qDivqiInverse) const
{

	std::vector<DCRTPolyType> result;

	DCRTPolyType input = this->Clone();

	if (input.GetFormat() == EVALUATION)
		input.SwitchFormat();

	for( usint i=0; i<m_vectors.size(); i++ ) {

		DCRTPolyType currentDCRTPoly = input.Clone();
		PolyType currentPoly = input.m_vectors[i]*qDivqiInverse[i];

		for ( usint k=0; k<m_vectors.size(); k++ ){
			PolyType temp(currentPoly);
			if (i!=k)
				temp.SwitchModulus(input.m_vectors[k].GetModulus(),input.m_vectors[k].GetRootOfUnity());
			currentDCRTPoly.m_vectors[k] = temp;
		}

		currentDCRTPoly.SwitchFormat();

		result.push_back( std::move(currentDCRTPoly) );
	}

	return std::move(result);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
std::vector<DCRTPolyImpl<ModType,IntType,VecType,ParmType>> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::PowersOfBase(usint baseBits) const
{
	bool dbg_flag = false;

	std::vector<DCRTPolyImpl<ModType,IntType,VecType,ParmType>> result;

	usint nBits = m_params->GetModulus().GetLengthForBase(2);

	usint nWindows = nBits / baseBits;
	if (nBits % baseBits > 0)
		nWindows++;

	result.reserve(nWindows);

	// prepare for the calculations by gathering a big integer version of each of the little moduli
	std::vector<IntType> mods(m_params->GetParams().size());
	for( usint i = 0; i < m_params->GetParams().size(); i++ ) {
		mods[i] = IntType(m_params->GetParams()[i]->GetModulus().ConvertToInt());
		DEBUG("DCRTPolyImpl::PowersOfBase.mods[" << i << "] = " << mods[i] );
	}


	for( usint i = 0; i < nWindows; i++ ) {
		DCRTPolyType x( m_params, m_format );

		// Shouldn't this be IntType twoPow ( IntType::ONE << (i*baseBits)  ??
		IntType twoPow( IntType(2).Exp( i*baseBits ) );
		DEBUG("DCRTPolyImpl::PowersOfBase.twoPow (" << i << ") = " << twoPow );
		for( usint t = 0; t < m_params->GetParams().size(); t++ ) {
			DEBUG("@(" << i << ", " << t << ")" );
			DEBUG("twoPow= " << twoPow << ", mods[" << t << "]" << mods[t] );
			IntType pI (twoPow % mods[t]);
			DEBUG("twoPow= " << twoPow << ", mods[" << t << "]" << mods[t] << ";   pI.ConvertToInt=" << pI.ConvertToInt() << ";   pI=" << pI );
			DEBUG("m_vectors= " << m_vectors[t] );

			x.m_vectors[t] = m_vectors[t] * pI.ConvertToInt();
			DEBUG("DCRTPolyImpl::PowersOfBase.x.m_vectors[" << t << ", " << i << "]" << x.m_vectors[t] );
		}
		result.push_back( x );
	}

	return std::move(result);
}

/*VECTOR OPERATIONS*/

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::MultiplicativeInverse() const
{
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		tmp.m_vectors[i] = m_vectors[i].MultiplicativeInverse();
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::ModByTwo() const
{
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		tmp.m_vectors[i] = m_vectors[i].ModByTwo();
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Plus(const DCRTPolyImpl &element) const
{
	if( m_vectors.size() != element.m_vectors.size() ) {
		throw std::logic_error("tower size mismatch; cannot add");
	}
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		tmp.m_vectors[i] += element.GetElementAtIndex (i);
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Negate() const
{
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(this->CloneParametersOnly());
	tmp.m_vectors.clear();

	for (usint i = 0; i < this->m_vectors.size(); i++) {
		tmp.m_vectors.push_back(std::move(this->m_vectors.at(i).Negate()));
	}

	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Minus(const DCRTPolyImpl &element) const
{
	if( m_vectors.size() != element.m_vectors.size() ) {
		throw std::logic_error("tower size mismatch; cannot subtract");
	}
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		tmp.m_vectors[i] -= element.GetElementAtIndex (i);
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
const DCRTPolyImpl<ModType,IntType,VecType,ParmType>& DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator+=(const DCRTPolyImpl &rhs)
{
	for (usint i = 0; i < this->GetNumOfElements(); i++) {
		this->m_vectors[i] += rhs.m_vectors[i];
	}
	return *this;

}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
const DCRTPolyImpl<ModType,IntType,VecType,ParmType>& DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator-=(const DCRTPolyImpl &rhs)
{
	for (usint i = 0; i < this->GetNumOfElements(); i++) {
		this->m_vectors.at(i) -= rhs.GetElementAtIndex(i);
	}
	return *this;

}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
const DCRTPolyImpl<ModType,IntType,VecType,ParmType>& DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator*=(const DCRTPolyImpl &element)
{
	for (usint i = 0; i < this->m_vectors.size(); i++) {
		this->m_vectors.at(i) *= element.m_vectors.at(i);
	}

	return *this;

}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
bool DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator==(const DCRTPolyImpl &rhs) const
{

	if( GetCyclotomicOrder() != rhs.GetCyclotomicOrder() )
		return false;

	if( GetModulus() != rhs.GetModulus() )
		return false;

	if (m_format != rhs.m_format) {
		return false;
	}

	if (m_vectors.size() != rhs.m_vectors.size()) {
		return false;
	}

	//check if the towers are the same
	else return (m_vectors == rhs.GetAllElements());
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
const DCRTPolyImpl<ModType,IntType,VecType,ParmType> & DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator=(const DCRTPolyImpl & rhs)
{
	if (this != &rhs) {
		m_vectors = rhs.m_vectors;
		m_format = rhs.m_format;
		m_params = rhs.m_params;
	}
	return *this;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
const DCRTPolyImpl<ModType,IntType,VecType,ParmType> & DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator=(DCRTPolyImpl&& rhs)
{
	if (this != &rhs) {
		m_vectors = std::move(rhs.m_vectors);
		m_format = std::move(rhs.m_format);
		m_params = std::move(rhs.m_params);
	}
	return *this;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>& DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator=(std::initializer_list<uint64_t> rhs)
{
	usint len = rhs.size();
	static PolyType::Integer ZERO(0);
	if(!IsEmpty()) {
		usint vectorLength = this->m_vectors[0].GetLength();
		for(usint i = 0; i < m_vectors.size(); ++i) { // this loops over each tower
			for(usint j = 0; j < vectorLength; ++j) { // loops within a tower
				if(j<len) {
				  this->m_vectors[i].at(j)= *(rhs.begin()+j);
				} else {
				  this->m_vectors[i].at(j)= ZERO;
				}
			}
		}
	} else {
		for(size_t i=0; i<m_vectors.size(); i++) {
			NativeVector temp(m_params->GetRingDimension());
			temp.SetModulus(m_vectors.at(i).GetModulus());
			temp = rhs;
			m_vectors.at(i).SetValues(std::move(temp),m_format);
		}

	}
	return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType, IntType, VecType, ParmType>& DCRTPolyImpl<ModType, IntType, VecType, ParmType>::operator=(uint64_t val)
{
	if (!IsEmpty()) {
		for (usint i = 0; i < m_vectors.size(); i++) {
			m_vectors[i] = val;
		}
	}
	else {
		for (usint i = 0; i<m_vectors.size(); i++) {
			NativeVector temp(m_params->GetRingDimension());
			temp.SetModulus(m_vectors.at(i).GetModulus());
			temp = val;
			m_vectors.at(i).SetValues(std::move(temp), m_format);
		}
	}

	return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType, IntType, VecType, ParmType>& DCRTPolyImpl<ModType, IntType, VecType, ParmType>::operator=(std::vector<int64_t> val)
{
	if (!IsEmpty()) {
		for (usint i = 0; i < m_vectors.size(); i++) {
			m_vectors[i] = val;
		}
	}
	else {
		for (usint i = 0; i<m_vectors.size(); i++) {
			NativeVector temp(m_params->GetRingDimension());
			temp.SetModulus(m_vectors.at(i).GetModulus());
			m_vectors.at(i).SetValues(std::move(temp), m_format);
			m_vectors[i] = val;
		}
	}

	m_format = COEFFICIENT;

	return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType, IntType, VecType, ParmType>& DCRTPolyImpl<ModType, IntType, VecType, ParmType>::operator=(std::vector<int32_t> val)
{
	if (!IsEmpty()) {
		for (usint i = 0; i < m_vectors.size(); i++) {
			m_vectors[i] = val;
		}
	}
	else {
		for (usint i = 0; i<m_vectors.size(); i++) {
			NativeVector temp(m_params->GetRingDimension());
			temp.SetModulus(m_vectors.at(i).GetModulus());
			m_vectors.at(i).SetValues(std::move(temp), m_format);
			m_vectors[i] = val;
		}
	}

	m_format = COEFFICIENT;

	return *this;
}


/*SCALAR OPERATIONS*/

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Plus(const IntType &element) const
{
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		tmp.m_vectors[i] += element.ConvertToInt();
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Minus(const IntType &element) const
{
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		tmp.m_vectors[i] -= element.ConvertToInt();
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Times(const DCRTPolyImpl & element) const
{
	if( m_vectors.size() != element.m_vectors.size() ) {
		throw std::logic_error("tower size mismatch; cannot multiply");
	}
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		//ModMul multiplies and performs a mod operation on the results. The mod is the modulus of each tower.
		tmp.m_vectors[i] *= element.m_vectors[i];
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Times(const IntType &element) const
{
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		tmp.m_vectors[i] = tmp.m_vectors[i] * element.ConvertToInt(); // (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Times(
		const std::vector<NativeInteger> &element) const
{
	DCRTPolyImpl<ModType,IntType,VecType,ParmType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		tmp.m_vectors[i] = tmp.m_vectors[i] * element[i]; // (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}
	return std::move(tmp);
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::MultiplyAndRound(const IntType &p, const IntType &q) const
{
	std::string errMsg = "Operation not implemented yet";
	throw std::runtime_error(errMsg);
	return *this;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DivideAndRound(const IntType &q) const
{
	std::string errMsg = "Operation not implemented yet";
	throw std::runtime_error(errMsg);
	return *this;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
const DCRTPolyImpl<ModType,IntType,VecType,ParmType>& DCRTPolyImpl<ModType,IntType,VecType,ParmType>::operator*=(const IntType &element)
{
	for (usint i = 0; i < this->m_vectors.size(); i++) {
		this->m_vectors.at(i) *= element.ConvertToInt(); //this->m_vectors.at(i) * (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}

	return *this;
}


template<typename ModType, typename IntType, typename VecType, typename ParmType>
  void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::SetValuesToZero()
  {
  	for(usint i = 0; i < m_vectors.size(); i++) {
  		m_vectors[i].SetValuesToZero();
  	}
  }
/*OTHER FUNCTIONS*/


  
template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::AddILElementOne()
{
	if(m_format != Format::EVALUATION)
		throw std::runtime_error("DCRTPolyImpl<ModType,IntType,VecType,ParmType>::AddILElementOne cannot be called on a DCRTPolyImpl in COEFFICIENT format.");
	for(usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i].AddILElementOne();
	}
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::MakeSparse(const uint32_t &wFactor)
{
	for(usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i].MakeSparse(wFactor);
	}
}

// This function modifies PolyArrayImpl to keep all the even indices in the tower.
// It reduces the ring dimension of the tower by half.
template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Decompose()
{

	if(m_format != Format::COEFFICIENT) {
		std::string errMsg = "DCRTPolyImpl not in COEFFICIENT format to perform Decompose.";
		throw std::runtime_error(errMsg);
	}

	for( size_t i = 0; i < m_vectors.size(); i++) {
		m_vectors[i].Decompose();
	}

	// the individual vectors parms have changed, so change the DCRT parms
	std::vector<std::shared_ptr<ILNativeParams>> vparms(m_vectors.size());
	for( size_t i = 0; i < m_vectors.size(); i++)
		vparms[i] = m_vectors[i].GetParams();
	m_params.reset( new ParmType(vparms[0]->GetCyclotomicOrder(), vparms) );
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
bool DCRTPolyImpl<ModType,IntType,VecType,ParmType>::IsEmpty() const
{
	for(size_t i=0; i<m_vectors.size(); i++) {
		if(!m_vectors.at(i).IsEmpty())
			return false;
	}
	return true;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DropLastElement()
{
	if(m_vectors.size() == 0) {
		throw std::out_of_range("Last element being removed from empty list");
	}

	m_vectors.resize(m_vectors.size() - 1);
	ParmType *newP = new ParmType( *m_params );
	newP->PopLastParam();
	m_params.reset(newP);
}

/**
* This function performs ModReduce on ciphertext element and private key element. The algorithm can be found from this paper:
* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
*
* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus q/qi. The qi is generally the largest. In the code below,
* ModReduce is written for DCRTPolyImpl and it drops the last tower while updating the necessary parameters.
* The steps taken here are as follows:
* 1. compute a short d in R such that d = c mod q
* 2. compute a short delta in R such that delta = (vq′−1)·d mod (pq′). E.g., all of delta’s integer coefficients can be in the range [−pq′/2, pq′/2).
* 3. let d′ = c + delta mod q. By construction, d′ is divisible by q′.
* 4. output (d′/q′) in R(q/q′).
*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::ModReduce(const IntType &plaintextModulus)
{
	bool dbg_flag = false;
	if(m_format != Format::EVALUATION) {
		throw std::logic_error("Mod Reduce function expects EVAL Formatted DCRTPolyImpl. It was passed COEFF Formatted DCRTPolyImpl.");
	}
	this->SwitchFormat();

	usint lastTowerIndex = m_vectors.size() - 1;

	DEBUG("ModReduce(" << plaintextModulus << ") on tower size " << m_vectors.size()<< " m=" << GetCyclotomicOrder());

	PolyType towerT(m_vectors[lastTowerIndex]); //last tower that will be dropped
	PolyType d(towerT);

	//precomputations
	typename PolyType::Integer ptm(plaintextModulus.ConvertToInt());
	typename PolyType::Integer qt(m_vectors[lastTowerIndex].GetModulus());
	DEBUG("qt: "<< qt);
	DEBUG("plaintextModulus: "<< ptm);
	typename PolyType::Integer v(qt.ModInverse(ptm));
	DEBUG("v: "<< v);
	typename PolyType::Integer a((v * qt).ModSub(1, ptm*qt));
	DEBUG("a:	"<<a);

	// Since only positive values are being used for Discrete gaussian generator, a call to switch modulus needs to be done
	d.SwitchModulus( ptm*qt, d.GetRootOfUnity() );
	// FIXME NOT CHANGING ROOT OF UNITY-TODO: What to do with SwitchModulus and is it necessary to pass rootOfUnity

	// Calculating delta, step 2
	PolyType delta(d.Times(a));

	// Calculating d' = c + delta mod q (step 3)
	// no point in going to size() since the last tower's being dropped
	for(usint i=0; i<m_vectors.size(); i++) {
		PolyType temp(delta);
		temp.SwitchModulus(m_vectors[i].GetModulus(), m_vectors[i].GetRootOfUnity());
		m_vectors[i] += temp;
	}

	//step 4
	DropLastElement();

	std::vector<PolyType::Integer> qtInverseModQi(m_vectors.size());
	for(usint i=0; i<m_vectors.size(); i++) {
		const PolyType::Integer& mod = m_vectors[i].GetModulus();
		qtInverseModQi[i] = qt.ModInverse(mod);
		m_vectors[i] = qtInverseModQi[i].ConvertToInt() * m_vectors[i];
	}

	SwitchFormat();
}

/*
 * This method applies the Chinese Remainder Interpolation on an ILVectoArray2n and produces an Poly
* How the Algorithm works:
* Consider the DCRTPolyImpl as a 2-dimensional matrix M, with dimension ringDimension * Number of Towers.
* For brevity , lets say this is r * t
* Let qt denote the bigModulus (all the towers' moduli multiplied together) and qi denote the modulus of a particular tower.
* Let V be a BigVector of size tower (tower size). Each coefficient of V is calculated as follows:
* for every r
*   calculate: V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}mod qt
*
* Once we have the V values, we construct an Poly from V, use qt as it's modulus, and calculate a root of unity
* for parameter selection of the Poly.
*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
typename DCRTPolyImpl<ModType,IntType,VecType,ParmType>::PolyLargeType DCRTPolyImpl<ModType,IntType,VecType,ParmType>::CRTInterpolate() const
{
	bool dbg_flag = false;

	usint ringDimension = GetRingDimension();
	usint nTowers = m_vectors.size();

	DEBUG("in Interpolate ring " << ringDimension << " towers " << nTowers);

	for( usint vi = 0; vi < nTowers; vi++ )
		DEBUG("tower " << vi << " is " << m_vectors[vi]);

	ModType bigModulus(GetModulus()); // qT

	DEBUG("bigModulus " << bigModulus);

	// this is the resulting vector of coefficients
	VecType coefficients(ringDimension, bigModulus);

	// this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj *[ (qt/qj)^(-1) mod qj ]}modqt

	// first, precompute qt/qj factors
	vector<IntType> multiplier(nTowers);
	for( usint vi = 0 ; vi < nTowers; vi++ ) {
		IntType qj(m_vectors[vi].GetModulus().ConvertToInt());
		IntType divBy = bigModulus / qj;
		IntType modInv = divBy.ModInverse(qj).Mod(qj);
		multiplier[vi] = divBy * modInv;

		DEBUG("multiplier " << vi << " " << qj << " " << multiplier[vi]);
	}

	// if the vectors are not in COEFFICIENT form, they need to be, so we will need to make a copy
	// of them and switchformat on them... otherwise we can just use what we have
	const std::vector<PolyType> *vecs = &m_vectors;
	std::vector<PolyType> coeffVecs;
	if( m_format == EVALUATION ) {
		for( usint i=0; i<m_vectors.size(); i++ ) {
			PolyType vecCopy(m_vectors[i]);
			vecCopy.SetFormat(COEFFICIENT);
			coeffVecs.push_back( std::move(vecCopy) );
		}
		vecs = &coeffVecs;
	}

	for( usint vi = 0; vi < nTowers; vi++ )
		DEBUG("tower " << vi << " is " << (*vecs)[vi]);

	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(bigModulus);

	// now, compute the values for the vector
#pragma omp parallel for
	for( usint ri = 0; ri < ringDimension; ri++ ) {
		coefficients[ri] = 0;
		for( usint vi = 0; vi < nTowers; vi++ ) {
			coefficients[ri] += (IntType((*vecs)[vi].GetValues()[ri].ConvertToInt()) * multiplier[vi]);
		}
		DEBUG( (*vecs)[0].GetValues()[ri] << " * " << multiplier[0] << " == " << coefficients[ri] );
		coefficients[ri].ModBarrettInPlace(bigModulus,mu);
	}

	DEBUG("passed loops");
	DEBUG(coefficients);

	// Create an Poly for this BigVector

	DEBUG("elementing after vectoring");
	DEBUG("m_cyclotomicOrder " << GetCyclotomicOrder());
	DEBUG("modulus "<< bigModulus);

	// Setting the root of unity to ONE as the calculation is expensive and not required.
	typename DCRTPolyImpl<ModType,IntType,VecType,ParmType>::PolyLargeType polynomialReconstructed( shared_ptr<ILParamsImpl<IntType>>( new ILParamsImpl<IntType>(GetCyclotomicOrder(), bigModulus, 1) ) );
	polynomialReconstructed.SetValues(coefficients,COEFFICIENT);

	DEBUG("answer: " << polynomialReconstructed);

	return std::move( polynomialReconstructed );
}

// todo can we be smarter with this method?
template<typename ModType, typename IntType, typename VecType, typename ParmType>
NativePoly DCRTPolyImpl<ModType,IntType,VecType,ParmType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
	return this->CRTInterpolate().DecryptionCRTInterpolate(ptm);
}

//Source: Halevi S. and Polyakov Y. (in preparation, 2018) A Simpler, Faster RNS Variant of the BFV Homomorphic Encryption Scheme.
//
//Computes Round(p/q*x) mod p as [\sum_i x_i*alpha_i + Round(\sum_i x_i*beta_i)] mod p for fast rounding in RNS
// vectors alpha and beta are precomputed as
// alpha_i = Floor[(p*[(q/qi)^{-1}]_qi)/qi]_p
// beta_i = ((p*[(q/qi)^{-1}]_qi)%qi)/qi in (0,1)
// used in decryption of BFVrns

template<typename ModType, typename IntType, typename VecType, typename ParmType>
PolyImpl<NativeInteger,NativeInteger,NativeVector,ILNativeParams>
DCRTPolyImpl<ModType,IntType,VecType,ParmType>::ScaleAndRound(const typename PolyType::Integer &p,
		const std::vector<typename PolyType::Integer> &alpha, const std::vector<double> &beta) const {

	usint ringDimension = GetRingDimension();
	usint nTowers = m_vectors.size();

	typename PolyType::Vector coefficients(ringDimension, p);

	for( usint ri = 0; ri < ringDimension; ri++ ) {
		double curFloatSum = 0.0f;
		typename PolyType::Integer curIntSum = 0;
		for( usint vi = 0; vi < nTowers; vi++ ) {
			const typename PolyType::Integer &xi = m_vectors[vi].GetValues()[ri];

			// We assume that that the value of p is smaller than 64 bits (like 58)
			// Thus we do not make additional curIntSum.Mod(p) calls for each value of vi
			curIntSum += xi.ModMul(alpha[vi],p);

			curFloatSum += xi.ConvertToInt()*beta[vi];
		}

		coefficients[ri] = (curIntSum + typename PolyType::Integer(std::llround(curFloatSum))).Mod(p);
	}

	// Setting the root of unity to ONE as the calculation is expensive
	// It is assumed that no polynomial multiplications in evaluation representation are performed after this
	PolyType result( shared_ptr<typename PolyType::Params>( new typename PolyType::Params(GetCyclotomicOrder(), p, 1) ) );
	result.SetValues(coefficients,COEFFICIENT);

	return std::move(result);

}

/*
 * Source: Halevi S. and Polyakov Y. (in preparation, 2018) A Simpler, Faster RNS Variant of the BFV Homomorphic Encryption Scheme.
 *
 * The goal is to switch the basis of x from Q to S
 *
 * Let us write x as
 * x = \sum_i [xi (q/qi)^{-1}]_qi \times q/qi - alpha*q,
 * where alpha is a number between 0 and k-1 (assuming we iterate over i \in [0,k-1]).
 *
 * Now let us take mod s_i (to go to the S basis).
 * mod s_i = \sum_i [xi (q/qi)^{-1}]_qi \times q/qi mod s_i - alpha*q mod s_i
 *
 * The main problem is that we need to find alpha.
 * If we know alpha, we can compute x mod s_i (assuming that q mod s_i is precomputed).
 *
 * We compute x mod s_i in two steps:
 * 	(1) find x' mod s_i = \sum_k [xi (q/qi)^{-1}]_qi \times q/qi mod s_i and find alpha when computing this sum;
 * 	(2) subtract alpha*q mod s_i from x' mod s_i.
 *
 * We compute lyam_i =  [xi (q/qi)^{-1}]_qi/qi, which is a floating-point number between 0 and 1, during the summation in step 1.
 * Then we compute alpha as Round(\sum_i lyam_i).
 *
 * Finally, we evaluate (x' - alpha q) mod s_i to get the CRT basis of x with respect to S.
 *
 */

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::SwitchCRTBasis(
		const shared_ptr<ParmType> params, const std::vector<typename PolyType::Integer> &qInvModqi,
		const std::vector<std::vector<typename PolyType::Integer>> &qDivqiModsi, const std::vector<typename PolyType::Integer> &qModsi) const{

	DCRTPolyType ans(params,m_format,true);

	usint ringDimension = GetRingDimension();
	usint nTowers = m_vectors.size();
	usint nTowersNew = ans.m_vectors.size();

	for( usint rIndex = 0; rIndex < ringDimension; rIndex++ ) {

		std::vector<typename PolyType::Integer> xInvVector(nTowers);
		double lyam = 0.0;

		// Compute alpha and vector of x_i terms
		for( usint vIndex = 0; vIndex < nTowers; vIndex++ ) {
			const typename PolyType::Integer &xi = m_vectors[vIndex].GetValues()[rIndex];
			const typename PolyType::Integer &qi = m_vectors[vIndex].GetModulus();

			//computes [xi (q/qi)^{-1}]_qi
			xInvVector[vIndex] = xi.ModMulFast(qInvModqi[vIndex],qi);

			//computes [xi (q/qi)^{-1}]_qi / qi to keep track of the number of q-overflows
			lyam += (double)xInvVector[vIndex].ConvertToInt()/(double)qi.ConvertToInt();
		}

		// alpha corresponds to the number of overflows
		typename PolyType::Integer alpha = std::llround(lyam);

		// alpha may get estimated incorrectly in this region; so we apply a correction procedure
		// currently we use the multiprecision approach for simplicity but we will change it to
		// the single-precision approach proposed by Kawamura et al. in https://doi.org/10.1007/3-540-45539-6_37
		if ((std::fabs(std::llround(lyam*2)/(double)2 - lyam) < nTowers*(2.22e-16)) && (std::llround(lyam*2) % 2 == 1) ){

			BigInteger xBig = 0;

			for( usint vIndex = 0; vIndex < nTowers; vIndex++ ) {

				BigInteger qi = m_vectors[vIndex].GetModulus();

				xBig += xInvVector[vIndex]*params->GetModulus()/qi;

			}

			BigInteger alphaBig = xBig.DivideAndRound(params->GetModulus());

			alpha = alphaBig.ConvertToInt();

		}

		for (usint newvIndex = 0; newvIndex < nTowersNew; newvIndex ++ ) {

			typename PolyType::Integer curValue = 0;

			const typename PolyType::Integer &si = ans.m_vectors[newvIndex].GetModulus();

			//first round - compute "fast conversion"
			for( usint vIndex = 0; vIndex < nTowers; vIndex++ ) {
				curValue += xInvVector[vIndex].ModMulFast(qDivqiModsi[newvIndex][vIndex],si);
			}

			// Since we let current value to exceed si to avoid extra modulo reductions, we have to apply mod si now
			curValue = curValue.Mod(si);

			//second round - remove q-overflows
			ans.m_vectors[newvIndex].at(rIndex) = curValue.ModSubFast(alpha.ModMulFast(qModsi[newvIndex],si),si);

		}

	}

	return std::move(ans);

}

// Source: Halevi S. and Polyakov Y. (in preparation, 2018) A Simpler, Faster RNS Variant of the BFV Homomorphic Encryption Scheme.
//
// @brief Expands polynomial in CRT basis Q = q1*q2*...*qn to a larger CRT basis Q*S, where S = s1*s2*...*sn;
// uses SwichCRTBasis as a subroutine; Outputs the resulting polynomial in EVALUATION representation

template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::ExpandCRTBasis(const shared_ptr<ParmType> paramsExpanded,
		const shared_ptr<ParmType> params, const std::vector<typename PolyType::Integer> &qInvModqi,
		const std::vector<std::vector<typename PolyType::Integer>> &qDivqiModsi, const std::vector<typename PolyType::Integer> &qModsi) {

	std::vector<PolyType> polyInNTT;

	// if the input polynomial is in evaluation representation, store it for later use to reduce the number of NTTs
	if (this->GetFormat() == EVALUATION) {
		polyInNTT = m_vectors;
		this->SwitchFormat();
	}

	DCRTPolyType polyWithSwitchedCRTBasis = SwitchCRTBasis(params,qInvModqi,qDivqiModsi,qModsi);

	size_t size = m_vectors.size();
	size_t newSize = polyWithSwitchedCRTBasis.m_vectors.size() + size;

	m_vectors.resize(newSize);

	// populate the towers corresponding to CRT basis S and convert them to evaluation representation
	for (size_t i = 0; i < polyWithSwitchedCRTBasis.m_vectors.size(); i++ ) {
		m_vectors[size + i] = polyWithSwitchedCRTBasis.GetElementAtIndex(i);
		m_vectors[size + i].SwitchFormat();
	}

	if (polyInNTT.size() > 0) // if the input polynomial was in evaluation representation, use the towers for Q from it
	{
		for (size_t i = 0; i < size; i++ )
			m_vectors[i] = polyInNTT[i];
	}
	else
	{ // else call NTT for the towers for Q
		for (size_t i = 0; i <size; i++ )
			m_vectors[i].SwitchFormat();
	}

	m_format = EVALUATION;

	m_params = paramsExpanded;

}

//Source: Halevi S. and Polyakov Y. (in preparation, 2018) A Simpler, Faster RNS Variant of the BFV Homomorphic Encryption Scheme.
//
// Computes Round(p/Q*x), where x is in the CRT basis Q*S,
// as [\sum_{i=1}^n alpha_i*x_i + Round(\sum_{i=1}^n beta_i*x_i)]_si,
// with the result in the Q CRT basis; used in homomorphic multiplication of BFVrns;
// alpha is a matrix of precomputed integer factors = {Floor[p*S*[(Q*S/vi)^{-1}]_{vi}/vi]}_si; for all combinations of vi, si; where vi is a prime modulus in Q*S
// beta is a vector of precomputed floating-point factors between 0 and 1 = [p*S*(Q*S/vi)^{-1}]_{vi}/vi; - for each vi

template<typename ModType, typename IntType, typename VecType, typename ParmType>
DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyImpl<ModType,IntType,VecType,ParmType>::ScaleAndRound(const shared_ptr<ParmType> params,
		const std::vector<std::vector<typename PolyType::Integer>> &alpha,
		const std::vector<double> &beta) const {

		DCRTPolyType ans(params,m_format,true);

		usint ringDimension = GetRingDimension();
		size_t size = m_vectors.size();
		size_t newSize = ans.m_vectors.size();

		for( usint rIndex = 0; rIndex < ringDimension; rIndex++ ) {

			for (usint newvIndex = 0; newvIndex < newSize; newvIndex ++ ) {

				double curFloat = 0.0;
				typename PolyType::Integer curValue = 0;

				const typename PolyType::Integer &si = params->GetParams()[newvIndex]->GetModulus();

				for( usint vIndex = 0; vIndex < size; vIndex++ ) {
					const typename PolyType::Integer &xi = m_vectors[vIndex].GetValues()[rIndex];

					curValue += alpha[vIndex][newvIndex].ModMulFast(xi,si);

					curFloat += beta[vIndex]*xi.ConvertToInt();

				}

				// Since we let current value to exceed si to avoid extra modulo reductions, we have apply mod si now
				curValue = curValue.Mod(si);

				typename PolyType::Integer rounded = std::llround(curFloat);

				ans.m_vectors[newvIndex].at(rIndex) = curValue.ModAddFast(rounded.Mod(si),si);

			}

		}

		return std::move(ans);

}

/*Switch format calls IlVector2n's switchformat*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::SwitchFormat()
{
	if (m_format == COEFFICIENT) {
		m_format = EVALUATION;
	} else {
		m_format = COEFFICIENT;
	}

//#pragma omp parallel for
	for (usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i].SwitchFormat();
	}
}

#ifdef OUT
template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::SwitchModulus(const IntType &modulus, const IntType &rootOfUnity)
{
	m_modulus = ModType::ONE;
	for (usint i = 0; i < m_vectors.size(); ++i) {
		auto mod = modulus % ModType((*m_params)[i]->GetModulus().ConvertToInt());
		auto root = rootOfUnity % ModType((*m_params)[i]->GetModulus().ConvertToInt());
		m_vectors[i].SwitchModulus(mod.ConvertToInt(), root.ConvertToInt());
		m_modulus = m_modulus * mod;
	}
}
#endif

template<typename ModType, typename IntType, typename VecType, typename ParmType>
void DCRTPolyImpl<ModType,IntType,VecType,ParmType>::SwitchModulusAtIndex(usint index, const IntType &modulus, const IntType &rootOfUnity)
{
	if(index > m_vectors.size()-1) {
		std::string errMsg;
		errMsg = "DCRTPolyImpl is of size = " + std::to_string(m_vectors.size()) + " but SwitchModulus for tower at index " + std::to_string(index) + "is called.";
		throw std::runtime_error(errMsg);
	}

	m_vectors[index].SwitchModulus(PolyType::Integer(modulus.ConvertToInt()), PolyType::Integer(rootOfUnity.ConvertToInt()));
	m_params->RecalculateModulus();
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
bool DCRTPolyImpl<ModType,IntType,VecType,ParmType>::InverseExists() const
{
	for (usint i = 0; i < m_vectors.size(); i++) {
		if (!m_vectors[i].InverseExists()) return false;
	}
	return true;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
double DCRTPolyImpl<ModType, IntType, VecType, ParmType>::Norm() const
{
	PolyLargeType poly(CRTInterpolate());
	return poly.Norm();
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
bool DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Serialize(Serialized* serObj) const
{
	if( !serObj->IsObject() )
		return false;

	Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
	if (!m_params->Serialize(&obj))
		return false;


	obj.AddMember("Format", std::to_string(this->GetFormat()), serObj->GetAllocator());

	SerializeVector<PolyType>("Vectors", "PolyImpl", this->GetAllElements(), &obj);

	serObj->AddMember("DCRTPolyImpl", obj, serObj->GetAllocator());

	return true;
}

template<typename ModType, typename IntType, typename VecType, typename ParmType>
bool DCRTPolyImpl<ModType,IntType,VecType,ParmType>::Deserialize(const Serialized& serObj)
{
	SerialItem::ConstMemberIterator it = serObj.FindMember("DCRTPolyImpl");

	if( it == serObj.MemberEnd() )
		return false;

	SerialItem::ConstMemberIterator pIt = it->value.FindMember("ILDCRTParams");
	if (pIt == it->value.MemberEnd()) return false;

	Serialized parm(rapidjson::kObjectType);
	parm.AddMember(SerialItem(pIt->name, parm.GetAllocator()), SerialItem(pIt->value, parm.GetAllocator()), parm.GetAllocator());

	shared_ptr<ParmType> json_ilParams(new ParmType());
	if (!json_ilParams->Deserialize(parm))
		return false;
	m_params = json_ilParams;

	SerialItem::ConstMemberIterator mIt = it->value.FindMember("Format");
	if( mIt == it->value.MemberEnd() ) return false;
	this->m_format = static_cast<Format>(std::stoi(mIt->value.GetString()));

	mIt = it->value.FindMember("Vectors");

	if( mIt == it->value.MemberEnd() ) {
		return false;
	}

	bool ret = DeserializeVector<PolyType>("Vectors", "PolyImpl", mIt, &this->m_vectors);

	return ret;
}


 template<typename ModType, typename IntType, typename VecType, typename ParmType>
   std::ostream& operator<<(std::ostream &os, const DCRTPolyImpl<ModType,IntType,VecType,ParmType> & p)

 //TODO: Standardize this printing so it is like other poly's
 {
        os<<"---START PRINT DOUBLE CRT-- WITH SIZE" <<p.m_vectors.size() << std::endl;
	for(usint i = 0; i < p.m_vectors.size(); i++) {
		os<<"VECTOR " << i << std::endl;
		os<<p.m_vectors[i];
	}
	os<<"---END PRINT DOUBLE CRT--" << std::endl;
	return os;
}



} // namespace lbcrypto ends
