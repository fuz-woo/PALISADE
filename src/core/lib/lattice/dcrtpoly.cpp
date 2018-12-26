/**
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
template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl() {
    m_format = EVALUATION;
    m_params.reset( new DCRTPolyImpl::Params(0,1) );
}

template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const shared_ptr<DCRTPolyImpl::Params> dcrtParams, Format format, bool initializeElementToZero) {
    m_format = format;
    m_params = dcrtParams;

    size_t vecSize = dcrtParams->GetParams().size();
    m_vectors.reserve(vecSize);

    for (usint i = 0; i < vecSize; i++) {
        m_vectors.push_back(std::move(PolyType(dcrtParams->GetParams()[i],format,initializeElementToZero)));
    }
}

template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const DCRTPolyImpl &element)
{
    m_format = element.m_format;
    m_vectors = element.m_vectors;
    m_params = element.m_params;
}

template<typename VecType>
const DCRTPolyImpl<VecType>&
DCRTPolyImpl<VecType>::operator=(const PolyLargeType &element)
{

    if ( element.GetModulus() > m_params->GetModulus() ) {
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
    std::vector<Integer> bigmods;
    bigmods.reserve(vecCount);
    for( usint i = 0; i < vecCount; i++ )
        bigmods.push_back( Integer(m_params->GetParams()[i]->GetModulus().ConvertToInt()) );

    // copy each coefficient mod the new modulus
    for(usint p = 0; p < element.GetLength(); p++ ) {
        for( usint v = 0; v < vecCount; v++ ) {

            Integer tmp = element.at(p) % bigmods[v];
            m_vectors[v].at(p)= tmp.ConvertToInt();
        }
    }

    return *this;
}

template<typename VecType>
const DCRTPolyImpl<VecType>&
DCRTPolyImpl<VecType>::operator=(const NativePoly &element)
{

    if ( element.GetModulus() > m_params->GetModulus() ) {
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

    // gets moduli
    std::vector<NativeInteger> mods;
    mods.reserve(vecCount);
    for( usint i = 0; i < vecCount; i++ )
        mods.push_back( NativeInteger(m_params->GetParams()[i]->GetModulus().ConvertToInt()) );

    // copy each coefficient mod the new modulus
    for(usint p = 0; p < element.GetLength(); p++ ) {
        for( usint v = 0; v < vecCount; v++ ) {
            m_vectors[v][p] = element[p].Mod(mods[v]);
        }
    }

    return *this;
}

/* Construct from a single Poly. The format is derived from the passed in Poly.*/
template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const PolyLargeType &element, const shared_ptr<DCRTPolyImpl::Params> params)
{
    Format format;
    try {
        format = element.GetFormat();
    } catch (const std::exception& e) {
        throw std::logic_error("There is an issue with the format of the Poly passed to the constructor of DCRTPolyImpl");
    }

    if ( element.GetCyclotomicOrder() != params->GetCyclotomicOrder() )
        throw std::logic_error("Cyclotomic order mismatch on input vector and parameters");

    m_format = format;
    m_params = params;

    *this = element;
}

/* Construct from a single Poly. The format is derived from the passed in Poly.*/
template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const NativePoly &element, const shared_ptr<DCRTPolyImpl::Params> params)
{
    Format format;
    try {
        format = element.GetFormat();
    } catch (const std::exception& e) {
        throw std::logic_error("There is an issue with the format of the NativePoly passed to the constructor of DCRTPolyImpl");
    }

    if ( element.GetCyclotomicOrder() != params->GetCyclotomicOrder() )
        throw std::logic_error("Cyclotomic order mismatch on input vector and parameters");

    m_format = format;
    m_params = params;

    *this = element;
}

/* Construct using a tower of vectors.
 * The params and format for the DCRTPolyImpl will be derived from the towers
 */
template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const std::vector<PolyType> &towers)
{
    usint cyclotomicOrder = towers.at(0).GetCyclotomicOrder();
    std::vector<std::shared_ptr<ILNativeParams>> parms;
    for (usint i = 0; i < towers.size(); i++) {
        if ( towers[i].GetCyclotomicOrder() != cyclotomicOrder ) {
            throw std::logic_error("Polys provided to constructor must have the same ring dimension");
        }
        parms.push_back( towers[i].GetParams() );
    }

    shared_ptr<DCRTPolyImpl::Params> p( new DCRTPolyImpl::Params(cyclotomicOrder, parms) );

    m_params = p;
    m_vectors = towers;
    m_format = m_vectors[0].GetFormat();
}

/*The dgg will be the seed to populate the towers of the DCRTPolyImpl with random numbers. The algorithm to populate the towers can be seen below.*/
template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const DggType& dgg, const shared_ptr<DCRTPolyImpl::Params> dcrtParams, Format format)
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
            uint64_t    entry;
            // if the random generated value is less than zero, then multiply it by (-1) and subtract the modulus of the current tower to set the coefficient
            int64_t k = (dggValues.get())[j];
            if (k < 0) {
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
        if (m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
            ilvector.SwitchFormat();
        }
        m_vectors.push_back(ilvector);
    }
}

template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(DugType& dug, const shared_ptr<DCRTPolyImpl::Params> dcrtParams, Format format)
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

template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const BugType& bug, const shared_ptr<DCRTPolyImpl::Params> dcrtParams, Format format)
{

    m_format = format;
    m_params = dcrtParams;

    size_t numberOfTowers = dcrtParams->GetParams().size();
    m_vectors.reserve(numberOfTowers);

    PolyType ilvector(bug,dcrtParams->GetParams()[0],COEFFICIENT);

    for (usint i = 0; i < numberOfTowers; i++) {

        if (i > 0)
            ilvector.SwitchModulus(dcrtParams->GetParams()[i]->GetModulus(),dcrtParams->GetParams()[i]->GetRootOfUnity());

        auto newVector = ilvector;
        if (m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
            newVector.SwitchFormat();
        }
        m_vectors.push_back(newVector);
    }
}

template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const TugType& tug, const shared_ptr<DCRTPolyImpl::Params> dcrtParams, Format format)
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
            uint64_t    entry;
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
template<typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const DCRTPolyImpl &&element)
{
    m_format = element.m_format;
    m_vectors = std::move(element.m_vectors);
    m_params = std::move(element.m_params);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::CloneParametersOnly() const
{

    DCRTPolyImpl res(this->m_params, this->m_format);
    return std::move(res);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType> &dgg, Format format) const
{

    DCRTPolyImpl res = CloneParametersOnly();

    VecType randVec = dgg.GenerateVector(m_params->GetCyclotomicOrder() / 2, m_params->GetModulus());

    // create an Element to pull from
    // create a dummy parm to use in the Poly world
    shared_ptr<ILParamsImpl<Integer>> parm( new ILParamsImpl<Integer>(m_params->GetCyclotomicOrder(), m_params->GetModulus(), 1) );
    PolyLargeType element( parm );
    element.SetValues( randVec, m_format );

    res = element;

    return std::move(res);
}

// DESTRUCTORS

template<typename VecType>
DCRTPolyImpl<VecType>::~DCRTPolyImpl() {}

// GET ACCESSORS
template<typename VecType>
const typename DCRTPolyImpl<VecType>::PolyType& DCRTPolyImpl<VecType>::GetElementAtIndex (usint i) const
{
    if(m_vectors.empty())
        throw std::logic_error("DCRTPolyImpl's towers are not initialized.");
    if(i > m_vectors.size()-1)
        throw std::logic_error("Index: " + std::to_string(i) + " is out of range.");
    return m_vectors[i];
}

template<typename VecType>
usint DCRTPolyImpl<VecType>::GetNumOfElements() const
{
    return m_vectors.size();
}

template<typename VecType>
const std::vector<typename DCRTPolyImpl<VecType>::PolyType>& DCRTPolyImpl<VecType>::GetAllElements() const
{
    return m_vectors;
}

template<typename VecType>
Format DCRTPolyImpl<VecType>::GetFormat() const
{
    return m_format;
}

template<typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const
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

    std::vector<DCRTPolyImpl<VecType>> result;

    // populate the result by converting each of the big vectors into a VectorArray
    for( usint i=0; i<bdV.size(); i++ ) {
        DCRTPolyImpl<VecType> dv(bdV[i], this->GetParams());
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

template<typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::CRTDecompose(uint32_t baseBits) const
{

    uint32_t nWindows = 1;

    if (baseBits > 0) {
        uint32_t nBits = m_vectors[0].GetModulus().GetLengthForBase(2);

        nWindows = nBits / baseBits;
        if (nBits % baseBits > 0)
            nWindows++;
    }

    std::vector<DCRTPolyType> result(m_vectors.size()*nWindows);

    DCRTPolyType input = this->Clone();

    if (input.GetFormat() == EVALUATION)
        input.SwitchFormat();

#pragma omp parallel for
    for( usint i=0; i<m_vectors.size(); i++ ) {

        if (baseBits == 0)
        {
            DCRTPolyType currentDCRTPoly = input.Clone();

            for ( usint k=0; k<m_vectors.size(); k++ ){
                PolyType temp(input.m_vectors[i]);
                if (i!=k)
                    temp.SwitchModulus(input.m_vectors[k].GetModulus(),input.m_vectors[k].GetRootOfUnity());
                currentDCRTPoly.m_vectors[k] = temp;
            }

            currentDCRTPoly.SwitchFormat();

            result[i] = std::move(currentDCRTPoly);
        }
        else
        {

            vector<PolyType> decomposed = input.m_vectors[i].BaseDecompose(baseBits,false);

            for (size_t j = 0; j < decomposed.size();  j++) {

                DCRTPolyType currentDCRTPoly = input.Clone();

                for ( usint k=0; k<m_vectors.size(); k++ ){
                    PolyType temp(decomposed[j]);
                    if (i!=k)
                        temp.SwitchModulus(input.m_vectors[k].GetModulus(),input.m_vectors[k].GetRootOfUnity());
                    currentDCRTPoly.m_vectors[k] = temp;
                }

                currentDCRTPoly.SwitchFormat();

                result[j + i*nWindows] = std::move(currentDCRTPoly);

            }

        }
    }

    return std::move(result);
}

template<typename VecType>
PolyImpl<NativeVector>& DCRTPolyImpl<VecType>::ElementAtIndex(usint i)
{
    return m_vectors[i];
}


template<typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::PowersOfBase(usint baseBits) const
{
    bool dbg_flag = false;

    std::vector<DCRTPolyImpl<VecType>> result;

    usint nBits = m_params->GetModulus().GetLengthForBase(2);

    usint nWindows = nBits / baseBits;
    if (nBits % baseBits > 0)
        nWindows++;

    result.reserve(nWindows);

    // prepare for the calculations by gathering a big integer version of each of the little moduli
    std::vector<Integer> mods(m_params->GetParams().size());
    for( usint i = 0; i < m_params->GetParams().size(); i++ ) {
        mods[i] = Integer(m_params->GetParams()[i]->GetModulus().ConvertToInt());
        DEBUG("DCRTPolyImpl::PowersOfBase.mods[" << i << "] = " << mods[i] );
    }


    for( usint i = 0; i < nWindows; i++ ) {
        DCRTPolyType x( m_params, m_format );

        // Shouldn't this be Integer twoPow ( Integer::ONE << (i*baseBits)  ??
        Integer twoPow( Integer(2).Exp( i*baseBits ) );
        DEBUG("DCRTPolyImpl::PowersOfBase.twoPow (" << i << ") = " << twoPow );
        for( usint t = 0; t < m_params->GetParams().size(); t++ ) {
            DEBUG("@(" << i << ", " << t << ")" );
            DEBUG("twoPow= " << twoPow << ", mods[" << t << "]" << mods[t] );
            Integer pI (twoPow % mods[t]);
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

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::MultiplicativeInverse() const
{
    DCRTPolyImpl<VecType> tmp(*this);

    for (usint i = 0; i < m_vectors.size(); i++) {
        tmp.m_vectors[i] = m_vectors[i].MultiplicativeInverse();
    }
    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ModByTwo() const
{
    DCRTPolyImpl<VecType> tmp(*this);

    for (usint i = 0; i < m_vectors.size(); i++) {
        tmp.m_vectors[i] = m_vectors[i].ModByTwo();
    }
    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Plus(const DCRTPolyImpl &element) const
{
    if( m_vectors.size() != element.m_vectors.size() ) {
        throw std::logic_error("tower size mismatch; cannot add");
    }
    DCRTPolyImpl<VecType> tmp(*this);

    for (usint i = 0; i < tmp.m_vectors.size(); i++) {
        tmp.m_vectors[i] += element.GetElementAtIndex (i);
    }
    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Negate() const
{
    DCRTPolyImpl<VecType> tmp(this->CloneParametersOnly());
    tmp.m_vectors.clear();

    for (usint i = 0; i < this->m_vectors.size(); i++) {
        tmp.m_vectors.push_back(std::move(this->m_vectors.at(i).Negate()));
    }

    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Minus(const DCRTPolyImpl &element) const
{
    if( m_vectors.size() != element.m_vectors.size() ) {
        throw std::logic_error("tower size mismatch; cannot subtract");
    }
    DCRTPolyImpl<VecType> tmp(*this);

    for (usint i = 0; i < tmp.m_vectors.size(); i++) {
        tmp.m_vectors[i] -= element.GetElementAtIndex (i);
    }
    return std::move(tmp);
}

template<typename VecType>
const DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator+=(const DCRTPolyImpl &rhs)
{
    for (usint i = 0; i < this->GetNumOfElements(); i++) {
        this->m_vectors[i] += rhs.m_vectors[i];
    }
    return *this;

}

template<typename VecType>
const DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator-=(const DCRTPolyImpl &rhs)
{
    for (usint i = 0; i < this->GetNumOfElements(); i++) {
        this->m_vectors.at(i) -= rhs.m_vectors[i];
    }
    return *this;

}

template<typename VecType>
const DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator*=(const DCRTPolyImpl &element)
{
    for (usint i = 0; i < this->m_vectors.size(); i++) {
        this->m_vectors.at(i) *= element.m_vectors.at(i);
    }

    return *this;

}

template<typename VecType>
bool DCRTPolyImpl<VecType>::operator==(const DCRTPolyImpl &rhs) const
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

template<typename VecType>
const DCRTPolyImpl<VecType> & DCRTPolyImpl<VecType>::operator=(const DCRTPolyImpl & rhs)
{
    if (this != &rhs) {
        m_vectors = rhs.m_vectors;
        m_format = rhs.m_format;
        m_params = rhs.m_params;
    }
    return *this;
}

template<typename VecType>
const DCRTPolyImpl<VecType> & DCRTPolyImpl<VecType>::operator=(DCRTPolyImpl&& rhs)
{
    if (this != &rhs) {
        m_vectors = std::move(rhs.m_vectors);
        m_format = std::move(rhs.m_format);
        m_params = std::move(rhs.m_params);
    }
    return *this;
}

template<typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs)
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
template<typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(uint64_t val)
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
template<typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(std::vector<int64_t> val)
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
template<typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(std::vector<int32_t> val)
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

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Plus(const Integer &element) const
{
    DCRTPolyImpl<VecType> tmp(*this);

    for (usint i = 0; i < tmp.m_vectors.size(); i++) {
        tmp.m_vectors[i] += element.ConvertToInt();
    }
    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Minus(const Integer &element) const
{
    DCRTPolyImpl<VecType> tmp(*this);

    for (usint i = 0; i < tmp.m_vectors.size(); i++) {
        tmp.m_vectors[i] -= element.ConvertToInt();
    }
    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(const DCRTPolyImpl & element) const
{
    if( m_vectors.size() != element.m_vectors.size() ) {
        throw std::logic_error("tower size mismatch; cannot multiply");
    }
    DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
    for (usint i = 0; i < m_vectors.size(); i++) {
        //ModMul multiplies and performs a mod operation on the results. The mod is the modulus of each tower.
        tmp.m_vectors[i] *= element.m_vectors[i];
    }
    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(const Integer &element) const
{
    DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
    for (usint i = 0; i < m_vectors.size(); i++) {
        tmp.m_vectors[i] = tmp.m_vectors[i] * element.ConvertToInt(); // (element % Integer((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
    }
    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(
        const std::vector<NativeInteger> &element) const
{
    DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
    for (usint i = 0; i < m_vectors.size(); i++) {
        tmp.m_vectors[i] *= element[i]; // (element % Integer((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
    }
    return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::MultiplyAndRound(const Integer &p, const Integer &q) const
{
    std::string errMsg = "Operation not implemented yet";
    throw std::runtime_error(errMsg);
    return *this;
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::DivideAndRound(const Integer &q) const
{
    std::string errMsg = "Operation not implemented yet";
    throw std::runtime_error(errMsg);
    return *this;
}

template<typename VecType>
const DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator*=(const Integer &element)
{
    for (usint i = 0; i < this->m_vectors.size(); i++) {
        this->m_vectors.at(i) *= (element.Mod(this->m_vectors[i].GetModulus())).ConvertToInt(); //this->m_vectors.at(i) * (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
    }

    return *this;
}


template<typename VecType>
  void DCRTPolyImpl<VecType>::SetValuesToZero()
  {
    for(usint i = 0; i < m_vectors.size(); i++) {
        m_vectors[i].SetValuesToZero();
    }
  }
/*OTHER FUNCTIONS*/


  
template<typename VecType>
void DCRTPolyImpl<VecType>::AddILElementOne()
{
    if(m_format != Format::EVALUATION)
        throw std::runtime_error("DCRTPolyImpl<VecType>::AddILElementOne cannot be called on a DCRTPolyImpl in COEFFICIENT format.");
    for(usint i = 0; i < m_vectors.size(); i++) {
        m_vectors[i].AddILElementOne();
    }
}

template<typename VecType>
void DCRTPolyImpl<VecType>::MakeSparse(const uint32_t &wFactor)
{
    for(usint i = 0; i < m_vectors.size(); i++) {
        m_vectors[i].MakeSparse(wFactor);
    }
}

// This function modifies PolyArrayImpl to keep all the even indices in the tower.
// It reduces the ring dimension of the tower by half.
template<typename VecType>
void DCRTPolyImpl<VecType>::Decompose()
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
    m_params.reset( new DCRTPolyImpl::Params(vparms[0]->GetCyclotomicOrder(), vparms) );
}

template<typename VecType>
bool DCRTPolyImpl<VecType>::IsEmpty() const
{
    for(size_t i=0; i<m_vectors.size(); i++) {
        if(!m_vectors.at(i).IsEmpty())
            return false;
    }
    return true;
}

template<typename VecType>
void DCRTPolyImpl<VecType>::DropLastElement()
{
    if(m_vectors.size() == 0) {
        throw std::out_of_range("Last element being removed from empty list");
    }

    m_vectors.resize(m_vectors.size() - 1);
    DCRTPolyImpl::Params *newP = new DCRTPolyImpl::Params( *m_params );
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
template<typename VecType>
void DCRTPolyImpl<VecType>::ModReduce(const Integer &plaintextModulus)
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
    DEBUG("a:   "<<a);

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
template<typename VecType>
typename DCRTPolyImpl<VecType>::PolyLargeType DCRTPolyImpl<VecType>::CRTInterpolate() const
{
    bool dbg_flag = false;

    usint ringDimension = GetRingDimension();
    usint nTowers = m_vectors.size();

    DEBUG("in Interpolate ring " << ringDimension << " towers " << nTowers);

    for( usint vi = 0; vi < nTowers; vi++ )
        DEBUG("tower " << vi << " is " << m_vectors[vi]);

    Integer bigModulus(GetModulus()); // qT

    DEBUG("bigModulus " << bigModulus);

    // this is the resulting vector of coefficients
    VecType coefficients(ringDimension, bigModulus);

    // this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj *[ (qt/qj)^(-1) mod qj ]}modqt

    // first, precompute qt/qj factors
    vector<Integer> multiplier(nTowers);
    for( usint vi = 0 ; vi < nTowers; vi++ ) {
        Integer qj(m_vectors[vi].GetModulus().ConvertToInt());
        Integer divBy = bigModulus / qj;
        Integer modInv = divBy.ModInverse(qj).Mod(qj);
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
    Integer mu = ComputeMu<Integer>(bigModulus);

    // now, compute the values for the vector
#pragma omp parallel for
    for( usint ri = 0; ri < ringDimension; ri++ ) {
        coefficients[ri] = 0;
        for( usint vi = 0; vi < nTowers; vi++ ) {
            coefficients[ri] += (Integer((*vecs)[vi].GetValues()[ri].ConvertToInt()) * multiplier[vi]);
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
    typename DCRTPolyImpl<VecType>::PolyLargeType polynomialReconstructed( shared_ptr<ILParamsImpl<Integer>>( new ILParamsImpl<Integer>(GetCyclotomicOrder(), bigModulus, 1) ) );
    polynomialReconstructed.SetValues(coefficients,COEFFICIENT);

    DEBUG("answer: " << polynomialReconstructed);

    return std::move( polynomialReconstructed );
}

// todo can we be smarter with this method?
template<typename VecType>
NativePoly DCRTPolyImpl<VecType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
    return this->CRTInterpolate().DecryptionCRTInterpolate(ptm);
}

//Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report 2018/117. (https://eprint.iacr.org/2018/117)
//
//Computes Round(p/q*x) mod p as [\sum_i x_i*alpha_i + Round(\sum_i x_i*beta_i)] mod p for fast rounding in RNS
// vectors alpha and beta are precomputed as
// alpha_i = Floor[(p*[(q/qi)^{-1}]_qi)/qi]_p
// beta_i = ((p*[(q/qi)^{-1}]_qi)%qi)/qi in (0,1)
// used in decryption of BFVrns

template<typename VecType>
PolyImpl<NativeVector>
DCRTPolyImpl<VecType>::ScaleAndRound(const NativeInteger &p,
        const std::vector<NativeInteger> &alpha, const std::vector<double> &beta,
        const std::vector<NativeInteger> &alphaPrecon, const std::vector<QuadFloat> &quadBeta,
        const std::vector<long double> &extBeta) const {

    usint ringDimension = GetRingDimension();
    usint nTowers = m_vectors.size();

    typename PolyType::Vector coefficients(ringDimension, p.ConvertToInt());

    if(m_vectors[0].GetModulus().GetMSB() < 45)
    {
#pragma omp parallel for
        for( usint ri = 0; ri < ringDimension; ri++ ) {
            double curFloatSum = 0.0;
            NativeInteger curIntSum = 0;
            for( usint vi = 0; vi < nTowers; vi++ ) {
                const NativeInteger &xi = m_vectors[vi].GetValues()[ri];

                // We assume that that the value of p is smaller than 64 bits (like 58)
                // Thus we do not make additional curIntSum.Mod(p) calls for each value of vi
                //curIntSum += xi.ModMul(alpha[vi],p);
                curIntSum += xi.ModMulPreconOptimized(alpha[vi],p,alphaPrecon[vi]);

                curFloatSum += (double)(xi.ConvertToInt())*beta[vi];
            }

            coefficients[ri] = (curIntSum + NativeInteger(std::llround(curFloatSum))).Mod(p);
        }
    }
    else if (m_vectors[0].GetModulus().GetMSB() < 58)
    {
#pragma omp parallel for
        for( usint ri = 0; ri < ringDimension; ri++ ) {
            long double curFloatSum = 0.0;
            NativeInteger curIntSum = 0;
            for( usint vi = 0; vi < nTowers; vi++ ) {
                const NativeInteger &xi = m_vectors[vi].GetValues()[ri];

                // We assume that that the value of p is smaller than 64 bits (like 58)
                // Thus we do not make additional curIntSum.Mod(p) calls for each value of vi
                //curIntSum += xi.ModMul(alpha[vi],p);
                curIntSum += xi.ModMulPreconOptimized(alpha[vi],p,alphaPrecon[vi]);

                curFloatSum += (long double)(xi.ConvertToInt())*extBeta[vi];
            }

            coefficients[ri] = (curIntSum + NativeInteger(std::llround(curFloatSum))).Mod(p);
        }
    }
    else
    {

        if (nTowers > 16) // handles the case when curFloatSum exceeds 2^63 (causing an an overflow in int)
            {
            QuadFloat pFloat = quadFloatFromInt64(p.ConvertToInt());

#pragma omp parallel for
            for( usint ri = 0; ri < ringDimension; ri++ ) {
                QuadFloat curFloatSum = QuadFloat(0);
                NativeInteger curIntSum = 0;
                for( usint vi = 0; vi < nTowers; vi++ ) {
                    const NativeInteger &xi = m_vectors[vi].GetValues()[ri];

                    // We assume that that the value of p is smaller than 64 bits (like 58)
                    // Thus we do not make additional curIntSum.Mod(p) calls for each value of vi
                    //curIntSum += xi.ModMul(alpha[vi],p);
                    curIntSum += xi.ModMulPreconOptimized(alpha[vi],p,alphaPrecon[vi]);

                    curFloatSum += quadFloatFromInt64(xi.ConvertToInt())*quadBeta[vi];
                }

                coefficients[ri] = (curIntSum + NativeInteger(quadFloatRound(curFloatSum - pFloat*floor(curFloatSum/pFloat)))).Mod(p);
            }
        }
        else
        {
#pragma omp parallel for
            for( usint ri = 0; ri < ringDimension; ri++ ) {
                QuadFloat curFloatSum = QuadFloat(0);
                NativeInteger curIntSum = 0;
                for( usint vi = 0; vi < nTowers; vi++ ) {
                    const NativeInteger &xi = m_vectors[vi].GetValues()[ri];

                    // We assume that that the value of p is smaller than 64 bits (like 58)
                    // Thus we do not make additional curIntSum.Mod(p) calls for each value of vi
                    //curIntSum += xi.ModMul(alpha[vi],p);
                    curIntSum += xi.ModMulPreconOptimized(alpha[vi],p,alphaPrecon[vi]);

                    curFloatSum += quadFloatFromInt64(xi.ConvertToInt())*quadBeta[vi];
                }

                coefficients[ri] = (curIntSum + NativeInteger(quadFloatRound(curFloatSum))).Mod(p);
            }
        }
    }

    // Setting the root of unity to ONE as the calculation is expensive
    // It is assumed that no polynomial multiplications in evaluation representation are performed after this
    PolyType result( shared_ptr<typename PolyType::Params>( new typename PolyType::Params(GetCyclotomicOrder(), p.ConvertToInt(), 1) ) );
    result.SetValues(coefficients,COEFFICIENT);

    return std::move(result);

}

/*
 * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report 2018/117. (https://eprint.iacr.org/2018/117)
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
 *  (1) find x' mod s_i = \sum_k [xi (q/qi)^{-1}]_qi \times q/qi mod s_i and find alpha when computing this sum;
 *  (2) subtract alpha*q mod s_i from x' mod s_i.
 *
 * We compute lyam_i =  [xi (q/qi)^{-1}]_qi/qi, which is a floating-point number between 0 and 1, during the summation in step 1.
 * Then we compute alpha as Round(\sum_i lyam_i).
 *
 * Finally, we evaluate (x' - alpha q) mod s_i to get the CRT basis of x with respect to S.
 *
 */

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::SwitchCRTBasis(
        const shared_ptr<DCRTPolyImpl::Params> params, const std::vector<NativeInteger> &qInvModqi,
        const std::vector<std::vector<NativeInteger>> &qDivqiModsi, const std::vector<NativeInteger> &qModsi,
        const std::vector<DoubleNativeInteger> &siModulimu, const std::vector<NativeInteger> &qInvModqiPrecon) const{

    DCRTPolyType ans(params,m_format,true);

    usint ringDimension = GetRingDimension();
    usint nTowers = m_vectors.size();
    usint nTowersNew = ans.m_vectors.size();

#pragma omp parallel for
    for( usint rIndex = 0; rIndex < ringDimension; rIndex++ ) {

        std::vector<NativeInteger> xInvVector(nTowers);
        double nu = 0.0;

        // Compute alpha and vector of x_i terms
        for( usint vIndex = 0; vIndex < nTowers; vIndex++ ) {
            const NativeInteger &xi = m_vectors[vIndex].GetValues()[rIndex];
            const NativeInteger &qi = m_vectors[vIndex].GetModulus();

            //computes [xi (q/qi)^{-1}]_qi
            xInvVector[vIndex] = xi.ModMulPreconOptimized(qInvModqi[vIndex],qi,qInvModqiPrecon[vIndex]);

            //computes [xi (q/qi)^{-1}]_qi / qi to keep track of the number of q-overflows
            nu += (double)xInvVector[vIndex].ConvertToInt()/(double)qi.ConvertToInt();
        }

        // alpha corresponds to the number of overflows
        NativeInteger alpha = std::llround(nu);

        for (usint newvIndex = 0; newvIndex < nTowersNew; newvIndex ++ ) {

            DoubleNativeInteger curValue = 0;

            const NativeInteger &si = ans.m_vectors[newvIndex].GetModulus();

            //first round - compute "fast conversion"
            for( usint vIndex = 0; vIndex < nTowers; vIndex++ ) {
                curValue += Mul128(xInvVector[vIndex].ConvertToInt(),qDivqiModsi[newvIndex][vIndex].ConvertToInt());
            }

            const NativeInteger &curNativeValue = NativeInteger(BarrettUint128ModUint64( curValue, si.ConvertToInt(), siModulimu[newvIndex]));

            //second round - remove q-overflows
            ans.m_vectors[newvIndex].at(rIndex) = curNativeValue.ModSubFast(alpha.ModMulFastOptimized(qModsi[newvIndex],si),si);

        }

    }

    return std::move(ans);

}

// Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report 2018/117. (https://eprint.iacr.org/2018/117)
//
// @brief Expands polynomial in CRT basis Q = q1*q2*...*qn to a larger CRT basis Q*S, where S = s1*s2*...*sn;
// uses SwichCRTBasis as a subroutine; Outputs the resulting polynomial in EVALUATION representation

template<typename VecType>
void DCRTPolyImpl<VecType>::ExpandCRTBasis(const shared_ptr<DCRTPolyImpl::Params> paramsExpanded,
        const shared_ptr<DCRTPolyImpl::Params> params, const std::vector<NativeInteger> &qInvModqi,
        const std::vector<std::vector<NativeInteger>> &qDivqiModsi, const std::vector<NativeInteger> &qModsi,
        const std::vector<DoubleNativeInteger> &siModulimu, const std::vector<NativeInteger> &qInvModqiPrecon) {

    std::vector<PolyType> polyInNTT;

    // if the input polynomial is in evaluation representation, store it for later use to reduce the number of NTTs
    if (this->GetFormat() == EVALUATION) {
        polyInNTT = m_vectors;
        this->SwitchFormat();
    }

    DCRTPolyType polyWithSwitchedCRTBasis = SwitchCRTBasis(params,qInvModqi,qDivqiModsi,qModsi, siModulimu, qInvModqiPrecon);

    size_t size = m_vectors.size();
    size_t newSize = polyWithSwitchedCRTBasis.m_vectors.size() + size;

    m_vectors.resize(newSize);

#pragma omp parallel for
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
#pragma omp parallel for
        for (size_t i = 0; i <size; i++ )
            m_vectors[i].SwitchFormat();
    }

    m_format = EVALUATION;

    m_params = paramsExpanded;

}

//Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes. Cryptology ePrint Archive: Report 2016/510. (https://eprint.iacr.org/2016/510)
//
// Computes Round(t/q*x) mod t for fast rounding in RNS
// vector qDivqiModqiTable are precomputed as (q/qi)^-1 mod qi
// matrix qDivqiModtgammaTable are precomputed as (q/qi) mod {t U gamma}, we assume t is stored first in the vector
// GCD(t, gamma) = 1
// used in decryption of BFVrnsB

template<typename VecType>
PolyImpl<NativeVector>
DCRTPolyImpl<VecType>::ScaleAndRound(
        const std::vector<NativeInteger> &qModuliTable,
        const NativeInteger &gamma,
        const NativeInteger &t,
        const NativeInteger &gammaInvModt,
        const NativeInteger &gammaInvModtPrecon,
        const std::vector<NativeInteger> &negqInvModtgammaTable,
        const std::vector<NativeInteger> &negqInvModtgammaPreconTable,
        const std::vector<NativeInteger> &tgammaqDivqiModqiTable,
        const std::vector<NativeInteger> &tgammaqDivqiModqiPreconTable,
        const std::vector<std::vector<NativeInteger>> &qDivqiModtgammaTable,
        const std::vector<std::vector<NativeInteger>> &qDivqiModtgammaPreconTable) const {

    usint n = GetRingDimension();
    usint numq = m_vectors.size();

    typename PolyType::Vector coefficients(n, t.ConvertToInt());

#pragma omp parallel for
    for (usint k = 0; k < n; k++)
    {
        NativeInteger sgamma = 0, st = 0, tmp, tmpt, tmpgamma;
        for (usint i = 0; i < numq; i++)
        {
            const NativeInteger &qi = qModuliTable[i];
            const NativeInteger &xi = m_vectors[i][k];
            tmp = xi;
            tmp.ModMulPreconOptimizedEq( tgammaqDivqiModqiTable[i], qi, tgammaqDivqiModqiPreconTable[i] ); // xi*t*gamma*(q/qi)^-1 mod qi

            tmpt = tmp.ModMulPreconOptimized( qDivqiModtgammaTable[i][0], t, qDivqiModtgammaPreconTable[i][0] ); // mod t
            tmpgamma = tmp.ModMulPreconOptimized( qDivqiModtgammaTable[i][1], gamma, qDivqiModtgammaPreconTable[i][1] ); // mod gamma

            st.ModAddFastOptimizedEq( tmpt, t.ConvertToInt() );
            sgamma.ModAddFastOptimizedEq( tmpgamma, gamma );
        }

        // mul by -q^-1
        st.ModMulPreconOptimizedEq(negqInvModtgammaTable[0], t, negqInvModtgammaPreconTable[0]);
        sgamma.ModMulPreconOptimizedEq( negqInvModtgammaTable[1], gamma, negqInvModtgammaPreconTable[1] );

        if ( sgamma > (gamma >> 1) )
            sgamma = sgamma.ModSubFast( gamma, t );

        tmp = st.ModSub( sgamma, t );

        coefficients[k] = tmp.ModMulPreconOptimized( gammaInvModt, t, gammaInvModtPrecon ).ConvertToInt();
    }

    // Setting the root of unity to ONE as the calculation is expensive
    // It is assumed that no polynomial multiplications in evaluation representation are performed after this
    PolyType result( shared_ptr<typename PolyType::Params>( new typename PolyType::Params(GetCyclotomicOrder(), t.ConvertToInt(), 1) ) );
    result.SetValues(coefficients,COEFFICIENT);

    return std::move(result);
}

//Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes. Cryptology ePrint Archive: Report 2016/510. (https://eprint.iacr.org/2016/510)
// Almost equivalent to "ExpandCRTBasis"
// @brief Expands polynomial in CRT basis q to a larger CRT basis {Bsk U mtilde}, mtilde is a redundant modulus used to remove q overflows generated from fast conversion.
// Outputs the resulting polynomial in CRT/RNS representation in basis {q U Bsk}
// used in EvalMult of BFVrnsB

template<typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvqToBskMontgomery(
        const shared_ptr<DCRTPolyImpl::Params> paramsBsk,
        const std::vector<NativeInteger> &qModuli,
        const std::vector<NativeInteger> &BskmtildeModuli,
        const std::vector<DoubleNativeInteger> &BskmtildeModulimu,
        const std::vector<NativeInteger> &mtildeqDivqiModqi,
        const std::vector<NativeInteger> &mtildeqDivqiModqiPrecon,
        const std::vector<std::vector<NativeInteger>> &qDivqiModBj,
        const std::vector<NativeInteger> &qModBski,
        const std::vector<NativeInteger> &qModBskiPrecon,
        const NativeInteger &negqInvModmtilde,
        const NativeInteger &negqInvModmtildePrecon,
        const std::vector<NativeInteger> &mtildeInvModBskiTable,
        const std::vector<NativeInteger> &mtildeInvModBskiPreconTable) {

    // Input: poly in basis q
    // Output: poly in base Bsk = {B U msk}

    //computing steps 0 and 1 in Algorithm 3 in source paper.

    std::vector<PolyType> polyInNTT;

    // if the input polynomial is in evaluation representation, store it for later use to reduce the number of NTTs
    if (this->GetFormat() == EVALUATION) {
        polyInNTT = m_vectors;
        this->SwitchFormat();
    }

    size_t numq = qModuli.size();
    size_t numBsk = BskmtildeModuli.size() - 1;
    size_t newSize = numq + BskmtildeModuli.size();

    m_vectors.resize(newSize);

    uint32_t n = GetLength();

    m_params = paramsBsk;

    // ----------------------- step 0 -----------------------

    // first we twist xi by mtilde*(q/qi)^-1 mod qi
    NativeInteger *ximtildeqiDivqModqi = new NativeInteger[n*numq];
    for (uint32_t i = 0; i < numq; i++)
    {
        const NativeInteger &currentmtildeqDivqiModqi = mtildeqDivqiModqi[i];
        const NativeInteger &currentmtildeqDivqiModqiPrecon = mtildeqDivqiModqiPrecon[i];

#pragma omp parallel for
        for (uint32_t k = 0; k < n; k++)
        {
            ximtildeqiDivqModqi[i*n + k] = m_vectors[i][k].ModMulPreconOptimized( currentmtildeqDivqiModqi, qModuli[i], currentmtildeqDivqiModqiPrecon);
        }
    }

    for (uint32_t j = 0; j < numBsk + 1; j++)
    {
        if( j < numBsk)
        {
            // TODO check this
            PolyType newvec(m_params->GetParams()[j], m_format, true);
            m_vectors[numq+j] = std::move(newvec);
        }
        else
        {
            // the mtilde vector (params not important)
            PolyType newvec(m_params->GetParams()[0], m_format, true);
            m_vectors[numq+j] = std::move(newvec);
        }

#pragma omp parallel for
        for ( uint32_t k = 0; k < n; k++ )
        {
            DoubleNativeInteger result = 0;
            for (uint32_t i = 0; i < numq; i++)
            {
                const NativeInteger &qDivqiModBjValue = qDivqiModBj[i][j];
                result += Mul128( ximtildeqiDivqModqi[i*n+k].ConvertToInt(), qDivqiModBjValue.ConvertToInt() );
            }
            m_vectors[numq+j][k] = BarrettUint128ModUint64( result, BskmtildeModuli[j].ConvertToInt(), BskmtildeModulimu[j] );
        }
    }

    // now we have input in Basis (q U Bsk U mtilde)
    // next we perform Small Motgomery Reduction mod q
    // ----------------------- step 1 -----------------------
    const NativeInteger &mtilde = BskmtildeModuli[numBsk];

    NativeInteger *r_m_tildes = new NativeInteger[n];

#pragma omp parallel for
    for ( uint32_t k = 0; k < n; k++ )
    {
        r_m_tildes[k] = m_vectors[numq+numBsk][k]; // c``_mtilde
        r_m_tildes[k].ModMulPreconOptimizedEq(negqInvModmtilde, mtilde, negqInvModmtildePrecon); // c``_mtilde*-1/q mod mtilde
    }

    for (uint32_t i = 0; i < numBsk; i++)
    {
        const NativeInteger &currentqModBski = qModBski[i];
        const NativeInteger &currentqModBskiPrecon = qModBskiPrecon[i];

#pragma omp parallel for
        for ( uint32_t k = 0; k < n; k++ )
        {
            // collapsing
            NativeInteger r_m_tilde = r_m_tildes[k]; // m_tilde < than all Bsk_i
            r_m_tilde.ModMulPreconOptimizedEq( currentqModBski, BskmtildeModuli[i], currentqModBskiPrecon ); // (r_mtilde) * q mod Bski
            r_m_tilde.ModAddFastOptimizedEq( m_vectors[numq+i][k], BskmtildeModuli[i] ); // (c``_m + (r_mtilde* q)) mod Bski
            m_vectors[numq+i][k] = r_m_tilde.ModMulPreconOptimized( mtildeInvModBskiTable[i], BskmtildeModuli[i], mtildeInvModBskiPreconTable[i] ); // (c``_m + (r_mtilde* q)) * mtilde mod Bski
        }
    }

    // remove mtilde residue
    m_vectors.erase(m_vectors.begin()+numq+numBsk);

    if (polyInNTT.size() > 0) // if the input polynomial was in evaluation representation, use the towers for Q from it
    {
        for (size_t i = 0; i < numq; i++ )
            m_vectors[i] = polyInNTT[i];
    }
    else
    { // else call NTT for the towers for q
#pragma omp parallel for
        for (size_t i = 0; i <numq; i++ )
            m_vectors[i].SwitchFormat();
    }

#pragma omp parallel for
    for (uint32_t i = 0; i < numBsk; i++)
        m_vectors[numq+i].SwitchFormat();


    m_format = EVALUATION;

    delete[] r_m_tildes;
    delete[] ximtildeqiDivqModqi;
    r_m_tildes = nullptr;
    ximtildeqiDivqModqi = nullptr;
}

// Source: Jean-Claude Bajard, Julien Eynard, Anwar Hasan, and Vincent Zucca.
// A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes.
// Cryptology ePrint Archive: Report 2016/510. (https://eprint.iacr.org/2016/510)
// Almost equivalent to "ScaleAndRound"
// @brief Scales polynomial in CRT basis {q U Bsk} by scalar t/q.
// Outputs the resulting polynomial
// in CRT/RNS representation in basis {q U Bsk}.
// Note that the actual result is basically in basis {Bsk}.
// used in EvalMult of BFVrnsB

template<typename VecType>
void DCRTPolyImpl<VecType>::FastRNSFloorq(
    const NativeInteger &t,
    const std::vector<NativeInteger> &qModuli,
    const std::vector<NativeInteger> &BskModuli,
    const std::vector<DoubleNativeInteger> &BskModulimu,
    const std::vector<NativeInteger> &tqDivqiModqi,
    const std::vector<NativeInteger> &tqDivqiModqiPrecon,
    const std::vector<std::vector<NativeInteger>> &qDivqiModBj,
    const std::vector<NativeInteger> &qInvModBi,
    const std::vector<NativeInteger> &qInvModBiPrecon
) {
    // Input: poly in basis {q U Bsk}
    // Output: approximateFloor(t/q*poly) in basis Bsk

    // --------------------- step 3 ---------------------
    // approximate rounding

    size_t numq = qModuli.size();
    size_t numBsk = BskModuli.size();

    uint32_t n = GetLength();

    // Twist xi by t*(q/qi)^-1 mod qi
    NativeInteger *txiqiDivqModqi = new NativeInteger[n*numBsk];

    for (uint32_t i = 0; i < numq; i++) {
        const NativeInteger &currenttqDivqiModqi = tqDivqiModqi[i];
        const NativeInteger &currenttqDivqiModqiPrecon = tqDivqiModqiPrecon[i];

#pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            // multiply by t*(q/qi)^-1 mod qi
            m_vectors[i][k].ModMulPreconOptimizedEq(
                currenttqDivqiModqi,
                qModuli[i],
                currenttqDivqiModqiPrecon);
        }
    }

    for (uint32_t j = 0; j < numBsk; j++) {
#pragma omp parallel for
        for ( uint32_t k = 0; k < n; k++ ) {
            DoubleNativeInteger aq = 0;
            for (uint32_t i = 0; i < numq; i++) {
                const NativeInteger &qDivqiModBjValue = qDivqiModBj[i][j];
                NativeInteger &xi = m_vectors[i][k];
                aq +=
                    Mul128(
                        xi.ConvertToInt(),
                        qDivqiModBjValue.ConvertToInt());
            }
            txiqiDivqModqi[j*n + k] =
                BarrettUint128ModUint64(
                    aq,
                    BskModuli[j].ConvertToInt(),
                    BskModulimu[j]);
        }
    }

    // now we have FastBaseConv( |t*ct|q, q, Bsk ) in txiqiDivqModqi

    for (uint32_t i = 0; i < numBsk; i++) {
        const NativeInteger &currentqInvModBski = qInvModBi[i];
        const NativeInteger &currentqInvModBskiPrecon = qInvModBiPrecon[i];
#pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            // Not worthy to use lazy reduction here
            m_vectors[i+numq][k].ModMulFastEq(t, BskModuli[i]);
            m_vectors[i+numq][k].ModSubEq(txiqiDivqModqi[i*n+k], BskModuli[i]);
            m_vectors[i+numq][k].ModMulPreconOptimizedEq(
                currentqInvModBski,
                BskModuli[i],
                currentqInvModBskiPrecon);
        }
    }
    delete[] txiqiDivqModqi;
    txiqiDivqModqi = nullptr;
}

// Source: Jean-Claude Bajard, Julien Eynard, Anwar Hasan, and Vincent Zucca.
// A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes.
// Cryptology ePrint Archive: Report 2016/510. (https://eprint.iacr.org/2016/510)
// // Almost qeuivalent to "SwitchCRTBasis"
// NOLINT() @brief Converts fast polynomial in CRT basis {q U Bsk} to basis {q} using Shenoy Kumaresan method.
// Outputs the resulting polynomial in CRT/RNS representation in basis q.
// Note that the actual result is basically in basis {Bsk}.
// used in EvalMult of BFVrnsB

template<typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvSK(
    const std::vector<NativeInteger> &qModuli,
    const std::vector<DoubleNativeInteger> &qModulimu,
    const std::vector<NativeInteger> &BskModuli,
    const std::vector<DoubleNativeInteger> &BskModulimu,
    const std::vector<NativeInteger> &BDivBiModBi,
    const std::vector<NativeInteger> &BDivBiModBiPrecon,
    const std::vector<NativeInteger> &BDivBiModmsk,
    const NativeInteger &BInvModmsk,
    const NativeInteger &BInvModmskPrecon,
    const std::vector<std::vector<NativeInteger>> &BDivBiModqj,
    const std::vector<NativeInteger> &BModqi,
    const std::vector<NativeInteger> &BModqiPrecon
) {
    // Input: poly in basis Bsk
    // Output: poly in basis q

    // FastBaseconv(x, B, q)
    size_t numq = qModuli.size();
    size_t numBsk = BskModuli.size();

    uint32_t n = GetLength();

    for (uint32_t i = 0; i < numBsk-1; i++) {  // exclude msk residue
        const NativeInteger &currentBDivBiModBi = BDivBiModBi[i];
        const NativeInteger &currentBDivBiModBiPrecon = BDivBiModBiPrecon[i];
#pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            m_vectors[numq+i][k].ModMulPreconOptimizedEq(
                currentBDivBiModBi,
                BskModuli[i],
                currentBDivBiModBiPrecon);
        }
    }

    for (uint32_t j = 0; j < numq; j++) {
#pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            DoubleNativeInteger result = 0;
            for (uint32_t i = 0; i < numBsk-1; i++) {  // exclude msk residue
                const NativeInteger &currentBDivBiModqj = BDivBiModqj[i][j];
                const NativeInteger &xi = m_vectors[numq+i][k];
                result +=
                    Mul128(
                        xi.ConvertToInt(),
                        currentBDivBiModqj.ConvertToInt());
            }
            m_vectors[j][k] =
                BarrettUint128ModUint64(
                    result,
                    qModuli[j].ConvertToInt(),
                    qModulimu[j]);
        }
    }

    // calculate alphaskx
    // FastBaseConv(x, B, msk)
    NativeInteger *alphaskxVector = new NativeInteger[n];
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
        DoubleNativeInteger result = 0;
        for (uint32_t i = 0; i < numBsk-1; i++) {
            const NativeInteger &currentBDivBiModmsk = BDivBiModmsk[i];
            result +=
                Mul128(
                    m_vectors[numq+i][k].ConvertToInt(),
                    currentBDivBiModmsk.ConvertToInt());
        }
        alphaskxVector[k] =
            BarrettUint128ModUint64(
                result,
                BskModuli[numBsk-1].ConvertToInt(),
                BskModulimu[numBsk-1]);
    }

    // subtract xsk
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
        alphaskxVector[k] = alphaskxVector[k].ModSubFast(
            m_vectors[numq+numBsk-1][k],
            BskModuli[numBsk-1]);
        alphaskxVector[k].ModMulPreconOptimizedEq(
            BInvModmsk,
            BskModuli[numBsk-1],
            BInvModmskPrecon);
    }

    // do (m_vector - alphaskx*M) mod q
    NativeInteger mskDivTwo = BskModuli[numBsk-1]/2;
    for (uint32_t i = 0; i < numq; i++) {
        const NativeInteger &currentBModqi = BModqi[i];
        const NativeInteger &currentBModqiPrecon = BModqiPrecon[i];

#pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            NativeInteger alphaskBModqi = alphaskxVector[k];
            if (alphaskBModqi > mskDivTwo)
                alphaskBModqi =
                    alphaskBModqi.ModSubFast(BskModuli[numBsk-1], qModuli[i]);

            alphaskBModqi.ModMulPreconOptimizedEq(
                currentBModqi,
                qModuli[i],
                currentBModqiPrecon);
            m_vectors[i][k] =
                m_vectors[i][k].ModSubFast(alphaskBModqi, qModuli[i]);
        }
    }

    // drop extra vectors

    // this code died on mac;
    // need to be smarter about use of erase, and bounds...
    //  for (uint32_t i = 0; i < numBsk; i++)
    //      m_vectors.erase (m_vectors.begin() + numq + i);

    // erase vectors from begin() + numq to begin() + numq + numBsk
    // make sure beginning and end are inside the vector :)
    if ( numq < m_vectors.size() ) {
        auto starti = m_vectors.begin() + numq;
        if ( starti + numBsk >= m_vectors.end() )
            m_vectors.erase(starti, m_vectors.end() );
        else
            m_vectors.erase(starti, starti + numBsk);
    }

    delete[] alphaskxVector;
    alphaskxVector = nullptr;
}

// Source: Halevi S., Polyakov Y., and Shoup V.
// An Improved RNS Variant of the BFV Homomorphic Encryption Scheme.
// Cryptology ePrint Archive, Report 2018/117.
// (https://eprint.iacr.org/2018/117)
//
// Computes Round(p/Q*x), where x is in the CRT basis Q*S,
// as [\sum_{i=1}^n alpha_i*x_i + Round(\sum_{i=1}^n beta_i*x_i)]_si,
// with the result in the Q CRT basis;
// used in homomorphic multiplication of BFVrns;
// alpha is a matrix of precomputed integer factors
// = {Floor[p*S*[(Q*S/vi)^{-1}]_{vi}/vi]}_si; for all combinations of vi, si;
// where vi is a prime modulus in Q*S
// beta is a vector of precomputed floating-point factors
// between 0 and 1 = [p*S*(Q*S/vi)^{-1}]_{vi}/vi; - for each vi

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ScaleAndRound(
    const shared_ptr<DCRTPolyImpl::Params> params,
    const std::vector<std::vector<NativeInteger>> &alpha,
    const std::vector<long double> &beta,
    const std::vector<DoubleNativeInteger> &siModulimu
) const {
    DCRTPolyType ans(params, m_format, true);

        usint ringDimension = GetRingDimension();
        size_t size = m_vectors.size();
        size_t newSize = ans.m_vectors.size();
        size_t sizeQ = size - newSize;

#pragma omp parallel for
        for ( usint rIndex = 0; rIndex < ringDimension; rIndex++ ) {
            long double nu = 0.0;

            for ( usint vIndex = 0; vIndex < sizeQ; vIndex++ ) {
                const NativeInteger &xi = m_vectors[vIndex].GetValues()[rIndex];

                nu += beta[vIndex]*xi.ConvertToInt();
            }

            NativeInteger rounded = std::llround(nu);

            for ( usint newvIndex = 0; newvIndex < newSize; newvIndex++ ) {
                DoubleNativeInteger curValue = 0;

                const NativeInteger &si =
                    params->GetParams()[newvIndex]->GetModulus();

                for ( usint vIndex = 0; vIndex < sizeQ; vIndex++ ) {
                    const NativeInteger &xi =
                        m_vectors[vIndex].GetValues()[rIndex];

                    curValue += Mul128(
                        xi.ConvertToInt(),
                        alpha[vIndex][newvIndex].ConvertToInt());
                }

                const NativeInteger &xi =
                    m_vectors[sizeQ + newvIndex].GetValues()[rIndex];

                curValue += Mul128(
                    xi.ConvertToInt(),
                    alpha[sizeQ][newvIndex].ConvertToInt());

                const NativeInteger &curNativeValue = NativeInteger(
                    BarrettUint128ModUint64(
                        curValue,
                        si.ConvertToInt(),
                        siModulimu[newvIndex]));

                ans.m_vectors[newvIndex].at(rIndex) =
                    curNativeValue.ModAddFastOptimized(rounded, si);
            }
        }

        return std::move(ans);
}

/*Switch format calls IlVector2n's switchformat*/
template<typename VecType>
void DCRTPolyImpl<VecType>::SwitchFormat() {
    if (m_format == COEFFICIENT) {
        m_format = EVALUATION;
    } else {
        m_format = COEFFICIENT;
    }

#pragma omp parallel for
    for (usint i = 0; i < m_vectors.size(); i++) {
        m_vectors[i].SwitchFormat();
    }
}

#ifdef OUT
template<typename VecType>
void DCRTPolyImpl<VecType>::SwitchModulus(
    const Integer &modulus,
    const Integer &rootOfUnity
) {
    m_modulus = Integer::ONE;
    for (usint i = 0; i < m_vectors.size(); ++i) {
        auto mod = modulus
            % Integer((*m_params)[i]->GetModulus().ConvertToInt());
        auto root = rootOfUnity
            % Integer((*m_params)[i]->GetModulus().ConvertToInt());
        m_vectors[i].SwitchModulus(mod.ConvertToInt(), root.ConvertToInt());
        m_modulus = m_modulus * mod;
    }
}
#endif

template<typename VecType>
void DCRTPolyImpl<VecType>::SwitchModulusAtIndex(
    usint index,
    const Integer &modulus,
    const Integer &rootOfUnity
) {
    if (index > m_vectors.size()-1) {
        std::string errMsg;
        errMsg = "DCRTPolyImpl is of size = "
            + std::to_string(m_vectors.size())
            + " but SwitchModulus for tower at index "
            + std::to_string(index) + "is called.";
        throw std::runtime_error(errMsg);
    }

    m_vectors[index].SwitchModulus(
        PolyType::Integer(modulus.ConvertToInt()),
        PolyType::Integer(rootOfUnity.ConvertToInt()));
    m_params->RecalculateModulus();
}

template<typename VecType>
bool DCRTPolyImpl<VecType>::InverseExists() const {
    for (usint i = 0; i < m_vectors.size(); i++) {
        if (!m_vectors[i].InverseExists()) return false;
    }
    return true;
}

template<typename VecType>
double DCRTPolyImpl<VecType>::Norm() const {
    PolyLargeType poly(CRTInterpolate());
    return poly.Norm();
}

template<typename VecType>
bool DCRTPolyImpl<VecType>::Serialize(Serialized* serObj) const {
    if ( !serObj->IsObject() ) {
        serObj->SetObject();
    }

    Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
    if (!m_params->Serialize(&obj))
        return false;


    obj.AddMember(
        "Format",
        std::to_string(this->GetFormat()),
        serObj->GetAllocator());

    SerializeVector<PolyType>(
        "Vectors",
        "PolyImpl",
        this->GetAllElements(),
        &obj);

    serObj->AddMember("DCRTPolyImpl", obj, serObj->GetAllocator());

    return true;
}

template<typename VecType>
bool DCRTPolyImpl<VecType>::Deserialize(const Serialized& serObj) {
    SerialItem::ConstMemberIterator it = serObj.FindMember("DCRTPolyImpl");

    if ( it == serObj.MemberEnd() )
        return false;

    SerialItem::ConstMemberIterator pIt = it->value.FindMember("ILDCRTParams");
    if (pIt == it->value.MemberEnd()) return false;

    Serialized parm(rapidjson::kObjectType);
    parm.AddMember(
        SerialItem(
            pIt->name,
            parm.GetAllocator()),
        SerialItem(
            pIt->value,
            parm.GetAllocator()),
        parm.GetAllocator());

    shared_ptr<DCRTPolyImpl::Params> json_ilParams(new DCRTPolyImpl::Params());
    if (!json_ilParams->Deserialize(parm))
        return false;
    m_params = json_ilParams;

    SerialItem::ConstMemberIterator mIt = it->value.FindMember("Format");
    if ( mIt == it->value.MemberEnd() ) return false;
    this->m_format = static_cast<Format>(std::stoi(mIt->value.GetString()));

    mIt = it->value.FindMember("Vectors");

    if ( mIt == it->value.MemberEnd() ) {
        return false;
    }

    bool ret = DeserializeVector<PolyType>(
        "Vectors",
        "PolyImpl",
        mIt,
        &this->m_vectors);

    return ret;
}


template<typename VecType>
std::ostream& operator<<(std::ostream &os, const DCRTPolyImpl<VecType> & p) {
    // TODO(gryan): Standardize this printing so it is like other poly's
    os << "---START PRINT DOUBLE CRT-- WITH SIZE"
        << p.m_vectors.size() << std::endl;
    for (usint i = 0; i < p.m_vectors.size(); i++) {
        os << "VECTOR " << i << std::endl;
        os << p.m_vectors[i];
    }
    os << "---END PRINT DOUBLE CRT--" << std::endl;
    return os;
}

}  // namespace lbcrypto
