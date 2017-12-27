/*
 * @file packedencoding.cpp Represents and defines plaintext encodings in Palisade with bit packing capabilities.
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

#include "packedencoding.h"

namespace lbcrypto {

std::map<ModulusM, NativeInteger> PackedEncoding::m_initRoot;
std::map<ModulusM, NativeInteger> PackedEncoding::m_bigModulus;
std::map<ModulusM, NativeInteger> PackedEncoding::m_bigRoot;

std::map<usint, usint> PackedEncoding::m_automorphismGenerator;
std::map<usint, std::vector<usint>> PackedEncoding::m_toCRTPerm;
std::map<usint, std::vector<usint>> PackedEncoding::m_fromCRTPerm;

bool PackedEncoding::Encode() {
	if( this->isEncoded ) return true;
	auto mod = this->encodingParams->GetPlaintextModulus();

	if( this->typeFlag == IsNativePoly ) {
		NativeVector temp(this->GetElementRingDimension(), this->GetElementModulus().ConvertToInt());

		size_t i;
		for( i=0; i < value.size(); i++ ) {
			uint32_t entry = value[i];

			if( entry >= mod )
				throw std::logic_error("Cannot encode integer " + std::to_string(entry) +
						" at position " + std::to_string(i) +
						" that is > plaintext modulus " + std::to_string(mod) );

			temp[i] = NativeInteger(entry);
		}

		for(; i < this->GetElementRingDimension(); i++ )
			temp[i] = NativeInteger(0);
		this->isEncoded = true;

		this->GetElement<NativePoly>().SetValues(temp, Format::EVALUATION); //output was in coefficient format

		this->Pack(&this->GetElement<NativePoly>(), this->encodingParams->GetPlaintextModulus());//ilVector coefficients are packed and resulting ilVector is in COEFFICIENT form.
	}
	else {
		BigVector temp(this->GetElementRingDimension(), BigInteger(this->GetElementModulus()));

		size_t i;
		for( i=0; i < value.size(); i++ ) {
			uint32_t entry = value[i];

			if( entry >= mod )
				throw std::logic_error("Cannot encode integer " + std::to_string(entry) +
						" at position " + std::to_string(i) +
						" that is > plaintext modulus " + std::to_string(mod) );

			temp[i] = BigInteger(entry);
		}

		for(; i < this->GetElementRingDimension(); i++ )
			temp[i] = BigInteger(0);
		this->isEncoded = true;

		this->GetElement<Poly>().SetValues(temp, Format::EVALUATION); //output was in coefficient format

		this->Pack(&this->GetElement<Poly>(), this->encodingParams->GetPlaintextModulus());//ilVector coefficients are packed and resulting ilVector is in COEFFICIENT form.
	}

	if( this->typeFlag == IsDCRTPoly ) {
		this->encodedVectorDCRT = this->encodedVector;
	}


	return true;
}

template<typename T>
static void fillVec(const T& poly, vector<uint64_t>& vec) {
	vec.clear();
	for (size_t i = 0; i<poly.GetLength(); i++) {
		vec.push_back(poly[i].ConvertToInt());
	}
}

bool PackedEncoding::Decode() {

	auto ptm = this->encodingParams->GetPlaintextModulus();

	if( this->typeFlag == IsNativePoly ) {
		this->Unpack(&this->GetElement<NativePoly>(), ptm);
		fillVec(this->encodedNativeVector, this->value);
	}
	else {
		this->Unpack(&this->GetElement<Poly>(), ptm);
		fillVec(this->encodedVector, this->value);
	}

	return true;
}

void PackedEncoding::Destroy()
{
	m_initRoot.clear();
	m_bigModulus.clear();
	m_bigRoot.clear();

	m_automorphismGenerator.clear();
	m_toCRTPerm.clear();
	m_fromCRTPerm.clear();
}

// FIXME: can these two SetParams methods be collapsed into one??
void PackedEncoding::SetParams(usint m, EncodingParams params)
{
	NativeInteger modulusNI(params->GetPlaintextModulus()); //native int modulus
	std::string exception_message;
	bool hadEx = false;

	//initialize the CRT coefficients if not initialized
#pragma omp critical
	try {
		if (!(m & (m - 1))) { // Check if m is a power of 2
			SetParams_2n(m, params);
		}
		else {
			const ModulusM modulusM = {modulusNI,m};
			// Arbitrary: Bluestein based CRT Arb. So we need the 2mth root of unity
			if (params->GetPlaintextRootOfUnity() == 0) {
				NativeInteger initRoot = RootOfUnity<NativeInteger>(2 * m, modulusNI);
				m_initRoot[modulusM] = initRoot;
				params->SetPlaintextRootOfUnity(m_initRoot[modulusM].ConvertToInt());
			}
			else
				m_initRoot[modulusM] = params->GetPlaintextRootOfUnity();

			// Find a compatible big-modulus and root of unity for CRTArb
			if (params->GetPlaintextBigModulus() == 0) {
				usint nttDim = pow(2, ceil(log2(2 * m - 1)));
				if ((modulusNI.ConvertToInt() - 1) % nttDim == 0) {
					m_bigModulus[modulusM] = modulusNI;
				}
				else {
					usint bigModulusSize = ceil(log2(2 * m - 1)) + 2 * modulusNI.GetMSB() + 1;
					m_bigModulus[modulusM] = FirstPrime<NativeInteger>(bigModulusSize, nttDim);
				}
				m_bigRoot[modulusM] = RootOfUnity<NativeInteger>(nttDim, m_bigModulus[modulusM]);
				params->SetPlaintextBigModulus(m_bigModulus[modulusM]);
				params->SetPlaintextBigRootOfUnity(m_bigRoot[modulusM]);
			}
			else
			{
				m_bigModulus[modulusM] = params->GetPlaintextBigModulus();
				m_bigRoot[modulusM] = params->GetPlaintextBigRootOfUnity();
			}

			// Find a generator for the automorphism group
			if (params->GetPlaintextGenerator() == 0) {
				NativeInteger M(m); // Hackish typecast
				NativeInteger automorphismGenerator = FindGeneratorCyclic<NativeInteger>(M);
				m_automorphismGenerator[m] = automorphismGenerator.ConvertToInt();
				params->SetPlaintextGenerator(m_automorphismGenerator[m]);
			}
			else
				m_automorphismGenerator[m] = params->GetPlaintextGenerator();

			// Create the permutations that interchange the automorphism and crt ordering
			usint phim = GetTotient(m);
			auto tList = GetTotientList(m);
			auto tIdx = std::vector<usint>(m, -1);
			for(usint i=0; i<phim; i++){
				tIdx[tList[i]] = i;
			}

			m_toCRTPerm[m] = std::vector<usint>(phim);
			m_fromCRTPerm[m] = std::vector<usint>(phim);

			usint curr_index = 1;
			for (usint i=0; i<phim; i++){
				m_toCRTPerm[m][tIdx[curr_index]] = i;
				m_fromCRTPerm[m][i] = tIdx[curr_index];

				curr_index = curr_index*m_automorphismGenerator[m] % m;
			}
		}
	}
	catch( std::exception& e ) {
		exception_message = e.what();
		hadEx = true;
	}

	if( hadEx )
		throw std::logic_error(exception_message);

}

void PackedEncoding::SetParams(usint m, const PlaintextModulus &modulus)
{
	NativeInteger modulusNI(modulus); //native int modulus

	std::string exception_message;
	bool hadEx = false;

	//initialize the CRT coefficients if not initialized
#pragma omp critical
	try {
		if (!(m & (m - 1))) { // Check if m is a power of 2
			SetParams_2n(m, modulusNI);
		}
		else {
			const ModulusM modulusM = {modulusNI,m};

			NativeInteger initRoot = RootOfUnity<NativeInteger>(2 * m, modulusNI);

			// Arbitrary: Bluestein based CRT Arb. So we need the 2mth root of unity

			m_initRoot[modulusM] = initRoot;

			// Find a compatible big-modulus and root of unity for CRTArb
			usint nttDim = pow(2, ceil(log2(2 * m - 1)));
			if ((modulusNI.ConvertToInt() - 1) % nttDim == 0) {
				m_bigModulus[modulusM] = modulusNI;
			}
			else {
				usint bigModulusSize = ceil(log2(2 * m - 1)) + 2 * modulusNI.GetMSB() + 1;
				m_bigModulus[modulusM] = FirstPrime<NativeInteger>(bigModulusSize, nttDim);
			}

			auto ri = RootOfUnity<NativeInteger>(nttDim, m_bigModulus[modulusM]);
			m_bigRoot[modulusM] = ri;


			// Find a generator for the automorphism group
			NativeInteger M(m); // Hackish typecast
			NativeInteger automorphismGenerator = FindGeneratorCyclic<NativeInteger>(M);
			m_automorphismGenerator[m] = automorphismGenerator.ConvertToInt();

			// Create the permutations that interchange the automorphism and crt ordering
			usint phim = GetTotient(m);
			auto tList = GetTotientList(m);
			auto tIdx = std::vector<usint>(m, -1);
			for (usint i = 0; i<phim; i++) {
				tIdx[tList[i]] = i;
			}

			m_toCRTPerm[m] = std::vector<usint>(phim);
			m_fromCRTPerm[m] = std::vector<usint>(phim);

			usint curr_index = 1;
			for (usint i = 0; i<phim; i++) {
				m_toCRTPerm[m][tIdx[curr_index]] = i;
				m_fromCRTPerm[m][i] = tIdx[curr_index];

				curr_index = curr_index*m_automorphismGenerator[m] % m;
			}
		}
	}
	catch( std::exception& e ) {
		exception_message = e.what();
		hadEx = true;
	}

	if( hadEx )
		throw std::logic_error(exception_message);
}

template<typename P>
void PackedEncoding::Pack(P *ring, const PlaintextModulus &modulus) const {

	bool dbg_flag = false;

	usint m = ring->GetCyclotomicOrder();//cyclotomic order
	NativeInteger modulusNI(modulus);//native int modulus

	const ModulusM modulusM = {modulusNI,m};

	//Do the precomputation if not initialized
	if (this->m_initRoot[modulusM].GetMSB() == 0) {
		SetParams(m, modulus);
	}

	usint phim = ring->GetRingDimension();

	DEBUG("Pack for order " << m << " phim " << phim << " modulus " << modulusNI);

	//copy values from ring to the vector
	NativeVector slotValues(phim, modulusNI);
	for (usint i = 0; i < phim; i++) {
		slotValues[i] = (*ring)[i].ConvertToInt();
	}

	DEBUG(*ring);
	DEBUG(slotValues);

	// Transform Eval to Coeff
	if (!(m & (m-1))) { // Check if m is a power of 2

		if (m_toCRTPerm[m].size() > 0)
		{
			// Permute to CRT Order
			NativeVector permutedSlots(phim, modulusNI);

			for (usint i = 0; i < phim; i++) {
				permutedSlots[i] = slotValues[m_toCRTPerm[m][i]];
			}
			ChineseRemainderTransformFTT<NativeInteger, NativeVector>::InverseTransform(permutedSlots, m_initRoot[modulusM], m, &slotValues);
		}
		else
		{
			ChineseRemainderTransformFTT<NativeInteger, NativeVector>::InverseTransform(slotValues, m_initRoot[modulusM], m, &slotValues);
		}

	} else { // Arbitrary cyclotomic

		// Permute to CRT Order
		NativeVector permutedSlots(phim, modulusNI);
		for (usint i = 0; i < phim; i++) {
			permutedSlots[i] = slotValues[m_toCRTPerm[m][i]];
		}

		DEBUG("permutedSlots " << permutedSlots);
		DEBUG("m_initRoot[modulusM] " << m_initRoot[modulusM]);
		DEBUG("m_bigModulus[modulusM] " << m_bigModulus[modulusM]);
		DEBUG("m_bigRoot[modulusM] " << m_bigRoot[modulusM]);

		slotValues = ChineseRemainderTransformArb<NativeInteger, NativeVector>::
				InverseTransform(permutedSlots, m_initRoot[modulusM], m_bigModulus[modulusM], m_bigRoot[modulusM], m);
	}

	DEBUG("slotvalues now " << slotValues);
	//copy values into the slotValuesRing
	typename P::Vector slotValuesRing(phim, ring->GetModulus());
	for (usint i = 0; i < phim; i++) {
		slotValuesRing[i] = typename P::Integer(slotValues[i].ConvertToInt());
	}

	ring->SetValues(slotValuesRing, Format::COEFFICIENT);
	DEBUG(*ring);
}

template<typename P>
void PackedEncoding::Unpack(P *ring, const PlaintextModulus &modulus) const {

	bool dbg_flag = false;

	usint m = ring->GetCyclotomicOrder(); // cyclotomic order
	NativeInteger modulusNI(modulus); //native int modulus

	const ModulusM modulusM = {modulusNI,m};

	//Do the precomputation if not initialized
	if (this->m_initRoot[modulusM].GetMSB() == 0) {
		SetParams(m, modulus);
	}

	usint phim = ring->GetRingDimension(); //ring dimension

	DEBUG("Unpack for order " << m << " phim " << phim << " modulus " << modulusNI);

	//copy aggregate plaintext values
	NativeVector packedVector(phim, modulusNI);
	for (usint i = 0; i < phim; i++) {
		packedVector[i] = NativeInteger((*ring)[i].ConvertToInt());
	}

	DEBUG(packedVector);

	// Transform Coeff to Eval
	NativeVector permutedSlots(phim, modulusNI);
	if (!(m & (m-1))) { // Check if m is a power of 2
		ChineseRemainderTransformFTT<NativeInteger, NativeVector>::ForwardTransform(packedVector, m_initRoot[modulusM], m, &permutedSlots);
	} else { // Arbitrary cyclotomic
		permutedSlots = ChineseRemainderTransformArb<NativeInteger, NativeVector>::
				ForwardTransform(packedVector, m_initRoot[modulusM], m_bigModulus[modulusM], m_bigRoot[modulusM], m);
	}

	if (m_fromCRTPerm[m].size() > 0) {
		// Permute to automorphism Order
		for (usint i = 0; i < phim; i++) {
			packedVector[i] = permutedSlots[m_fromCRTPerm[m][i]];
		}
	}
	else
		packedVector = permutedSlots;

	DEBUG(packedVector);

	//copy values into the slotValuesRing
	typename P::Vector packedVectorRing(phim, ring->GetModulus());
	for (usint i = 0; i < phim; i++) {
		packedVectorRing[i] = typename P::Integer(packedVector[i].ConvertToInt());
	}

	ring->SetValues(packedVectorRing, Format::COEFFICIENT);
}

void PackedEncoding::SetParams_2n(usint m, const NativeInteger &modulusNI) {

	const ModulusM modulusM = {modulusNI,m};

	// Power of two: m/2-point FTT. So we need the mth root of unity
	m_initRoot[modulusM] = RootOfUnity<NativeInteger>(m, modulusNI);

	// Create the permutations that interchange the automorphism and crt ordering
	// First we create the cyclic group generated by 5 and then adjoin the co-factor by multiplying by 3

	usint phim = (m >> 1);
	usint phim_by_2 = (m >> 2);

	m_toCRTPerm[m] = std::vector<usint>(phim);
	m_fromCRTPerm[m] = std::vector<usint>(phim);

	usint curr_index = 1;
	for (usint i = 0; i < phim_by_2; i++) {
		m_toCRTPerm[m][(curr_index - 1) / 2] = i;
		m_fromCRTPerm[m][i] = (curr_index - 1) / 2;

		usint cofactor_index = curr_index * 3 % m;
		m_toCRTPerm[m][(cofactor_index - 1) / 2] = i + phim_by_2;
		m_fromCRTPerm[m][i + phim_by_2] = (cofactor_index - 1) / 2;

		curr_index = curr_index * 5 % m;

	}

}

void PackedEncoding::SetParams_2n(usint m, EncodingParams params){

		NativeInteger modulusNI(params->GetPlaintextModulus()); //native int modulus

		const ModulusM modulusM = {modulusNI,m};

		// Power of two: m/2-point FTT. So we need the mth root of unity
		if (params->GetPlaintextRootOfUnity() == 0)
		{
			m_initRoot[modulusM] = RootOfUnity<NativeInteger>(m, modulusNI);
			params->SetPlaintextRootOfUnity(m_initRoot[modulusM]);
		}
		else
			m_initRoot[modulusM] = params->GetPlaintextRootOfUnity();

		// Create the permutations that interchange the automorphism and crt ordering
		// First we create the cyclic group generated by 5 and then adjoin the co-factor by multiplying by 3

		usint phim = (m >> 1);
		usint phim_by_2 = (m >> 2);

		m_toCRTPerm[m] = std::vector<usint>(phim);
		m_fromCRTPerm[m] = std::vector<usint>(phim);

		usint curr_index = 1;
		for (usint i = 0; i < phim_by_2; i++) {
			m_toCRTPerm[m][(curr_index - 1) / 2] = i;
			m_fromCRTPerm[m][i] = (curr_index - 1) / 2;

			usint cofactor_index = curr_index * 3 % m;
			m_toCRTPerm[m][(cofactor_index - 1) / 2] = i + phim_by_2;
			m_fromCRTPerm[m][i + phim_by_2] = (cofactor_index - 1) / 2;

			curr_index = curr_index * 5 % m;

		}

	}

}
