/*
 * @file packedintplaintextencoding.cpp Represents and defines plaintext encodings in Palisade with bit packing capabilities.
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

 //#include "../crypto/cryptocontext.h"
#include "packedintplaintextencoding.h"

namespace lbcrypto {

	std::map<native_int::BigInteger, native_int::BigInteger> PackedIntPlaintextEncoding::m_initRoot;
	std::map<native_int::BigInteger, native_int::BigInteger> PackedIntPlaintextEncoding::m_bigModulus;
	std::map<native_int::BigInteger, native_int::BigInteger> PackedIntPlaintextEncoding::m_bigRoot;

	std::map<native_int::BigInteger, usint> PackedIntPlaintextEncoding::m_automorphismGenerator;
	std::map<native_int::BigInteger, std::vector<usint>> PackedIntPlaintextEncoding::m_toCRTPerm;
	std::map<native_int::BigInteger, std::vector<usint>> PackedIntPlaintextEncoding::m_fromCRTPerm;

	void PackedIntPlaintextEncoding::Encode(const BigInteger &modulus, Poly *ilVector, size_t startFrom, size_t length) const
	{
		size_t padlen = 0;
		uint64_t mod = modulus.ConvertToInt();

		if (length == 0) length = this->size();

		// length is usually chunk size; if start + length would go past the end of the item, add padding
		if ((startFrom + length) > this->size()) {
			padlen = (startFrom + length) - this->size();
			length = length - padlen;
		}

		BigVector temp(ilVector->GetRingDimension(), ilVector->GetModulus());

		for (size_t i = 0; i < length; i++) {
			uint32_t entry = this->at(i + startFrom);
			if (entry >= mod)
				throw std::logic_error("Cannot encode integer at position " + std::to_string(i) + " because it is >= plaintext modulus " + std::to_string(mod));
			BigInteger Val = BigInteger(entry);
			temp.SetValAtIndex(i, Val);
		}

		//BigInteger Num = modulus - BigInteger::ONE;
		for (size_t i = 0; i<padlen; i++) {
			temp.SetValAtIndex(i + length, BigInteger(0));
		}

		ilVector->SetValues(temp, Format::EVALUATION); //output was in coefficient format

		this->Pack(ilVector, modulus);//ilVector coefficients are packed and resulting ilVector is in COEFFICIENT form.

	}

	void PackedIntPlaintextEncoding::Decode(const BigInteger &modulus, Poly *ilVector) {

		this->Unpack(ilVector, modulus); //Format is in COEFFICIENT

		for (usint i = 0; i<ilVector->GetValues().GetLength(); i++) {
			this->push_back(ilVector->GetValues().GetValAtIndex(i).ConvertToInt());
		}

	}


	size_t PackedIntPlaintextEncoding::GetChunksize(const usint ring, const BigInteger& ptm) const
	{
		return ring;
	}

	void PackedIntPlaintextEncoding::Destroy()
	{
		m_initRoot.clear();
		m_bigModulus.clear();
		m_bigRoot.clear();

		m_automorphismGenerator.clear();
		m_toCRTPerm.clear();
		m_fromCRTPerm.clear();
	}

	void PackedIntPlaintextEncoding::SetParams(usint m, shared_ptr<EncodingParams> params)
	{
		native_int::BigInteger modulusNI(params->GetPlaintextModulus().ConvertToInt()); //native int modulus

		//initialize the CRT coefficients if not initialized
#pragma omp critical
{
		if (!(m & (m-1))){ // Check if m is a power of 2
			// Power of two: m/2-point FTT. So we need the mth root of unity
			if (params->GetPlaintextRootOfUnity() == 0)
			{
				m_initRoot[modulusNI] = RootOfUnity<native_int::BigInteger>(m, modulusNI);
				params->SetPlaintextRootOfUnity(m_initRoot[modulusNI].ConvertToInt());
			}
			else
				m_initRoot[modulusNI] = params->GetPlaintextRootOfUnity().ConvertToInt();
		} else {
			// Arbitrary: Bluestein based CRT Arb. So we need the 2mth root of unity

			if (params->GetPlaintextRootOfUnity() == 0) {
				native_int::BigInteger initRoot = RootOfUnity<native_int::BigInteger>(2 * m, modulusNI);
				m_initRoot[modulusNI] = initRoot;
				params->SetPlaintextRootOfUnity(m_initRoot[modulusNI].ConvertToInt());
			}
			else
				m_initRoot[modulusNI] = params->GetPlaintextRootOfUnity().ConvertToInt();

			// Find a compatible big-modulus and root of unity for CRTArb
			if (params->GetPlaintextBigModulus() == 0) {
				usint nttDim = pow(2, ceil(log2(2 * m - 1)));
				if ((modulusNI.ConvertToInt() - 1) % nttDim == 0) {
					m_bigModulus[modulusNI] = modulusNI;
				}
				else {
					usint bigModulusSize = ceil(log2(2 * m - 1)) + 2 * modulusNI.GetMSB() + 1;
					m_bigModulus[modulusNI] = FirstPrime<native_int::BigInteger>(bigModulusSize, nttDim);
				}
				m_bigRoot[modulusNI] = RootOfUnity<native_int::BigInteger>(nttDim, m_bigModulus[modulusNI]);
				params->SetPlaintextBigModulus(m_bigModulus[modulusNI].ConvertToInt());
				params->SetPlaintextBigRootOfUnity(m_bigRoot[modulusNI].ConvertToInt());
			}
			else
			{
				m_bigModulus[modulusNI] = params->GetPlaintextBigModulus().ConvertToInt();
				m_bigRoot[modulusNI] = params->GetPlaintextBigRootOfUnity().ConvertToInt();
			}

			// Find a generator for the automorphism group
			if (params->GetPlaintextGenerator() == 0) {
				native_int::BigInteger M(m); // Hackish typecast
				native_int::BigInteger automorphismGenerator = FindGeneratorCyclic<native_int::BigInteger>(M);
				m_automorphismGenerator[modulusNI] = automorphismGenerator.ConvertToInt();
				params->SetPlaintextGenerator(m_automorphismGenerator[modulusNI]);
			}
			else
				m_automorphismGenerator[modulusNI] = params->GetPlaintextGenerator();

			// Create the permutations that interchange the automorphism and crt ordering
			usint phim = GetTotient(m);
			auto tList = GetTotientList(m);
			auto tIdx = std::vector<usint>(m, -1);
			for(usint i=0; i<phim; i++){
				tIdx[tList[i]] = i;
			}

			m_toCRTPerm[modulusNI] = std::vector<usint>(phim);
			m_fromCRTPerm[modulusNI] = std::vector<usint>(phim);

			usint curr_index = 1;
			for (usint i=0; i<phim; i++){
				m_toCRTPerm[modulusNI][tIdx[curr_index]] = i;
				m_fromCRTPerm[modulusNI][i] = tIdx[curr_index];

				curr_index = curr_index*m_automorphismGenerator[modulusNI] % m;
			}
		}
	}

	}

	void PackedIntPlaintextEncoding::SetParams(const BigInteger &modulus, usint m)
	{
		native_int::BigInteger modulusNI(modulus.ConvertToInt()); //native int modulus

																						//initialize the CRT coefficients if not initialized
#pragma omp critical
		{
			if (!(m & (m - 1))) { // Check if m is a power of 2
								  // Power of two: m/2-point FTT. So we need the mth root of unity
					m_initRoot[modulusNI] = RootOfUnity<native_int::BigInteger>(m, modulusNI);
			}
			else {
				// Arbitrary: Bluestein based CRT Arb. So we need the 2mth root of unity

				native_int::BigInteger initRoot = RootOfUnity<native_int::BigInteger>(2 * m, modulusNI);
				m_initRoot[modulusNI] = initRoot;

				// Find a compatible big-modulus and root of unity for CRTArb
				usint nttDim = pow(2, ceil(log2(2 * m - 1)));
				if ((modulusNI.ConvertToInt() - 1) % nttDim == 0) {
					m_bigModulus[modulusNI] = modulusNI;
				}
				else {
					usint bigModulusSize = ceil(log2(2 * m - 1)) + 2 * modulusNI.GetMSB() + 1;
					m_bigModulus[modulusNI] = FirstPrime<native_int::BigInteger>(bigModulusSize, nttDim);
				}
				m_bigRoot[modulusNI] = RootOfUnity<native_int::BigInteger>(nttDim, m_bigModulus[modulusNI]);


				// Find a generator for the automorphism group
				native_int::BigInteger M(m); // Hackish typecast
				native_int::BigInteger automorphismGenerator = FindGeneratorCyclic<native_int::BigInteger>(M);
				m_automorphismGenerator[modulusNI] = automorphismGenerator.ConvertToInt();

				// Create the permutations that interchange the automorphism and crt ordering
				usint phim = GetTotient(m);
				auto tList = GetTotientList(m);
				auto tIdx = std::vector<usint>(m, -1);
				for (usint i = 0; i<phim; i++) {
					tIdx[tList[i]] = i;
				}

				m_toCRTPerm[modulusNI] = std::vector<usint>(phim);
				m_fromCRTPerm[modulusNI] = std::vector<usint>(phim);

				usint curr_index = 1;
				for (usint i = 0; i<phim; i++) {
					m_toCRTPerm[modulusNI][tIdx[curr_index]] = i;
					m_fromCRTPerm[modulusNI][i] = tIdx[curr_index];

					curr_index = curr_index*m_automorphismGenerator[modulusNI] % m;
				}
			}
		}

	}


	void PackedIntPlaintextEncoding::Pack(Poly *ring, const BigInteger &modulus) const {
		usint m = ring->GetCyclotomicOrder();//cyclotomic order
		native_int::BigInteger modulusNI(modulus.ConvertToInt());//native int modulus

		//Do the precomputation if not initialized
		if (this->m_initRoot[modulusNI].GetMSB() == 0) {
			SetParams(modulus, m);
		}

		usint phim = ring->GetRingDimension();

		//copy values from ring to the vector
		native_int::BigVector slotValues(phim, modulusNI);
		for (usint i = 0; i < phim; i++) {
			slotValues.SetValAtIndex(i, ring->GetValAtIndex(i).ConvertToInt());
		}

		//std::cout << packedVector << std::endl;

		if (!(m & (m-1))) { // Check if m is a power of 2
			//power of 2 cyclotomics can use inverse CRT as packing function.
			slotValues = ChineseRemainderTransformFTT<native_int::BigInteger, native_int::BigVector>::GetInstance().InverseTransform(slotValues, m_initRoot[modulusNI], m);
		} else {
			// Arbitrary cyclotomic use CRTArb
			// Permute to CRT Order
			native_int::BigVector permutedSlots(phim, modulusNI);
			for (usint i = 0; i < phim; i++) {
				permutedSlots.SetValAtIndex(i, slotValues.GetValAtIndex(m_toCRTPerm[modulusNI][i]));
			}

			// Transform eval-representation to coeff
			slotValues = ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().
					InverseTransform(permutedSlots, m_initRoot[modulusNI], m_bigModulus[modulusNI], m_bigRoot[modulusNI], m);
		}

		//copy values into the slotValuesRing
		BigVector slotValuesRing(phim, ring->GetModulus());
		for (usint i = 0; i < phim; i++) {
			slotValuesRing.SetValAtIndex(i, BigInteger(slotValues.GetValAtIndex(i).ConvertToInt()));
		}

		ring->SetValues(slotValuesRing, Format::COEFFICIENT);

		//ring->PrintValues();

	}

	void PackedIntPlaintextEncoding::Unpack(Poly *ring, const BigInteger &modulus) const {

		usint m = ring->GetCyclotomicOrder(); // cyclotomic order
		native_int::BigInteger modulusNI(modulus.ConvertToInt()); //native int modulus

		//Do the precomputation if not initialized
		if (this->m_initRoot[modulusNI].GetMSB() == 0) {
			SetParams(modulus, m);
		}

		usint phim = ring->GetRingDimension(); //ring dimension

		//copy aggregate plaintext values
		native_int::BigVector packedVector(phim, modulusNI);
		for (usint i = 0; i < phim; i++) {
			packedVector.SetValAtIndex(i, native_int::BigInteger(ring->GetValAtIndex(i).ConvertToInt()));
		}

		if (!(m & (m-1))) { // Check if m is a power of 2
			//power of 2 cyclotomics can use forward CRT for getting slot values
			packedVector = ChineseRemainderTransformFTT<native_int::BigInteger, native_int::BigVector>::GetInstance().ForwardTransform(packedVector, m_initRoot[modulusNI], m);
		} else {
			// Arbitrary cyclotomic use CRTArb
			// Transform coeff to eval representation
			native_int::BigVector permutedSlots(phim, modulusNI);
			permutedSlots = ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>::GetInstance().
					ForwardTransform(packedVector, m_initRoot[modulusNI], m_bigModulus[modulusNI], m_bigRoot[modulusNI], m);

			// Permute to automorphism Order
			for (usint i = 0; i < phim; i++) {
				packedVector.SetValAtIndex(i, permutedSlots.GetValAtIndex(m_fromCRTPerm[modulusNI][i]));
			}
		}

		BigVector packedVectorRing(phim, ring->GetModulus());

		for (usint i = 0; i < phim; i++) {
			packedVectorRing.SetValAtIndex(i, BigInteger(packedVector.GetValAtIndex(i).ConvertToInt()));
		}

		ring->SetValues(packedVectorRing, Format::COEFFICIENT);

	}

}
