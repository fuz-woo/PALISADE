/*
 * @file transfrm.cpp This file contains the linear transform interface functionality.
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

#include "transfrm.h"

namespace lbcrypto {


template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityInverseTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType,NativeVector> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityPreconTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType,NativeVector> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityInversePreconTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformArb<IntType, VecType>::m_cyclotomicPolyMap;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformArb<IntType, VecType>::m_cyclotomicPolyReverseNTTMap;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformArb<IntType, VecType>::m_cyclotomicPolyNTTMap;

template<typename IntType, typename VecType>
std::map<ModulusRoot<IntType>, VecType> BluesteinFFT<IntType, VecType>::m_rootOfUnityTableByModulusRoot;

template<typename IntType, typename VecType>
std::map<ModulusRoot<IntType>, VecType> BluesteinFFT<IntType, VecType>::m_rootOfUnityInverseTableByModulusRoot;

template<typename IntType, typename VecType>
std::map<ModulusRoot<IntType>, VecType> BluesteinFFT<IntType, VecType>::m_powersTableByModulusRoot;

template<typename IntType, typename VecType>
std::map<ModulusRootPair<IntType>, VecType> BluesteinFFT<IntType, VecType>::m_RBTableByModulusRootPair;

template<typename IntType, typename VecType>
std::map<IntType, ModulusRoot<IntType>> BluesteinFFT<IntType, VecType>::m_defaultNTTModulusRoot;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformArb<IntType, VecType>::m_rootOfUnityDivisionTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformArb<IntType, VecType>::m_rootOfUnityDivisionInverseTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, IntType> ChineseRemainderTransformArb<IntType, VecType>::m_DivisionNTTModulus;

template<typename IntType, typename VecType>
std::map<IntType, IntType> ChineseRemainderTransformArb<IntType, VecType>::m_DivisionNTTRootOfUnity;

template<typename IntType, typename VecType>
std::map<usint, usint> ChineseRemainderTransformArb<IntType, VecType>::m_nttDivisionDim;

std::complex<double>* DiscreteFourierTransform::rootOfUnityTable = 0;

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
template<typename IntType, typename VecType>
void NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable, const usint cycloOrder, VecType *ans) {

	ans->SetModulus(element.GetModulus());

	NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(element, rootOfUnityInverseTable, cycloOrder, ans);

	//TODO:: note this could be stored
	*ans *= (IntType(cycloOrder).ModInverse(element.GetModulus()));
	return;
}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
template<typename IntType, typename VecType>
void NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable,
		const NativeVector& preconRootOfUnityInverseTable, const usint cycloOrder, VecType *ans) {

	if (typeid(IntType) == typeid(NativeInteger))
	{

		ans->SetModulus(element.GetModulus());

		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(element, rootOfUnityInverseTable,
				preconRootOfUnityInverseTable, cycloOrder, ans);

		//TODO:: note this could be stored
		*ans *= (IntType(cycloOrder).ModInverse(element.GetModulus()));
	}
	else
		PALISADE_THROW(math_error, "This NTT method only works with NativeInteger");

	return;
}

//main Forward CRT Transform - implements FTT - uses iterative NTT as a subroutine
//includes precomputation of twidle factor table
template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::ForwardTransform(const VecType& element, const IntType& rootOfUnity,
		const usint CycloOrder, VecType *OpFFT) {

	if( OpFFT->GetLength() != CycloOrder/2 )
		throw std::logic_error("Vector for ChineseRemainderTransformFTT::ForwardTransform size must be == CyclotomicOrder/2");

	if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0)) {
		// No transform, just copy in to out

		*OpFFT = element;
		return;

		//throw std::logic_error("Root of unity for ChineseRemainderTransformFTT::ForwardTransform cannot be zero or one");
	}

	if (!IsPowerOfTwo(CycloOrder))
		throw std::logic_error("CyclotomicOrder for ChineseRemainderTransformFTT::ForwardTransform is not a power of two");

	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(element.GetModulus());

	const VecType *rootOfUnityTable = NULL;

	// check to see if the modulus is in the table, and add it if it isn't
	const auto mapSearch = m_rootOfUnityTableByModulus.find(element.GetModulus());
	if( mapSearch == m_rootOfUnityTableByModulus.end() || mapSearch->second[1] != rootOfUnity ) {
#pragma omp critical
		{
			IntType modulus(element.GetModulus());
			VecType rTable(CycloOrder / 2,modulus);
			IntType x(1);

			for (usint i = 0; i<CycloOrder / 2; i++) {
 			    rTable[i]= x;
			    x.ModBarrettMulInPlace(rootOfUnity, modulus, mu);
			}
			rootOfUnityTable = &(m_rootOfUnityTableByModulus[modulus] = std::move(rTable));

			if (typeid(IntType) == typeid(NativeInteger)) {
				NativeInteger nativeModulus = modulus.ConvertToInt();
				NativeVector preconTable(CycloOrder/2,nativeModulus);
				if(nativeModulus.GetMSB() < NTL_SP_NBITS + 1)
				{
					for (usint i = 0; i<CycloOrder / 2; i++) {
						preconTable[i] = NativeInteger(rootOfUnityTable->operator[](i).ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
					}
				}
				else{
					for (usint i = 0; i<CycloOrder / 2; i++) {
						preconTable[i] = 0;
					}
				}
				m_rootOfUnityPreconTableByModulus[modulus] = std::move(preconTable);
			}
		}
	}
	else {
		rootOfUnityTable = &mapSearch->second;
	}

	VecType InputToFFT(element.GetLength(),element.GetModulus());

	usint ringDimensionFactor = rootOfUnityTable->GetLength() / (CycloOrder / 2);

	//Fermat Theoretic Transform (FTT)
	if (typeid(IntType) == typeid(NativeInteger)) {
		const NativeVector &preconTable = m_rootOfUnityPreconTableByModulus[element.GetModulus()];
		NativeInteger modulus = element.GetModulus().ConvertToInt();
		if(element.GetModulus().GetMSB() < NTL_SP_NBITS + 1){
			if (ringDimensionFactor == 1)
					for (usint i = 0; i<CycloOrder / 2; i++)
							InputToFFT[i]=element[i].ModMulPreconOptimized((*rootOfUnityTable)[i],modulus,preconTable[i]);
					else
						for (usint i = 0; i<CycloOrder / 2; i++)
							InputToFFT[i]=element[i].ModMulPreconOptimized((*rootOfUnityTable)[i*ringDimensionFactor],modulus,preconTable[i*ringDimensionFactor]);
		}
		else{
			if (ringDimensionFactor == 1)
								for (usint i = 0; i<CycloOrder / 2; i++)
										InputToFFT[i]=element[i].ModMulFast((*rootOfUnityTable)[i],modulus);
								else
									for (usint i = 0; i<CycloOrder / 2; i++)
										InputToFFT[i]=element[i].ModMulFast((*rootOfUnityTable)[i*ringDimensionFactor],modulus);

		}

	} else {
		for (usint i = 0; i<CycloOrder / 2; i++)
			InputToFFT[i]= element[i].ModBarrettMul((*rootOfUnityTable)[i*ringDimensionFactor], element.GetModulus(), mu);
	}

	if (typeid(IntType) == typeid(NativeInteger))
		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(InputToFFT, *rootOfUnityTable,
				m_rootOfUnityPreconTableByModulus[element.GetModulus()], CycloOrder / 2, OpFFT);
	else
		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(InputToFFT, *rootOfUnityTable, CycloOrder / 2, OpFFT);

	return;
}

//main Inverse CRT Transform - implements FTT - uses iterative NTT as a subroutine
//includes precomputation of inverse twidle factor table
template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder, VecType *OpIFFT) {

	if( OpIFFT->GetLength() != CycloOrder/2 )
		throw std::logic_error("Vector for ChineseRemainderTransformFTT::InverseTransform size must be == CyclotomicOrder/2");

	if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0)) {
		// just copy, no transform

		*OpIFFT = element;
		return;

		//throw std::logic_error("Root of unity for ChineseRemainderTransformFTT::InverseTransform cannot be zero or one");
	}

	if (!IsPowerOfTwo(CycloOrder))
		throw std::logic_error("CyclotomicOrder for ChineseRemainderTransformFTT::InverseTransform is not a power of two");


	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(element.GetModulus());

	const VecType *rootOfUnityITable = NULL;

	IntType rootofUnityInverse;

	auto mSearch = m_rootOfUnityInverseTableByModulus.find(element.GetModulus());

	try {
		rootofUnityInverse = rootOfUnity.ModInverse(element.GetModulus());
	}
	catch (std::exception& e) {
		throw std::logic_error(std::string(e.what()) + ": rootOfUnity " + rootOfUnity.ToString() + " has no inverse");
	}

	// check to see if the modulus is in the table
	if( mSearch == m_rootOfUnityInverseTableByModulus.end() || mSearch->second.GetLength() == 0 || mSearch->second[1] != rootofUnityInverse ) {
#pragma omp critical
			{

				VecType TableI(CycloOrder / 2);

				IntType x(1);

				for (usint i = 0; i<CycloOrder / 2; i++) {
					TableI[i]= x;
					x.ModBarrettMulInPlace(rootofUnityInverse, element.GetModulus(), mu);
				}

				rootOfUnityITable = &(m_rootOfUnityInverseTableByModulus[element.GetModulus()] = std::move(TableI));

				if (typeid(IntType) == typeid(NativeInteger)) {
					NativeInteger nativeModulus = element.GetModulus().ConvertToInt();
					NativeVector preconTableI(CycloOrder / 2, nativeModulus);
					if(element.GetModulus().GetMSB() < NTL_SP_NBITS+1){
						for (usint i = 0; i<CycloOrder / 2; i++) {
											preconTableI[i] = NativeInteger(rootOfUnityITable->operator[](i).ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
										}
					}
					else{

						for (usint i = 0; i<CycloOrder / 2; i++) {
											preconTableI[i] = 0;
										}

					}

					m_rootOfUnityInversePreconTableByModulus[element.GetModulus()] = std::move(preconTableI);
				}
			}
		}

	else {
		rootOfUnityITable = &mSearch->second;
	}

	if (typeid(IntType) == typeid(NativeInteger))
		NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(element, *rootOfUnityITable,
				m_rootOfUnityInversePreconTableByModulus[element.GetModulus()], CycloOrder / 2, OpIFFT);
	else
		NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(element, *rootOfUnityITable, CycloOrder / 2, OpIFFT);

	usint ringDimensionFactor = rootOfUnityITable->GetLength() / (CycloOrder / 2);

	if (typeid(IntType) == typeid(NativeInteger)) {
		const NativeVector &preconTable = m_rootOfUnityInversePreconTableByModulus[element.GetModulus()];
		NativeInteger nativeModulus = element.GetModulus().ConvertToInt();
		if(element.GetModulus().GetMSB() < NTL_SP_NBITS + 1){
			if (ringDimensionFactor == 1)
						for (usint i = 0; i<CycloOrder / 2; i++)
							(*OpIFFT)[i].ModMulPreconOptimizedEq((*rootOfUnityITable)[i],nativeModulus,preconTable[i]);
					else
						for (usint i = 0; i<CycloOrder / 2; i++)
							(*OpIFFT)[i].ModMulPreconOptimizedEq((*rootOfUnityITable)[i*ringDimensionFactor],nativeModulus,preconTable[i*ringDimensionFactor]);
		}
		else{
			if (ringDimensionFactor == 1)
						for (usint i = 0; i<CycloOrder / 2; i++)
							(*OpIFFT)[i].ModMulEq((*rootOfUnityITable)[i],nativeModulus);
					else
						for (usint i = 0; i<CycloOrder / 2; i++)
							(*OpIFFT)[i].ModMulEq((*rootOfUnityITable)[i*ringDimensionFactor],nativeModulus);
		}

	}
	else {
		for (usint i = 0; i<CycloOrder / 2; i++)
			(*OpIFFT)[i].ModBarrettMulInPlace((*rootOfUnityITable)[i*ringDimensionFactor], element.GetModulus(), mu);
	}
	return;
}

template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::PreCompute(const IntType& rootOfUnity, const usint CycloOrder, const IntType &modulus) {

	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(modulus);

	IntType x(1);


	VecType *rootOfUnityTableCheck = NULL;

	rootOfUnityTableCheck = &m_rootOfUnityTableByModulus[modulus];
	//Precomputes twiddle factor omega and FTT parameter phi for Forward Transform
	if (rootOfUnityTableCheck->GetLength() == 0) {
#pragma omp critical
{
		VecType Table(CycloOrder / 2, modulus);

		for (usint i = 0; i<CycloOrder / 2; i++) {
			Table[i]= x;
			x.ModBarrettMulInPlace(rootOfUnity, modulus, mu);
		}
		m_rootOfUnityTableByModulus[modulus] = std::move(Table);

		if (typeid(IntType) == typeid(NativeInteger)) {
			NativeInteger nativeModulus = modulus.ConvertToInt();
			NativeVector preconTable(CycloOrder/2,nativeModulus);
			if(modulus.GetMSB()<NTL_SP_NBITS+1){
				for (usint i = 0; i<CycloOrder / 2; i++) {
						preconTable[i] = NativeInteger(m_rootOfUnityTableByModulus[modulus].operator[](i).ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
					}
			}
			else{
				for (usint i = 0; i<CycloOrder / 2; i++) {
						preconTable[i] = 0;
					}
			}

			m_rootOfUnityPreconTableByModulus[modulus] = std::move(preconTable);
		}
}

	}

	//Precomputes twiddle factor omega and FTT parameter phi for Inverse Transform
	VecType  *rootOfUnityInverseTableCheck = &m_rootOfUnityInverseTableByModulus[modulus];
	if (rootOfUnityInverseTableCheck->GetLength() == 0) {
#pragma omp critical
{
		VecType TableI(CycloOrder / 2, modulus);
		IntType rootOfUnityInverse = rootOfUnity.ModInverse(modulus);

		x = 1;

		for (usint i = 0; i<CycloOrder / 2; i++) {
			TableI[i]= x;
			x.ModBarrettMulInPlace(rootOfUnityInverse, modulus, mu);
		}
		m_rootOfUnityInverseTableByModulus[modulus] = std::move(TableI);

		if (typeid(IntType) == typeid(NativeInteger)) {
			NativeInteger nativeModulus = modulus.ConvertToInt();
			NativeVector preconTableI(CycloOrder/2,nativeModulus);
			if(modulus.GetMSB()<NTL_SP_NBITS+1){
				for (usint i = 0; i<CycloOrder / 2; i++) {
								preconTableI[i] = NativeInteger(m_rootOfUnityInverseTableByModulus[modulus].operator[](i).ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
						}
			}
			else{
				for (usint i = 0; i<CycloOrder / 2; i++) {
								preconTableI[i] = 0;
				}
			}

			m_rootOfUnityInversePreconTableByModulus[modulus] = std::move(preconTableI);
		}
}

	}

}

template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::PreCompute(std::vector<IntType> &rootOfUnity, const usint CycloOrder, std::vector<IntType> &moduliiChain) {

	usint numOfRootU = rootOfUnity.size();
	usint numModulii = moduliiChain.size();

	if (numOfRootU != numModulii) {
		throw std::logic_error("size of root of unity and size of moduli chain not of same size");
	}

#pragma omp critical
	for (usint i = 0; i<numOfRootU; ++i) {

		IntType currentRoot(rootOfUnity[i]);
		IntType currentMod(moduliiChain[i]);

		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(currentMod);

		if (m_rootOfUnityTableByModulus[moduliiChain[i]].GetLength() != 0)
			continue;

		IntType x(1);

		//computation of root of unity table
		VecType rTable(CycloOrder / 2, currentMod);

		for (usint i = 0; i<CycloOrder / 2; i++) {
		  rTable[i]= x;
		  x.ModBarrettMulInPlace(currentRoot, currentMod, mu);
		}
		m_rootOfUnityTableByModulus[currentMod] = std::move(rTable);

		if (typeid(x) == typeid(NativeInteger)) {
			NativeInteger nativeModulus = currentMod.ConvertToInt();
			NativeVector preconTable(CycloOrder/2,nativeModulus);
			if(currentMod.GetMSB()<NTL_SP_NBITS+1){
				for (usint i = 0; i<CycloOrder / 2; i++) {
						  preconTable[i] = NativeInteger(m_rootOfUnityTableByModulus[currentMod].operator[](i).ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
						}
			}
			else{
				for (usint i = 0; i<CycloOrder / 2; i++) {
						  preconTable[i] = 0;
						}
			}

			m_rootOfUnityPreconTableByModulus[currentMod] = std::move(preconTable);
		}

		//computation of root of unity inverse table
		x = 1;

		IntType rootOfUnityInverse = currentRoot.ModInverse(currentMod);

		VecType rTableI(CycloOrder / 2,currentMod);

		for (usint i = 0; i<CycloOrder / 2; i++) {
			rTableI[i]= x;
			x.ModBarrettMulInPlace(rootOfUnityInverse, currentMod, mu);
		}
		m_rootOfUnityInverseTableByModulus[currentMod] = std::move(rTableI);

		if (typeid(x) == typeid(NativeInteger)) {
			NativeInteger nativeModulus = currentMod.ConvertToInt();
			NativeVector preconTableI(CycloOrder/2,nativeModulus);
			if(currentMod.GetMSB()<NTL_SP_NBITS+1){
				for (usint i = 0; i<CycloOrder / 2; i++) {
								preconTableI[i] = NativeInteger(m_rootOfUnityInverseTableByModulus[currentMod].operator[](i).ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
							}
			}
			else{
				for (usint i = 0; i<CycloOrder / 2; i++) {
								preconTableI[i] = 0;
							}
			}

			m_rootOfUnityInversePreconTableByModulus[currentMod] = std::move(preconTableI);
		}
	}
}

template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::Reset() {
	m_rootOfUnityTableByModulus.clear();
	m_rootOfUnityInverseTableByModulus.clear();
	m_rootOfUnityPreconTableByModulus.clear();
	m_rootOfUnityInversePreconTableByModulus.clear();
}
	
	void DiscreteFourierTransform::Reset() {
		if (rootOfUnityTable) {
			delete[] rootOfUnityTable;
			rootOfUnityTable = 0;
		}
	}

	void DiscreteFourierTransform::PreComputeTable(uint32_t s) {
		Reset();

		rootOfUnityTable = new std::complex<double>[s];
		for (size_t j = 0;j < s;j++) {
			rootOfUnityTable[j] = std::polar(1.0, -2 * M_PI * j / s);
		}
	}

	std::vector<std::complex<double>> DiscreteFourierTransform::FFTForwardTransform(std::vector<std::complex<double>> & A) {
		usint m = A.size();
		std::vector<std::complex<double>> B(A);
		usint l = floor(log2(m));


		static usint maxMCached (8192);
		static usint LOGM_MAX(13);
		static std::vector<usint> cachedM(LOGM_MAX, 0);
		static std::vector<std::vector<double>> cosTable(LOGM_MAX);
		static std::vector<std::vector<double>> sinTable(LOGM_MAX);;

#pragma omp critical
		if( m != cachedM[l] ) {
		  if (m>maxMCached){
		     //need to grow cachedM and the tables
		    cachedM.resize(l);
		    cosTable.resize(l);
		    cosTable.resize(l);
		    maxMCached = m;
		  }
		  //std::cout<<"miss m "<<m<<" != M "<<cachedM[l]<<std::endl;
		  cachedM[l] = m;

		  sinTable[l].resize(m/2);
		  cosTable[l].resize(m/2);
		  for (usint i = 0; i < m / 2; i++) {
		    cosTable[l][i] = cos(2 * M_PI * i / m);
		    sinTable[l][i] = sin(2 * M_PI * i / m);
		  }
		  
		}

		// Bit-reversed addressing permutation
		for (usint i = 0; i < m; i++) {
			usint j = ReverseBits(i,32) >> (32-l);
			if (j > i) {
				double temp = B[i].real();
				B[i].real( B[j].real() );
				B[j].real( temp );
				temp = B[i].imag();
				B[i].imag( B[j].imag() );
				B[j].imag( temp );
			}
		}

		// Cooley-Tukey decimation-in-time radix-2 FFT
		for (usint size = 2; size <= m; size *= 2) {
			usint halfsize = size / 2;
			usint tablestep = m / size;
			for (usint i = 0; i < m; i += size) {
				for (usint j = i, k = 0; j < i + halfsize; j++, k += tablestep) {
					double tpre =  B[j+halfsize].real() * cosTable[l][k] + B[j+halfsize].imag() * sinTable[l][k];
					double tpim = -B[j+halfsize].real() * sinTable[l][k] + B[j+halfsize].imag() * cosTable[l][k];
					B[j + halfsize].real( B[j].real() - tpre );
					B[j + halfsize].imag( B[j].imag() - tpim );
					B[j].real( B[j].real() + tpre );
					B[j].imag( B[j].imag() + tpim );
				}
			}
			if (size == m)  // Prevent overflow in 'size *= 2'
				break;
		}

		return B;
	}

	std::vector<std::complex<double>> DiscreteFourierTransform::FFTInverseTransform(std::vector<std::complex<double>> & A) {

		std::vector<std::complex<double>> result = DiscreteFourierTransform::FFTForwardTransform(A);
		double n = result.size() / 2;
		for (int i = 0;i < n;i++) {
			result[i] = std::complex<double>(result[i].real() / n, result[i].imag() / n);
		}
		return result;
	}

	std::vector<std::complex<double>> DiscreteFourierTransform::ForwardTransform(std::vector<std::complex<double>> A) {
		int n = A.size();
		A.resize(2 * n);
		for (int i = 0;i < n;i++) {
			A[n + i] = 0;
			//A.push_back(0);
		}
		// if (rootOfUnityTable == NULL) {
		// 	PreComputeTable(2 * n);
		// }
		std::vector<std::complex<double>> dft = FFTForwardTransform(A);
		std::vector<std::complex<double>> dftRemainder(dft.size()/2);
		size_t k = 0;
		for (int i = dft.size() - 1;i > 0;i--) {
			if (i % 2 != 0) {
				dftRemainder[k] = dft[i];
				k++;
				//dftRemainder.push_back(dft[i]);
			}
		}
		return dftRemainder;
	}

	std::vector<std::complex<double>> DiscreteFourierTransform::InverseTransform(std::vector<std::complex<double>> A) {
		size_t n = A.size();
		std::vector<std::complex<double>> dft(2*n);
		for (size_t i = 0; i < n; i++) {
			dft[2*i] = 0;
			dft[2 * i + 1] = A[i];
		}
		std::vector<std::complex<double>> invDft = FFTInverseTransform(dft);
		std::vector<std::complex<double>> invDftRemainder(invDft.size() / 2);
		for (size_t i = 0;i<invDft.size() / 2;i++) {
			invDftRemainder[i] = invDft[i];
		}
		return invDftRemainder;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::PreComputeDefaultNTTModulusRoot(usint cycloOrder, const IntType &modulus) {
		usint nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));
		const auto nttModulus = FirstPrime<IntType>(log2(nttDim) + 2 * modulus.GetMSB(), nttDim);
		const auto nttRoot = RootOfUnity(nttDim, nttModulus);
		const ModulusRoot<IntType> nttModulusRoot = {nttModulus, nttRoot};
		m_defaultNTTModulusRoot[modulus] = nttModulusRoot;

		PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::PreComputeRootTableForNTT(usint cyclotoOrder, const ModulusRoot<IntType> &nttModulusRoot) {
		usint nttDim = pow(2, ceil(log2(2 * cyclotoOrder - 1)));
		const auto &nttModulus = nttModulusRoot.first;
		const auto &nttRoot = nttModulusRoot.second;

		IntType root(nttRoot);

		auto rootInv = root.ModInverse(nttModulus);

		VecType rootTable(nttDim / 2, nttModulus);
		VecType rootTableInverse(nttDim / 2, nttModulus);

		IntType x(1);
		for (usint i = 0; i<nttDim / 2; i++) {
			rootTable[i]= x;
			x = x.ModMul(root, nttModulus);
		}

		x = 1;
		for (usint i = 0; i<nttDim / 2; i++) {
			rootTableInverse[i]= x;
			x = x.ModMul(rootInv, nttModulus);
		}

		m_rootOfUnityTableByModulusRoot[nttModulusRoot] = rootTable;
		m_rootOfUnityInverseTableByModulusRoot[nttModulusRoot] = rootTableInverse;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::PreComputePowers(usint cycloOrder, const ModulusRoot<IntType> &modulusRoot) {
		const auto &modulus = modulusRoot.first;
		const auto &root = modulusRoot.second;

		VecType powers(cycloOrder, modulus);
		powers[0]= 1;
		for (usint i = 1; i <cycloOrder; i++) {
			auto iSqr = (i*i) % (2 * cycloOrder);
			auto val = root.ModExp(IntType(iSqr), modulus);
			powers[i]= val;
		}
		m_powersTableByModulusRoot[modulusRoot] = std::move(powers);
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::PreComputeRBTable(usint cycloOrder, const ModulusRootPair<IntType> &modulusRootPair) {
		const auto &modulusRoot = modulusRootPair.first;
		const auto &modulus = modulusRoot.first;
		const auto &root = modulusRoot.second;
		const auto rootInv = root.ModInverse(modulus);
		
		const auto &nttModulusRoot = modulusRootPair.second;
		const auto &nttModulus = nttModulusRoot.first;
		// const auto &nttRoot = nttModulusRoot.second;
		const auto &rootTable = m_rootOfUnityTableByModulusRoot[nttModulusRoot]; //assumes rootTable is precomputed
		usint nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));

		VecType b(2 * cycloOrder - 1, modulus);
		b[cycloOrder - 1] = 1;
		for (usint i = 1; i < cycloOrder; i++) {
			auto iSqr = (i*i) % (2 * cycloOrder);
			auto val = rootInv.ModExp(IntType(iSqr), modulus);
			b[cycloOrder - 1 + i]= val;
			b[cycloOrder - 1 - i]= val;
		}

		auto Rb = PadZeros(b, nttDim);
		Rb.SetModulus(nttModulus);

		VecType RB(nttDim);
		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(Rb, rootTable, nttDim, &RB);
		m_RBTableByModulusRootPair[modulusRootPair] = std::move(RB);

	}

	template<typename IntType, typename VecType>
	VecType BluesteinFFT<IntType, VecType>::ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder) {
		const auto &modulus = element.GetModulus();
		const auto &nttModulusRoot = m_defaultNTTModulusRoot[modulus];

		return ForwardTransform(element, root, cycloOrder, nttModulusRoot);
	}

	template<typename IntType, typename VecType>
	VecType BluesteinFFT<IntType, VecType>::ForwardTransform(const VecType& element, const IntType& root,
			const usint cycloOrder, const ModulusRoot<IntType>& nttModulusRoot) {
		if (element.GetLength() != cycloOrder) {
			throw std::runtime_error("expected size of element vector should be equal to cyclotomic order");
		}

		const auto &modulus = element.GetModulus();
		const ModulusRoot<IntType> modulusRoot = {modulus, root};
		const VecType &powers = m_powersTableByModulusRoot[modulusRoot];

		const auto &nttModulus = nttModulusRoot.first;
		const auto &rootTable = m_rootOfUnityTableByModulusRoot[nttModulusRoot]; //assumes rootTable is precomputed
		const auto &rootTableInverse = m_rootOfUnityInverseTableByModulusRoot[nttModulusRoot]; //assumes rootTableInverse is precomputed

		VecType x(element*powers);

		usint nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));
		auto Ra = PadZeros(x, nttDim);
		Ra.SetModulus(nttModulus);
		VecType RA(nttDim);
		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(Ra, rootTable, nttDim, &RA);

		const ModulusRootPair<IntType> modulusRootPair = {modulusRoot, nttModulusRoot};
		const auto &RB = m_RBTableByModulusRootPair[modulusRootPair];

		auto RC = RA*RB;
		VecType Rc(nttDim);
		NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(RC, rootTableInverse, nttDim, &Rc);
		auto resizeRc = Resize(Rc, cycloOrder - 1, 2 * (cycloOrder - 1));
		resizeRc.SetModulus(modulus);

		auto result = resizeRc*powers;

		return result;
	}

	template<typename IntType, typename VecType>
	VecType BluesteinFFT<IntType, VecType>::PadZeros(const VecType &a, const usint finalSize) {
		usint s = a.GetLength();
		VecType result(finalSize, a.GetModulus());

		for (usint i = 0; i < s; i++) {
			result[i]= a[i];
		}

		for (usint i = a.GetLength(); i < finalSize; i++) {
			result[i]= IntType(0);
		}

		return result;
	}

	template<typename IntType, typename VecType>
	VecType BluesteinFFT<IntType, VecType>::Resize(const VecType &a, usint  lo, usint hi) {
		VecType result(hi - lo + 1, a.GetModulus());

		for (usint i = lo, j = 0; i <= hi; i++, j++) {
			result[j]= a[i];
		}

		return result;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::Reset() {
		m_rootOfUnityTableByModulusRoot.clear();
		m_rootOfUnityInverseTableByModulusRoot.clear();
		m_powersTableByModulusRoot.clear();
		m_RBTableByModulusRootPair.clear();
		m_defaultNTTModulusRoot.clear();
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::SetCylotomicPolynomial(const VecType &poly, const IntType &mod) {
		m_cyclotomicPolyMap[mod] = poly;
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::PreCompute(const usint cyclotoOrder, const IntType &modulus) {
		BluesteinFFT<IntType, VecType>::PreComputeDefaultNTTModulusRoot(cyclotoOrder, modulus);
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::SetPreComputedNTTModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttModulus, const IntType &nttRoot) {
		const ModulusRoot<IntType> nttModulusRoot = { nttModulus, nttRoot };
		BluesteinFFT<IntType, VecType>::PreComputeRootTableForNTT(cyclotoOrder, nttModulusRoot);
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::SetPreComputedNTTDivisionModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod,
		const IntType &nttRootBig) {
        bool dbg_flag = false;

		usint n = GetTotient(cyclotoOrder);
		DEBUG("GetTotient("<<cyclotoOrder<<")= "<<n);

		usint power = cyclotoOrder - n;
		m_nttDivisionDim[cyclotoOrder] = 2 * std::pow(2, ceil(log2(power)));

		usint nttDimBig = std::pow(2, ceil(log2(2 * cyclotoOrder - 1)));

		// Computes the root of unity for the division NTT based on the root of unity for regular NTT
		IntType nttRoot = nttRootBig.ModExp(IntType(nttDimBig / m_nttDivisionDim[cyclotoOrder]), nttMod);

		m_DivisionNTTModulus[modulus] = nttMod;
		m_DivisionNTTRootOfUnity[modulus] = nttRoot;
		//part0 setting of rootTable and inverse rootTable
		usint nttDim = m_nttDivisionDim[cyclotoOrder];
		IntType root(nttRoot);
		auto rootInv = root.ModInverse(nttMod);

		VecType rootTable(nttDim / 2, nttMod);
		VecType rootTableInverse(nttDim / 2, nttMod);

		IntType x(1);
		for (usint i = 0; i < nttDim / 2; i++) {
			rootTable[i]= x;
			x = x.ModMul(root, nttMod);
		}

		x = 1;
		for (usint i = 0; i < nttDim / 2; i++) {
			rootTableInverse[i]= x;
			x = x.ModMul(rootInv, nttMod);
		}

		m_rootOfUnityDivisionTableByModulus[nttMod] = rootTable;
		m_rootOfUnityDivisionInverseTableByModulus[nttMod] = rootTableInverse;

		//end of part0
		//part1
		const auto &RevCPM = InversePolyMod(m_cyclotomicPolyMap[modulus], modulus, power);
		auto RevCPMPadded = BluesteinFFT<IntType, VecType>::PadZeros(RevCPM, nttDim);
		RevCPMPadded.SetModulus(nttMod);
		//end of part1

		VecType RA(nttDim);
		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(RevCPMPadded, rootTable, nttDim, &RA);
		m_cyclotomicPolyReverseNTTMap[modulus] = std::move(RA);

		const auto &cycloPoly = m_cyclotomicPolyMap[modulus];

		VecType QForwardTransform(nttDim, nttMod);
		for (usint i = 0; i < cycloPoly.GetLength(); i++) {
			QForwardTransform[i]= cycloPoly[i];
		}

		VecType QFwdResult(nttDim);
		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(QForwardTransform, rootTable, nttDim, &QFwdResult);

		m_cyclotomicPolyNTTMap[modulus] = std::move(QFwdResult);
	}

	template<typename IntType, typename VecType>
	VecType ChineseRemainderTransformArb<IntType, VecType>::InversePolyMod(const VecType &cycloPoly, const IntType &modulus, usint power) {

		VecType result(power, modulus);
		usint r = ceil(log2(power));
		VecType h(1, modulus);//h is a unit polynomial
		h[0]= 1;

		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(modulus);

		for (usint i = 0; i < r; i++) {
			usint qDegree = std::pow(2, i + 1);
			VecType q(qDegree + 1, modulus);//q = x^(2^i+1)
			q[qDegree]= 1;
			auto hSquare = PolynomialMultiplication(h, h);

			auto a = h * IntType(2);
			auto b = PolynomialMultiplication(hSquare, cycloPoly);
			//b = 2h - gh^2
			for (usint j = 0; j < b.GetLength(); j++) {
				if (j < a.GetLength()) {
					b[j]= a[j].ModBarrettSub(b[j], modulus, mu);
				}
				else
					b[j]= modulus.ModBarrettSub(b[j], modulus, mu);
			}
			h = PolyMod(b, q, modulus);

		}
		//take modulo x^power
		for (usint i = 0; i < power; i++) {
			result[i]= h[i];
		}

		return result;
	}

	template<typename IntType, typename VecType>
	VecType ChineseRemainderTransformArb<IntType, VecType>::ForwardTransform(const VecType& element, const IntType& root, const IntType& nttModulus,
		const IntType& nttRoot, const usint cycloOrder) {
		usint phim = GetTotient(cycloOrder);
		if (element.GetLength() != phim) {
			throw std::runtime_error("element size should be equal to phim");
		}

		const auto &modulus = element.GetModulus();
		const ModulusRoot<IntType> modulusRoot = { modulus, root };

		const ModulusRoot<IntType> nttModulusRoot = { nttModulus, nttRoot };
		const ModulusRootPair<IntType> modulusRootPair = {  modulusRoot, nttModulusRoot };

#pragma omp critical
		{
			if (BluesteinFFT<IntType, VecType>::m_rootOfUnityTableByModulusRoot[nttModulusRoot].GetLength() == 0) {
				BluesteinFFT<IntType, VecType>::PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
			}

			if (BluesteinFFT<IntType, VecType>::m_powersTableByModulusRoot[modulusRoot].GetLength() == 0) {
				BluesteinFFT<IntType, VecType>::PreComputePowers(cycloOrder, modulusRoot);
			}

			if(BluesteinFFT<IntType, VecType>::m_RBTableByModulusRootPair[modulusRootPair].GetLength() == 0){
				BluesteinFFT<IntType, VecType>::PreComputeRBTable(cycloOrder, modulusRootPair);
			}
		}

		VecType inputToBluestein = Pad(element, cycloOrder, true);
		auto outputBluestein = BluesteinFFT<IntType, VecType>::ForwardTransform(inputToBluestein, root, cycloOrder, nttModulusRoot);
		VecType output = Drop(outputBluestein, cycloOrder, true, nttModulus, nttRoot);

		return output;

		}

	template<typename IntType, typename VecType>
	VecType ChineseRemainderTransformArb<IntType, VecType>::InverseTransform(const VecType& element, const IntType& root,
			const IntType& nttModulus, const IntType& nttRoot, const usint cycloOrder) {
		usint phim = GetTotient(cycloOrder);
		if (element.GetLength() != phim) {
			throw std::runtime_error("element size should be equal to phim");
		}

		const auto &modulus = element.GetModulus();
		auto rootInverse(root.ModInverse(modulus));
		const ModulusRoot<IntType> modulusRootInverse = { modulus, rootInverse };

		const ModulusRoot<IntType> nttModulusRoot = { nttModulus, nttRoot };
		const ModulusRootPair<IntType> modulusRootPair = {  modulusRootInverse, nttModulusRoot };

#pragma omp critical
{
		if (BluesteinFFT<IntType, VecType>::m_rootOfUnityTableByModulusRoot[nttModulusRoot].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
		}

		if (BluesteinFFT<IntType, VecType>::m_powersTableByModulusRoot[modulusRootInverse].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::PreComputePowers(cycloOrder, modulusRootInverse);
		}

		if(BluesteinFFT<IntType, VecType>::m_RBTableByModulusRootPair[modulusRootPair].GetLength() == 0){
			BluesteinFFT<IntType, VecType>::PreComputeRBTable(cycloOrder, modulusRootPair);
		}
	}

		VecType inputToBluestein = Pad(element, cycloOrder, false);
		auto outputBluestein = BluesteinFFT<IntType, VecType>::ForwardTransform(inputToBluestein, rootInverse, cycloOrder, nttModulusRoot);
		auto cyclotomicInverse((IntType(cycloOrder)).ModInverse(modulus));
		outputBluestein = outputBluestein*cyclotomicInverse;
		VecType output = Drop(outputBluestein, cycloOrder, false, nttModulus, nttRoot);

		return output;
	}

	template<typename IntType, typename VecType>
	VecType ChineseRemainderTransformArb<IntType, VecType>::Pad(const VecType& element, const usint cycloOrder, bool forward) {
		usint n = GetTotient(cycloOrder);

		const auto &modulus = element.GetModulus();
		VecType inputToBluestein(cycloOrder, modulus);

		if(forward){ // Forward transform padding
			for (usint i = 0; i < n; i++) {
				inputToBluestein[i]= element[i];
			}
		} else { // Inverse transform padding
		auto tList = GetTotientList(cycloOrder);
		usint i = 0;
		for (auto &coprime : tList) {
			inputToBluestein[coprime]= element[i++];
		}
		}

		return inputToBluestein;
		}

	template<typename IntType, typename VecType>
	VecType ChineseRemainderTransformArb<IntType, VecType>::Drop(const VecType& element, const usint cycloOrder, bool forward, const IntType& bigMod, const IntType& bigRoot) {
		usint n = GetTotient(cycloOrder);

		const auto &modulus = element.GetModulus();
		VecType output(n, modulus);

		if(forward){ // Forward transform drop
			auto tList = GetTotientList(cycloOrder);
			for (usint i = 0; i < n; i++) {
				output[i]= element[tList[i]];
		}
		} else { // Inverse transform drop
			if((n+1) == cycloOrder){
				// cycloOrder is prime: Reduce mod Phi_{n+1}(x)
				// Reduction involves subtracting the coeff of x^n from all terms
				auto coeff_n = element[n];

				//Precompute the Barrett mu parameter
				IntType mu = ComputeMu<IntType>(modulus);

				for (usint i = 0; i < n; i++) {
					output[i] = element[i].ModBarrettSub(coeff_n, modulus, mu);
				}
			} else if ((n+1)*2 == cycloOrder){
				// cycloOrder is 2*prime: 2 Step reduction
				// First reduce mod x^(n+1)+1 (=(x+1)*Phi_{2*(n+1)}(x))
				// Subtract co-efficient of x^(i+n+1) from x^(i)

				//Precompute the Barrett mu parameter
				IntType mu = ComputeMu<IntType>(modulus);

				for (usint i = 0; i < n; i++) {
					auto coeff_i = element[i];
					auto coeff_ip = element[i+n+1];
					output[i]= coeff_i.ModBarrettSub(coeff_ip, modulus, mu);
				}
				auto coeff_n = element[n].ModBarrettSub(
						element[2*n+1], modulus, mu
					);
				// Now reduce mod Phi_{2*(n+1)}(x)
				// Similar to the prime case but with alternating signs
				for (usint i = 0; i < n; i++) {
					if (i%2 == 0) {
						output[i]= output[i].ModBarrettSub(coeff_n, modulus, mu);
					} else {
						output[i]= output[i].ModBarrettAdd(coeff_n, modulus, mu);
					}
				}
			} else {

		//precompute root of unity tables for division NTT
		if ((m_rootOfUnityDivisionTableByModulus[bigMod].GetLength() == 0) || (m_DivisionNTTModulus[modulus] != bigMod)) {
			SetPreComputedNTTDivisionModulus(cycloOrder, modulus, bigMod, bigRoot);
		}

				// cycloOrder is arbitrary
				//auto output = PolyMod(element, this->m_cyclotomicPolyMap[modulus], modulus);

		const auto &nttMod = m_DivisionNTTModulus[modulus];
		const auto &rootTable = m_rootOfUnityDivisionTableByModulus[nttMod];
		VecType aPadded2(m_nttDivisionDim[cycloOrder], nttMod);
		//perform mod operation
		usint power = cycloOrder - n;
				for (usint i = n; i < element.GetLength(); i++) {
					aPadded2[power-(i-n)-1]= element[i];
		}

		VecType A(m_nttDivisionDim[cycloOrder]);
		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(aPadded2, rootTable, m_nttDivisionDim[cycloOrder], &A);
		auto AB = A*m_cyclotomicPolyReverseNTTMap[modulus];
		const auto &rootTableInverse = m_rootOfUnityDivisionInverseTableByModulus[nttMod];
		VecType a(m_nttDivisionDim[cycloOrder]);
		NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(AB, rootTableInverse, m_nttDivisionDim[cycloOrder], &a);

		VecType quotient(m_nttDivisionDim[cycloOrder], modulus);
		for (usint i = 0; i < power; i++) {
			quotient[i]= a[i];
		}
		quotient = quotient.Mod(modulus);
		quotient.SetModulus(nttMod);

		VecType newQuotient(m_nttDivisionDim[cycloOrder]);
		NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(quotient, rootTable, m_nttDivisionDim[cycloOrder], &newQuotient);

		newQuotient = newQuotient*m_cyclotomicPolyNTTMap[modulus];

		VecType newQuotient2(m_nttDivisionDim[cycloOrder]);
		NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(newQuotient, rootTableInverse, m_nttDivisionDim[cycloOrder], &newQuotient2);
		newQuotient2.SetModulus(modulus);
		newQuotient2 = newQuotient2.Mod(modulus);


		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(modulus);

		for (usint i = 0; i < n; i++) {
			output[i]= element[i].ModBarrettSub(newQuotient2[cycloOrder - 1 - i], modulus, mu);
		}

			}
		}

		return output;
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::Reset() {
		m_cyclotomicPolyMap.clear();
		m_cyclotomicPolyReverseNTTMap.clear();
		m_cyclotomicPolyNTTMap.clear();
		m_rootOfUnityDivisionTableByModulus.clear();
		m_rootOfUnityDivisionInverseTableByModulus.clear();
		m_DivisionNTTModulus.clear();
		m_DivisionNTTRootOfUnity.clear();
		m_nttDivisionDim.clear();
		BluesteinFFT<IntType, VecType>::Reset();
	}


	template class ChineseRemainderTransformFTT<BigInteger,BigVector>;
	template class NumberTheoreticTransform<BigInteger,BigVector>;
	template class ChineseRemainderTransformArb<BigInteger, BigVector>;
	template class BluesteinFFT<BigInteger, BigVector>;

	template class ChineseRemainderTransformFTT<NativeInteger,NativeVector>;
	template class NumberTheoreticTransform<NativeInteger,NativeVector>;
	template class ChineseRemainderTransformArb<NativeInteger, NativeVector>;
	template class BluesteinFFT<NativeInteger, NativeVector>;
}//namespace ends here
