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


//static Initializations
template<typename IntType, typename VecType>
NumberTheoreticTransform<IntType,VecType>* NumberTheoreticTransform<IntType,VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
ChineseRemainderTransform<IntType,VecType>* ChineseRemainderTransform<IntType,VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
VecType* ChineseRemainderTransform<IntType,VecType>::m_rootOfUnityInverseTable = 0;

template<typename IntType, typename VecType>
VecType* ChineseRemainderTransform<IntType,VecType>::m_rootOfUnityTable = 0;

template<typename IntType, typename VecType>
ChineseRemainderTransformFTT<IntType,VecType>* ChineseRemainderTransformFTT<IntType,VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
BluesteinFFT<IntType, VecType>* BluesteinFFT<IntType, VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
ChineseRemainderTransformArb<IntType, VecType>* ChineseRemainderTransformArb<IntType, VecType>::m_onlyInstance = 0;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityTableByModulus;

template<typename IntType, typename VecType>
std::map<IntType, VecType> ChineseRemainderTransformFTT<IntType,VecType>::m_rootOfUnityInverseTableByModulus;

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

DiscreteFourierTransform* DiscreteFourierTransform::m_onlyInstance = 0;
std::complex<double>* DiscreteFourierTransform::rootOfUnityTable = 0;

template<typename IntType, typename VecType>
NumberTheoreticTransform<IntType,VecType>& NumberTheoreticTransform<IntType,VecType>::GetInstance() {
	if (m_onlyInstance == NULL) {
		m_onlyInstance = new NumberTheoreticTransform<IntType,VecType>();//lazy instantiation
	}
	return *m_onlyInstance;
}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
template<typename IntType, typename VecType>
VecType NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(const VecType& element, const VecType &rootOfUnityTable, const usint cycloOrder) {
        bool dbg_flag = false;
	usint n = cycloOrder;
	VecType result(n);
	result.SetModulus(element.GetModulus());

	//reverse coefficients (bit reversal)
	usint msb = GetMSB64(n - 1);
	for (size_t i = 0; i < n; i++)
		result.SetValAtIndex(i, element.GetValAtIndex(ReverseBits(i, msb)));

	IntType omegaFactor;
	IntType product;
	IntType butterflyPlus;
	IntType butterflyMinus;
	/*Ring dimension factor calculates the ratio between the cyclotomic order of the root of unity table
		  that was generated originally and the cyclotomic order of the current VecType. The twiddle table
		  for lower cyclotomic orders is smaller. This trick only works for powers of two cyclotomics.*/ 
	float ringDimensionFactor = ((float)rootOfUnityTable.GetLength()) / (float)cycloOrder;

	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(element.GetModulus());

	for (usint m = 2; m <= n; m = 2 * m)
	{

		for (usint j = 0; j<n; j = j + m)
		{
			for (usint i = 0; i <= m / 2 - 1; i++)
			{

				usint x = (2 * i*n / m ) * ringDimensionFactor;

				const IntType& omega = rootOfUnityTable.GetValAtIndex(x);

				usint indexEven = j + i;
				usint indexOdd = j + i + m / 2;

				if (result.GetValAtIndex(indexOdd).GetMSB()>0)
				{

					if (result.GetValAtIndex(indexOdd).GetMSB() == 1)
						omegaFactor = omega;
					else
					{

						omegaFactor = omega.ModBarrettMul(result.GetValAtIndex(indexOdd),element.GetModulus(), mu);

						DEBUG("omegaFactor "<<omegaFactor);
					}

					butterflyPlus = result.GetValAtIndex(indexEven);
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= element.GetModulus())
						butterflyPlus -= element.GetModulus();

					butterflyMinus = result.GetValAtIndex(indexEven);
					if (result.GetValAtIndex(indexEven) < omegaFactor)
						butterflyMinus += element.GetModulus();
					butterflyMinus -= omegaFactor;

					result.SetValAtIndex(indexEven, butterflyPlus);
					result.SetValAtIndex(indexOdd, butterflyMinus);

				}
				else
				  //result.SetValAtIndex(indexOdd, result.GetValAtIndex(indexEven));
				  result[indexOdd] = result[indexEven];

			}

		}
	}

	return result;

}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
template<typename IntType, typename VecType>
VecType NumberTheoreticTransform<IntType,VecType>::InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable, const usint cycloOrder) {

	VecType ans = NumberTheoreticTransform<IntType,VecType>::GetInstance().ForwardTransformIterative(element, rootOfUnityInverseTable, cycloOrder);

	ans.SetModulus(element.GetModulus());
	//TODO:: note this could be stored
#if 1//MATHBACKEND !=6
	ans = ans.ModMul(IntType(cycloOrder).ModInverse(element.GetModulus()));
#else
	ans *= (IntType(cycloOrder).ModInverse(element.GetModulus()));
#endif

	return ans;
}

template<typename IntType, typename VecType>
void NumberTheoreticTransform<IntType,VecType>::SetElement(const VecType &element) {
	m_element = &element;
}

template<typename IntType, typename VecType>
void NumberTheoreticTransform<IntType,VecType>::Destroy() {
	if( m_element != NULL ) delete m_element;
	m_element = NULL;
}


template<typename IntType, typename VecType>
ChineseRemainderTransform<IntType,VecType>& ChineseRemainderTransform<IntType,VecType>::GetInstance() {
	if (m_onlyInstance == NULL) {
		m_onlyInstance = new ChineseRemainderTransform<IntType,VecType>();
	}

	return *m_onlyInstance;
}

template<typename IntType, typename VecType>
ChineseRemainderTransformFTT<IntType,VecType>& ChineseRemainderTransformFTT<IntType,VecType>::GetInstance() {
	if (m_onlyInstance == NULL) {
		m_onlyInstance = new ChineseRemainderTransformFTT<IntType,VecType>();
	}

	return *m_onlyInstance;
}


//main CRT Transform - uses iterative FFT as a subroutine
//includes precomputation of twidle factor table
template<typename IntType, typename VecType>
VecType ChineseRemainderTransform<IntType,VecType>::ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) {

#pragma omp critical
	if (m_rootOfUnityTable == NULL) {
		m_rootOfUnityTable = new VecType(CycloOrder + 1);  //We may be able to change length to CycloOrder/2
		IntType x(IntType::ONE);
		for (usint i = 0; i<CycloOrder / 2; i++) {
			m_rootOfUnityTable->SetValAtIndex(i, x);
			m_rootOfUnityTable->SetValAtIndex(i + CycloOrder / 2, element.GetModulus() - x);
			x = x.ModMul(rootOfUnity, element.GetModulus());
		}

		m_rootOfUnityTable->SetValAtIndex(CycloOrder, IntType::ONE);

	}

	if (!IsPowerOfTwo(CycloOrder)) {
		std::cout << "Error in the FFT operation\n\n";
		exit(-10);
	}

	VecType OpFFT;
	VecType InputToFFT = ZeroPadForward(element, CycloOrder);

	if (!IsPowerOfTwo(element.GetLength())) {
		std::cout << "Input to FFT is not a power of two\n ERROR BEFORE FFT\n";
		OpFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().ForwardTransformIterative(InputToFFT, *m_rootOfUnityTable, CycloOrder);
	}
	else {
		OpFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().ForwardTransformIterative(InputToFFT, *m_rootOfUnityTable, CycloOrder);
	}

	VecType ans(CycloOrder / 2);

	for (usint i = 0; i<CycloOrder / 2; i++)
		ans.SetValAtIndex(i, OpFFT.GetValAtIndex(2 * i + 1));

	ans.SetModulus(OpFFT.GetModulus());

	return ans;
}

//main CRT Transform - uses iterative FFT as a subroutine
//includes precomputation of inverse twidle factor table
template<typename IntType, typename VecType>
VecType ChineseRemainderTransform<IntType,VecType>::InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) {

	IntType rootOfUnityInverse = rootOfUnity.ModInverse(element.GetModulus());

	if (!IsPowerOfTwo(CycloOrder)) {
		std::cout << "Error in the FFT operation\n\n";
		exit(-10);
	}

#pragma omp critical
	if (m_rootOfUnityInverseTable == NULL) {
		m_rootOfUnityInverseTable = new VecType(CycloOrder + 1);
		IntType x(IntType::ONE);
		for (usint i = 0; i<CycloOrder / 2; i++) {
			m_rootOfUnityInverseTable->SetValAtIndex(i, x);
			m_rootOfUnityInverseTable->SetValAtIndex(i + CycloOrder / 2, element.GetModulus() - x);
			x = x.ModMul(rootOfUnityInverse, element.GetModulus());
		}

		m_rootOfUnityInverseTable->SetValAtIndex(CycloOrder, IntType::ONE);

	}

	VecType OpIFFT;
	VecType InputToFFT = ZeroPadInverse(element, CycloOrder);

	if (!IsPowerOfTwo(element.GetLength())) {
		std::cout << "Input to IFFT is not a power of two\n ERROR BEFORE FFT\n";
		//HERE IS WHERE WE NEED ADD additional table of modinverse etc.
		OpIFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().InverseTransformIterative(InputToFFT, *m_rootOfUnityInverseTable, CycloOrder);
	}
	else {
		OpIFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().InverseTransformIterative(InputToFFT, *m_rootOfUnityInverseTable, CycloOrder);
	}

	VecType ans(CycloOrder / 2);
	//TODO:: can this be done quicker?
	for (usint i = 0; i<CycloOrder / 2; i++)
		ans.SetValAtIndex(i, (OpIFFT).GetValAtIndex(i).ModMul(IntType::TWO, (OpIFFT).GetModulus()));

	ans.SetModulus(OpIFFT.GetModulus());

	return ans;
}

//main Forward CRT Transform - implements FTT - uses iterative NTT as a subroutine
//includes precomputation of twidle factor table
template<typename IntType, typename VecType>
VecType ChineseRemainderTransformFTT<IntType,VecType>::ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) {
	std::string errMsg;
	if (rootOfUnity == 1 || rootOfUnity == 0) {
		errMsg = "Root of unity cannot be zero or one to perform a forward transform";
		throw std::logic_error(errMsg);
	}
	if (!IsPowerOfTwo(CycloOrder)) {
		errMsg = "cyclotomic order must be a power of 2 to perform a forward transform";
		throw std::logic_error(errMsg);
	}

	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(element.GetModulus());

	const VecType *rootOfUnityTable = NULL;

	// check to see if the modulus is in the table, and add it if it isn't
#pragma omp critical
	{
		bool recompute = false;
		auto mSearch = m_rootOfUnityTableByModulus.find(element.GetModulus());

		if( mSearch != m_rootOfUnityTableByModulus.end() ) {
			// i found it... make sure it's kosher
			if( mSearch->second.GetLength() == 0 || mSearch->second.GetValAtIndex(1) != rootOfUnity ) {
				recompute = true;
			}
			else
				rootOfUnityTable = &mSearch->second;
		}

		if( mSearch == m_rootOfUnityTableByModulus.end() || recompute ){
			VecType rTable(CycloOrder / 2);
			IntType modulus(element.GetModulus());
			IntType x(1);

			for (usint i = 0; i<CycloOrder / 2; i++) {
				rTable.SetValAtIndex(i, x);
				x = x.ModBarrettMul(rootOfUnity, modulus, mu);
			}

			rootOfUnityTable = &(m_rootOfUnityTableByModulus[modulus] = std::move(rTable));
		}
	}

	VecType OpFFT;
	VecType InputToFFT(element);

	usint ringDimensionFactor = rootOfUnityTable->GetLength() / (CycloOrder / 2);

	//Fermat Theoretic Transform (FTT)
	for (usint i = 0; i<CycloOrder / 2; i++)
		InputToFFT.SetValAtIndex(i, element.GetValAtIndex(i).ModBarrettMul(rootOfUnityTable->GetValAtIndex(i*ringDimensionFactor), element.GetModulus(), mu));

	OpFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().ForwardTransformIterative(InputToFFT, *rootOfUnityTable, CycloOrder / 2);

	return OpFFT;
}

//main Inverse CRT Transform - implements FTT - uses iterative NTT as a subroutine
//includes precomputation of inverse twidle factor table
template<typename IntType, typename VecType>
VecType ChineseRemainderTransformFTT<IntType,VecType>::InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) {
	std::string errMsg;
	if (rootOfUnity == 1 || rootOfUnity == 0) {
		errMsg = "Root of unity cannot be zero or one to perform an inverse transform";
		throw std::logic_error(errMsg);
	}
	if (!IsPowerOfTwo(CycloOrder)) {
		errMsg = "cyclotomic order must be a power of 2 to perform an inverse transform";
		throw std::logic_error(errMsg);
	}

	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(element.GetModulus());

	const VecType *rootOfUnityITable = NULL;

	IntType rootofUnityInverse;

	//TODO: is there a reason this isn't checked oly initially when the table is made? 
	try {
		rootofUnityInverse = rootOfUnity.ModInverse(element.GetModulus());
	}
	catch (std::exception& e) {
		errMsg = std::string(e.what()) + ": rootOfUnity " + rootOfUnity.ToString() + " has no inverse";
		throw std::logic_error(errMsg);
	}

	// check to see if the modulus is in the table
#pragma omp critical
	{
		bool recompute = false;
		auto mSearch = m_rootOfUnityInverseTableByModulus.find(element.GetModulus());

		if( mSearch != m_rootOfUnityInverseTableByModulus.end() ) {
			// i found it... make sure it's kosher
			if( mSearch->second.GetLength() == 0 || mSearch->second.GetValAtIndex(1) != rootofUnityInverse ) {
				recompute = true;
			}
			else
				rootOfUnityITable = &mSearch->second;
		}

		if( mSearch == m_rootOfUnityInverseTableByModulus.end() || recompute ) {
			VecType TableI(CycloOrder / 2);

			IntType x(1);

			for (usint i = 0; i<CycloOrder / 2; i++) {
				TableI.SetValAtIndex(i, x);
				x = x.ModBarrettMul(rootofUnityInverse, element.GetModulus(), mu);
			}

			rootOfUnityITable = &(m_rootOfUnityInverseTableByModulus[element.GetModulus()] = std::move(TableI));
		}
	}

	VecType OpIFFT;
	OpIFFT = NumberTheoreticTransform<IntType,VecType>::GetInstance().InverseTransformIterative(element, *rootOfUnityITable, CycloOrder / 2);

	usint ringDimensionFactor = rootOfUnityITable->GetLength() / (CycloOrder / 2);

	VecType rInvTable(*rootOfUnityITable);
	for (usint i = 0; i<CycloOrder / 2; i++)
		OpIFFT.SetValAtIndex(i, OpIFFT.GetValAtIndex(i).ModBarrettMul(rInvTable.GetValAtIndex(i*ringDimensionFactor), element.GetModulus(), mu));

	return OpIFFT;
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
		VecType Table(CycloOrder / 2);


		for (usint i = 0; i<CycloOrder / 2; i++) {
			Table.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnity, modulus, mu);
		}

		this->m_rootOfUnityTableByModulus[modulus] = std::move(Table);
	}

	//Precomputes twiddle factor omega and FTT parameter phi for Inverse Transform
	VecType  *rootOfUnityInverseTableCheck = &m_rootOfUnityInverseTableByModulus[modulus];
	if (rootOfUnityInverseTableCheck->GetLength() == 0) {
		VecType TableI(CycloOrder / 2);
		IntType rootOfUnityInverse = rootOfUnity.ModInverse(modulus);

		x = 1;

		for (usint i = 0; i<CycloOrder / 2; i++) {
			TableI.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnityInverse, modulus, mu);
		}

		this->m_rootOfUnityInverseTableByModulus[modulus] = std::move(TableI);

	}

}

template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::PreCompute(std::vector<IntType> &rootOfUnity, const usint CycloOrder, std::vector<IntType> &moduliiChain) {

	usint numOfRootU = rootOfUnity.size();
	usint numModulii = moduliiChain.size();

	if (numOfRootU != numModulii) {
		throw std::logic_error("size of root of unity and size of moduli chain not of same size");
	}

	for (usint i = numOfRootU; i<numOfRootU; ++i) {

		IntType currentRoot(rootOfUnity[i]);
		IntType currentMod(moduliiChain[i]);

		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(currentMod);

		if (this->m_rootOfUnityTableByModulus[moduliiChain[i]].GetLength() != 0)
			continue;



		IntType x(1);


		//computation of root of unity table
		VecType rTable(CycloOrder / 2);


		for (usint i = 0; i<CycloOrder / 2; i++) {
			rTable.SetValAtIndex(i, x);
			x = x.ModBarrettMul(currentRoot, currentMod, mu);
		}

		this->m_rootOfUnityTableByModulus[currentMod] = std::move(rTable);

		//computation of root of unity inverse table
		x = 1;

		IntType rootOfUnityInverse = currentRoot.ModInverse(currentMod);

		VecType rTableI(CycloOrder / 2);


		for (usint i = 0; i<CycloOrder / 2; i++) {
			rTableI.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnityInverse, currentMod, mu);
		}

		this->m_rootOfUnityInverseTableByModulus[currentMod] = std::move(rTableI);


	}


}

template<typename IntType, typename VecType>
void ChineseRemainderTransform<IntType,VecType>::Destroy() {
	if( m_rootOfUnityTable ) delete m_rootOfUnityTable;
	if( m_rootOfUnityInverseTable ) delete m_rootOfUnityInverseTable;
}

template<typename IntType, typename VecType>
void ChineseRemainderTransformFTT<IntType,VecType>::Destroy() {
	if( m_onlyInstance != NULL ) delete m_onlyInstance;
	m_onlyInstance = NULL;
}
	
	void DiscreteFourierTransform::Destroy() {
		if (rootOfUnityTable) {
			delete rootOfUnityTable;
			rootOfUnityTable = 0;
		}
		if (m_onlyInstance) {
			delete m_onlyInstance; 
			m_onlyInstance = 0;
		}
	}
	void DiscreteFourierTransform::PreComputeTable(uint32_t s) {
		size = s;
		if (rootOfUnityTable) {
			delete rootOfUnityTable;
			rootOfUnityTable = 0;
		}
		rootOfUnityTable = new std::complex<double>[s];
		for (size_t j = 0;j < s;j++) {
			rootOfUnityTable[j] = std::polar(1.0, -2 * M_PI * j / s);
		}
	}

	std::vector<std::complex<double>> DiscreteFourierTransform::FFTForwardTransform(std::vector<std::complex<double>> & A) {
		int m = A.size();
		std::vector<std::complex<double>> B(A);
		int levels = floor(log2(m));

		static int cachedM;
		static std::vector<double> cosTable;
		static std::vector<double> sinTable;

#pragma omp critical
		if( m != cachedM ) {
			cachedM = m;
			sinTable.resize(m/2);
			cosTable.resize(m/2);
			for (int i = 0; i < m / 2; i++) {
				cosTable[i] = cos(2 * M_PI * i / m);
				sinTable[i] = sin(2 * M_PI * i / m);
			}
		}

		// Bit-reversed addressing permutation
		for (int i = 0; i < m; i++) {
			int j = ReverseBits(i,32) >> (32-levels);
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
		for (int size = 2; size <= m; size *= 2) {
			int halfsize = size / 2;
			int tablestep = m / size;
			for (int i = 0; i < m; i += size) {
				for (int j = i, k = 0; j < i + halfsize; j++, k += tablestep) {
					double tpre =  B[j+halfsize].real() * cosTable[k] + B[j+halfsize].imag() * sinTable[k];
					double tpim = -B[j+halfsize].real() * sinTable[k] + B[j+halfsize].imag() * cosTable[k];
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
		for (int i = 0;i < n;i++) {
			A.push_back(0);
		}
		if (rootOfUnityTable == NULL) {
			PreComputeTable(2 * n);
		}
		std::vector<std::complex<double>> dft = FFTForwardTransform(A);
		std::vector<std::complex<double>> dftRemainder;
		for (int i = dft.size() - 1;i > 0;i--) {
			if (i % 2 != 0) {
				dftRemainder.push_back(dft.at(i));
			}
		}
		return dftRemainder;
	}
	std::vector<std::complex<double>> DiscreteFourierTransform::InverseTransform(std::vector<std::complex<double>> A) {
		size_t n = A.size();
		std::vector<std::complex<double>> dft;
		for (size_t i = 0; i < n; i++) {
			dft.push_back(0);
			dft.push_back(A.at(i));
		}
		std::vector<std::complex<double>> invDft = FFTInverseTransform(dft);
		std::vector<std::complex<double>> invDftRemainder;
		for (size_t i = 0;i<invDft.size() / 2;i++) {
			invDftRemainder.push_back(invDft.at(i));
		}
		return invDftRemainder;
	}

	DiscreteFourierTransform& DiscreteFourierTransform::GetInstance() {
		if (m_onlyInstance == NULL) {
			m_onlyInstance = new DiscreteFourierTransform();//lazy instantiation
		}
		return *m_onlyInstance;
	}

	template<typename IntType, typename VecType>
	BluesteinFFT<IntType, VecType>& BluesteinFFT<IntType, VecType>::GetInstance() {
		if (m_onlyInstance == NULL) {
			m_onlyInstance = new BluesteinFFT<IntType, VecType>();//lazy instantiation
		}
		return *m_onlyInstance;
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
			rootTable.SetValAtIndex(i, x);
			x = x.ModMul(root, nttModulus);
		}

		x = 1;
		for (usint i = 0; i<nttDim / 2; i++) {
			rootTableInverse.SetValAtIndex(i, x);
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
		powers.SetValAtIndex(0, 1);
		for (usint i = 1; i <cycloOrder; i++) {
			auto iSqr = (i*i) % (2 * cycloOrder);
			auto val = root.ModExp(IntType(iSqr), modulus);
			powers.SetValAtIndex(i, val);
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
		b.SetValAtIndex(cycloOrder - 1, 1);
		for (usint i = 1; i < cycloOrder; i++) {
			auto iSqr = (i*i) % (2 * cycloOrder);
			auto val = rootInv.ModExp(IntType(iSqr), modulus);
			b.SetValAtIndex(cycloOrder - 1 + i, val);
			b.SetValAtIndex(cycloOrder - 1 - i, val);
		}

		auto Rb = PadZeros(b, nttDim);
		Rb.SetModulus(nttModulus);

		auto RB = NumberTheoreticTransform<IntType, VecType>::GetInstance().ForwardTransformIterative(Rb, rootTable, nttDim);
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
		auto RA = NumberTheoreticTransform<IntType, VecType>::GetInstance().ForwardTransformIterative(Ra, rootTable, nttDim);

		const ModulusRootPair<IntType> modulusRootPair = {modulusRoot, nttModulusRoot};
		const auto &RB = m_RBTableByModulusRootPair[modulusRootPair];

		auto RC = RA*RB;
		auto Rc = NumberTheoreticTransform<IntType, VecType>::GetInstance().InverseTransformIterative(RC, rootTableInverse, nttDim);
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
			result.SetValAtIndex(i, a.GetValAtIndex(i));
		}

		for (usint i = a.GetLength(); i < finalSize; i++) {
			result.SetValAtIndex(i, IntType(0));
		}

		return result;
	}

	template<typename IntType, typename VecType>
	VecType BluesteinFFT<IntType, VecType>::Resize(const VecType &a, usint  lo, usint hi) {
		VecType result(hi - lo + 1, a.GetModulus());

		for (usint i = lo, j = 0; i <= hi; i++, j++) {
			result.SetValAtIndex(j, a.GetValAtIndex(i));
		}

		return result;
	}

	template<typename IntType, typename VecType>
	void BluesteinFFT<IntType, VecType>::Destroy() {
		m_rootOfUnityTableByModulusRoot.clear();
		m_rootOfUnityInverseTableByModulusRoot.clear();
		m_powersTableByModulusRoot.clear();
		m_RBTableByModulusRootPair.clear();
		m_defaultNTTModulusRoot.clear();
	}

	template<typename IntType, typename VecType>
	ChineseRemainderTransformArb<IntType, VecType>& ChineseRemainderTransformArb<IntType, VecType>::GetInstance() {
		if (m_onlyInstance == NULL) {
			m_onlyInstance = new ChineseRemainderTransformArb<IntType, VecType>();//lazy instantiation
		}
		return *m_onlyInstance;
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::SetCylotomicPolynomial(const VecType &poly, const IntType &mod) {
		m_cyclotomicPolyMap[mod] = poly;
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::PreCompute(const usint cyclotoOrder, const IntType &modulus) {
		BluesteinFFT<IntType, VecType>::GetInstance().PreComputeDefaultNTTModulusRoot(cyclotoOrder, modulus);
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::SetPreComputedNTTModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttModulus, const IntType &nttRoot) {
		const ModulusRoot<IntType> nttModulusRoot = { nttModulus, nttRoot };
		BluesteinFFT<IntType, VecType>::GetInstance().PreComputeRootTableForNTT(cyclotoOrder, nttModulusRoot);
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
			rootTable.SetValAtIndex(i, x);
			x = x.ModMul(root, nttMod);
		}

		x = 1;
		for (usint i = 0; i < nttDim / 2; i++) {
			rootTableInverse.SetValAtIndex(i, x);
			x = x.ModMul(rootInv, nttMod);
		}

		m_rootOfUnityDivisionTableByModulus[nttMod] = rootTable;
		m_rootOfUnityDivisionInverseTableByModulus[nttMod] = rootTableInverse;

		//end of part0
		//part1
		const auto &RevCPM = InversePolyMod(m_cyclotomicPolyMap[modulus], modulus, power);
		auto RevCPMPadded = BluesteinFFT<IntType, VecType>::GetInstance().PadZeros(RevCPM, nttDim);
		RevCPMPadded.SetModulus(nttMod);
		//std::cout << RevCPMPadded << std::endl;
		//end of part1

		auto RA = NumberTheoreticTransform<IntType, VecType>::GetInstance().ForwardTransformIterative(RevCPMPadded, rootTable, nttDim);
		m_cyclotomicPolyReverseNTTMap[modulus] = std::move(RA);

		const auto &cycloPoly = m_cyclotomicPolyMap[modulus];

		VecType QForwardTansform(nttDim, nttMod);
		for (usint i = 0; i < cycloPoly.GetLength(); i++) {
			QForwardTansform.SetValAtIndex(i, cycloPoly.GetValAtIndex(i));
		}

		QForwardTansform = NumberTheoreticTransform<IntType, VecType>::GetInstance().ForwardTransformIterative(QForwardTansform, rootTable, nttDim);

		m_cyclotomicPolyNTTMap[modulus] = std::move(QForwardTansform);

		//ChineseRemainderTransformArb<IntType, VecType>::GetInstance().SetRootTableForNTTDivision(cyclotoOrder, modulus, nttMod, nttRoot);
	}

	template<typename IntType, typename VecType>
	VecType ChineseRemainderTransformArb<IntType, VecType>::InversePolyMod(const VecType &cycloPoly, const IntType &modulus, usint power) {

		VecType result(power, modulus);
		usint r = ceil(log2(power));
		VecType h(1, modulus);//h is a unit polynomial
		h.SetValAtIndex(0, 1);

		//Precompute the Barrett mu parameter
		IntType mu = ComputeMu<IntType>(modulus);

		for (usint i = 0; i < r; i++) {
			usint qDegree = std::pow(2, i + 1);
			VecType q(qDegree + 1, modulus);//q = x^(2^i+1)
			q.SetValAtIndex(qDegree, 1);
			auto hSquare = PolynomialMultiplication(h, h);

			auto a = h * IntType(2);
			auto b = PolynomialMultiplication(hSquare, cycloPoly);
			//b = 2h - gh^2
			for (usint j = 0; j < b.GetLength(); j++) {
				if (j < a.GetLength()) {
					b.SetValAtIndex(j, a.GetValAtIndex(j).ModBarrettSub(b.GetValAtIndex(j), modulus, mu));
				}
				else
					b.SetValAtIndex(j, modulus.ModBarrettSub(b.GetValAtIndex(j), modulus, mu));
			}

			h = PolyMod(b, q, modulus);

		}
		//take modulo x^power
		for (usint i = 0; i < power; i++) {
			result.SetValAtIndex(i, h.GetValAtIndex(i));
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
		if (BluesteinFFT<IntType, VecType>::GetInstance().m_rootOfUnityTableByModulusRoot[nttModulusRoot].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
		}

		if (BluesteinFFT<IntType, VecType>::GetInstance().m_powersTableByModulusRoot[modulusRoot].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputePowers(cycloOrder, modulusRoot);
		}

		if(BluesteinFFT<IntType, VecType>::GetInstance().m_RBTableByModulusRootPair[modulusRootPair].GetLength() == 0){
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputeRBTable(cycloOrder, modulusRootPair);
		}
}

		VecType inputToBluestein = Pad(element, cycloOrder, true);
		auto outputBluestein = BluesteinFFT<IntType, VecType>::GetInstance().ForwardTransform(inputToBluestein, root, cycloOrder, nttModulusRoot);
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

		// std::cout << "CRT-ARB-IT: " << modulus << " " << root << " " << nttModulus << " " << nttRoot << std::endl;
#pragma omp critical
{
		if (BluesteinFFT<IntType, VecType>::GetInstance().m_rootOfUnityTableByModulusRoot[nttModulusRoot].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
		}

		if (BluesteinFFT<IntType, VecType>::GetInstance().m_powersTableByModulusRoot[modulusRootInverse].GetLength() == 0) {
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputePowers(cycloOrder, modulusRootInverse);
		}

		if(BluesteinFFT<IntType, VecType>::GetInstance().m_RBTableByModulusRootPair[modulusRootPair].GetLength() == 0){
			BluesteinFFT<IntType, VecType>::GetInstance().PreComputeRBTable(cycloOrder, modulusRootPair);
		}
}

		VecType inputToBluestein = Pad(element, cycloOrder, false);
		auto outputBluestein = BluesteinFFT<IntType, VecType>::GetInstance().ForwardTransform(inputToBluestein, rootInverse, cycloOrder, nttModulusRoot);
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
				inputToBluestein.SetValAtIndex(i, element.GetValAtIndex(i));
			}
		} else { // Inverse transform padding
			auto tList = GetTotientList(cycloOrder);
			usint i = 0;
			for (auto &coprime : tList) {
				inputToBluestein.SetValAtIndex(coprime, element.GetValAtIndex(i++));
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
				output.SetValAtIndex(i, element.GetValAtIndex(tList[i]));
			}
		} else { // Inverse transform drop
			if((n+1) == cycloOrder){
				// cycloOrder is prime: Reduce mod Phi_{n+1}(x)
				// Reduction involves subtracting the coeff of x^n from all terms
				auto coeff_n = element.GetValAtIndex(n);

				//Precompute the Barrett mu parameter
				IntType mu = ComputeMu<IntType>(modulus);

				for (usint i = 0; i < n; i++) {
					output.SetValAtIndex(i, element.GetValAtIndex(i).ModBarrettSub(coeff_n, modulus, mu));
				}
			} else if ((n+1)*2 == cycloOrder){
				// cycloOrder is 2*prime: 2 Step reduction
				// First reduce mod x^(n+1)+1 (=(x+1)*Phi_{2*(n+1)}(x))
				// Subtract co-efficient of x^(i+n+1) from x^(i)

				//Precompute the Barrett mu parameter
				IntType mu = ComputeMu<IntType>(modulus);

				for (usint i = 0; i < n; i++) {
					auto coeff_i = element.GetValAtIndex(i);
					auto coeff_ip = element.GetValAtIndex(i+n+1);
					output.SetValAtIndex(i, coeff_i.ModBarrettSub(coeff_ip, modulus, mu));
				}
				auto coeff_n = element.GetValAtIndex(n).ModBarrettSub(
						element.GetValAtIndex(2*n+1), modulus, mu
					);
				// Now reduce mod Phi_{2*(n+1)}(x)
				// Similar to the prime case but with alternating signs
				for (usint i = 0; i < n; i++) {
					if (i%2 == 0) {
						output.SetValAtIndex(i, output.GetValAtIndex(i).ModBarrettSub(coeff_n, modulus, mu));
					} else {
						output.SetValAtIndex(i, output.GetValAtIndex(i).ModBarrettAdd(coeff_n, modulus, mu));
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
					aPadded2.SetValAtIndex(power - (i - n) - 1, element.GetValAtIndex(i));
				}

				//std::cout << aPadded2 << std::endl;

				auto A = NumberTheoreticTransform<IntType, VecType>::GetInstance().ForwardTransformIterative(aPadded2, rootTable, m_nttDivisionDim[cycloOrder]);
				auto AB = A*m_cyclotomicPolyReverseNTTMap[modulus];
				const auto &rootTableInverse = m_rootOfUnityDivisionInverseTableByModulus[nttMod];
				auto a = NumberTheoreticTransform<IntType, VecType>::GetInstance().InverseTransformIterative(AB, rootTableInverse, m_nttDivisionDim[cycloOrder]);

				VecType quotient(m_nttDivisionDim[cycloOrder], modulus);
				for (usint i = 0; i < power; i++) {
					quotient.SetValAtIndex(i, a.GetValAtIndex(i));
				}
				quotient = quotient.Mod(modulus);
				quotient.SetModulus(nttMod);

				quotient = NumberTheoreticTransform<IntType, VecType>::GetInstance().ForwardTransformIterative(quotient, rootTable, m_nttDivisionDim[cycloOrder]);

				quotient = quotient*m_cyclotomicPolyNTTMap[modulus];

				quotient = NumberTheoreticTransform<IntType, VecType>::GetInstance().InverseTransformIterative(quotient, rootTableInverse, m_nttDivisionDim[cycloOrder]);
				quotient.SetModulus(modulus);
				quotient = quotient.Mod(modulus);

				//Precompute the Barrett mu parameter
				IntType mu = ComputeMu<IntType>(modulus);

				for (usint i = 0; i < n; i++) {
					output.SetValAtIndex(i, element.GetValAtIndex(i).ModBarrettSub(quotient.GetValAtIndex(cycloOrder - 1 - i), modulus, mu));
				}
			}
		}

		return output;
	}

	template<typename IntType, typename VecType>
	void ChineseRemainderTransformArb<IntType, VecType>::Destroy() {
		m_cyclotomicPolyMap.clear();
		m_cyclotomicPolyReverseNTTMap.clear();
		m_cyclotomicPolyNTTMap.clear();
		m_rootOfUnityDivisionTableByModulus.clear();
		m_rootOfUnityDivisionInverseTableByModulus.clear();
		m_DivisionNTTModulus.clear();
		m_DivisionNTTRootOfUnity.clear();
		m_nttDivisionDim.clear();
		BluesteinFFT<IntType, VecType>::GetInstance().Destroy();
	}


	template class ChineseRemainderTransformFTT<BigInteger,BigVector>;
	template class NumberTheoreticTransform<BigInteger,BigVector>;
	template class ChineseRemainderTransformArb<BigInteger, BigVector>;
	template class BluesteinFFT<BigInteger, BigVector>;

#if MATHBACKEND != 7
	template class ChineseRemainderTransformFTT<native_int::BigInteger,native_int::BigVector>;
	template class NumberTheoreticTransform<native_int::BigInteger,native_int::BigVector>;
	template class ChineseRemainderTransformArb<native_int::BigInteger, native_int::BigVector>;
	template class BluesteinFFT<native_int::BigInteger, native_int::BigVector>;
#endif

}//namespace ends here
