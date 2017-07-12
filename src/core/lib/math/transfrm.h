/**
 * @file transfrm.h This file contains the linear transform interface functionality.
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

#ifndef LBCRYPTO_MATH_TRANSFRM_H
#define LBCRYPTO_MATH_TRANSFRM_H


#include "backend.h"
#include "nbtheory.h"
#include "../utils/utilities.h"
#include <chrono>
#include <complex>
#include <time.h>
#include <map>
#include <fstream>
#include <thread>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	/**
	* @brief Generic transform class.
	*/
	class Transform
	{
	public:
		virtual ~Transform() {}
	};

	/**
	* @brief Generic linear transform class.
	*/
	template<typename IntType, typename VecType>
	class LinearTransform : public Transform
	{
	public:
		/**
		* Virtual forward transform.
		*
		* @param &element is the element to perform the transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		virtual VecType ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) = 0;

		/**
		* Virtual inverse transform.
		*
		* @param &element is the element to perform the inverse transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the inverse transform.
		*/
		virtual VecType InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder) = 0;
		//static VecType& ZeroPadd(const VecType&,usint);
	};

	/**
	* @brief Number Theoretic Transform implemetation
	*/
	template<typename IntType, typename VecType>
	class NumberTheoreticTransform
	{
	public:
		/**
		* Get instance to return this object.
		*
		* @return is this object.
		*/
		static NumberTheoreticTransform& GetInstance();

		/**
		* Forward transform.
		*
		* @param element is the element to perform the transform on.
		* @param rootOfUnityTable the root of unity table.
		* @param cycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		VecType ForwardTransformIterative(const VecType& element, const VecType& rootOfUnityTable, const usint cycloOrder);

		/**
		* Inverse transform.
		*
		* @param element is the element to perform the transform on.
		* @param rootOfUnityInverseTable the root of unity table.
		* @param cycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		VecType InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable, const usint cycloOrder);

		/**
		* Set the ring element.
		*
		* @param &element is the element to set.
		*/
		void SetElement(const VecType &element);

		/**
		* Destructor.
		*/
		void Destroy();
	private:
		static NumberTheoreticTransform *m_onlyInstance;
		NumberTheoreticTransform() : m_element(0) {}
		~NumberTheoreticTransform() {}
		NumberTheoreticTransform(const NumberTheoreticTransform&) : m_element(0) {}
		//	NumberTheoreticTransform& operator=(NumberTheoreticTransform const&) {}
		const VecType *m_element;
	};

	/**
	* @brief Chinese Remainder Transform implemetation.  This is a refined, higher performance implementation.
	*/
	template<typename IntType, typename VecType>
	class ChineseRemainderTransform : public LinearTransform<IntType, VecType>
	{
	public:
		/**
		* Get instance to return this object.
		*
		* @return is this object.
		*/
		static ChineseRemainderTransform& GetInstance();

		/**
		* Virtual forward transform.
		*
		* @param &element is the element to perform the transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		VecType ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder);

		/**
		* Virtual inverse transform.
		*
		* @param &element is the element to perform the inverse transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the inverse transform.
		*/
		VecType InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder);

		/**
		* Destructor.
		*/
		void Destroy();
	private:
		static ChineseRemainderTransform *m_onlyInstance;
		static VecType *m_rootOfUnityTable;
		static VecType *m_rootOfUnityInverseTable;
		ChineseRemainderTransform() {}
		~ChineseRemainderTransform() {}
		ChineseRemainderTransform(const ChineseRemainderTransform&) {}
		ChineseRemainderTransform& operator=(ChineseRemainderTransform const&) {};
	};

	/**
	* @brief Golden Chinese Remainder Transform FFT implemetation.
	*/
	template<typename IntType, typename VecType>
	class ChineseRemainderTransformFTT : public LinearTransform<IntType, VecType>
	{
	public:
		/**
		* Get instance to return this object.
		*
		* @return is this object.
		*/
		static ChineseRemainderTransformFTT& GetInstance();
		/**
		* Virtual forward transform.
		*
		* @param &element is the element to perform the transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		VecType ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder);

		/**
		* Virtual inverse transform.
		*
		* @param &element is the element to perform the inverse transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the inverse transform.
		*/
		VecType InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder);

		/**
		* Precomputation of root of unity tables.
		*
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @param modulus is the modulus
		*/
		void PreCompute(const IntType& rootOfUnity, const usint CycloOrder, const IntType &modulus);

		/**
		* Precomputation of root of unity tables.
		*
		* @param &rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @param &moduliiChain is the modulus
		*/
		void PreCompute(std::vector<IntType> &rootOfUnity, const usint CycloOrder, std::vector<IntType> &moduliiChain);
		/**
		* Destructor.
		*/
		void Destroy();

	private:
		static ChineseRemainderTransformFTT *m_onlyInstance;
		static std::map<IntType, VecType> m_rootOfUnityTableByModulus;
		static std::map<IntType, VecType> m_rootOfUnityInverseTableByModulus;
		//static VecType *m_rootOfUnityTable;

		//static VecType *m_rootOfUnityInverseTable;
		//static VecType *m_phiTable;
		//static VecType *m_phiInverseTable;
		ChineseRemainderTransformFTT() {}
		~ChineseRemainderTransformFTT() {}
		ChineseRemainderTransformFTT(const ChineseRemainderTransformFTT<IntType, VecType>&) {}
		//ChineseRemainderTransformFTT& operator=(ChineseRemainderTransformFTT<IntType,VecType> const&){};
	};

	/**
	* @brief Discrete Fourier Transform FFT implemetation.
	*/
	class DiscreteFourierTransform
	{
	public:
		/**
		* Virtual FFT forward transform.
		*
		* @param A is the element to perform the transform on.
		* @return is the output result of the transform.
		*/
		std::vector<std::complex<double>> FFTForwardTransform(std::vector<std::complex<double>>& A);

		/**
		* Virtual FFT inverse transform.
		*
		* @param A is the element to perform the inverse transform on.
		* @return is the output result of the inverse transform.
		*/
		std::vector<std::complex<double>> FFTInverseTransform(std::vector<std::complex<double>>& A);

		/**
		* Virtual forward transform.
		*
		* @param A is the element to perform the transform on.
		* @return is the output result of the transform.
		*/
		std::vector<std::complex<double>> ForwardTransform(std::vector<std::complex<double>> A);

		/**
		* Virtual inverse transform.
		*
		* @param A is the element to perform the inverse transform on.
		* @return is the output result of the inverse transform.
		*/
		std::vector<std::complex<double>> InverseTransform(std::vector<std::complex<double>> A);

		void Destroy();
		void PreComputeTable(uint32_t s);
		static DiscreteFourierTransform& GetInstance();

	private:
		static DiscreteFourierTransform* m_onlyInstance;
		static std::complex<double>* rootOfUnityTable;
		uint32_t size;
	};

	// struct used as a key in BlueStein transform
	template<typename IntType>
	using ModulusRoot = std::pair<IntType, IntType>;

	template<typename IntType>
	using ModulusRootPair = std::pair<ModulusRoot<IntType>, ModulusRoot<IntType>>;

	/**
	* @brief Bluestein Fast Fourier Transform implemetation
	*/
	template<typename IntType, typename VecType>
	class BluesteinFFT {
	public:
		/**
		* Get instance to return this object.
		*
		* @return is this object.
		*/
		static BluesteinFFT& GetInstance();

		/**
		* Forward transform.
		*
		* @param element is the element to perform the transform on.
		* @param rootOfUnityTable the root of unity table.
		* @param cycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		VecType ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder);
		VecType ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder, const ModulusRoot<IntType>& nttModulusRoot);

		/**
		*
		* @param a is the input vector to be padded with zeros.
		* @param finalSize is the length of the output vector.
		* @return output vector padded with (finalSize - initial size)additional zeros.
		*/
		static VecType PadZeros(const VecType &a, const usint finalSize);

		/**
		*
		* @param a is the input vector to be resized.
		* @param lo is lower coefficient index.
		* @param hi is higher coefficient index.
		* @return output vector s.t output vector = a[lo]...a[hi].
		*/
		VecType Resize(const VecType &a, usint  lo, usint hi);

		// void PreComputeNTTModulus(usint cycloOrder, const std::vector<IntType> &modulii);

		/**
		* @brief Precomputes the modulus needed for NTT operation in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial.
		* @param modulus is the modulus of the polynomial.
		*/
		void PreComputeDefaultNTTModulusRoot(usint cycloOrder, const IntType &modulus);

		/**
		* @brief Precomputes the root of unity table needed for NTT operation in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial.
		*/
		void PreComputeRootTableForNTT(usint cycloOrder, const ModulusRoot<IntType> &nttModulusRoot);

		/**
		* @brief precomputes the powers of root used in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		* @param root is the root of unity s.t. root^2m = 1.
		*/
		static void PreComputePowers(usint cycloOrder, const ModulusRoot<IntType> &modulusRoot);

		/**
		* @brief precomputes the NTT transform of the power of root of unity used in the Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		* @param root is the root of unity s.t. root^2m = 1.
		* @param bigMod is the modulus required for the NTT transform.
		* @param bigRoot is the root of unity required for the NTT transform.
		*/
		static void PreComputeRBTable(usint cycloOrder, const ModulusRootPair<IntType> &modulusRootPair);

		/**
		* Destructor.
		*/
		void Destroy();

		//map to store the root of unity table with modulus as key.
		static std::map<ModulusRoot<IntType>, VecType> m_rootOfUnityTableByModulusRoot;

		//map to store the root of unity inverse table with modulus as key.
		static std::map<ModulusRoot<IntType>, VecType> m_rootOfUnityInverseTableByModulusRoot;

		//map to store the power of roots as a table with modulus + root of unity as key.
		static std::map<ModulusRoot<IntType>, VecType> m_powersTableByModulusRoot;

		//map to store the forward transform of power table with modulus + root of unity as key.
		static std::map<ModulusRootPair<IntType>, VecType> m_RBTableByModulusRootPair;

	private:
		//map to store the precomputed NTT modulus with modulus as key.
		static std::map<IntType, ModulusRoot<IntType>> m_defaultNTTModulusRoot;
		//pointer to the class to support sigleton class structure.
		static BluesteinFFT *m_onlyInstance;
		~BluesteinFFT() {}

	};

	/**
	* @brief Chinese Remainder Transform for arbitrary cyclotomics.
	*/
	template<typename IntType, typename VecType>
	class ChineseRemainderTransformArb {
	public:
		/**
		* Get instance to return this object.
		*
		* @return is this object.
		*/
		static ChineseRemainderTransformArb& GetInstance();

		/**
		* Sets the cyclotomic polynomial.
		*
		*/
		static void SetCylotomicPolynomial(const VecType &poly, const IntType &mod);

		/**
		* Forward transform.
		*
		* @param element is the element to perform the transform on.
		* @param root is the 2mth root of unity w.r.t the ring modulus.
		* @param cycloOrder is the cyclotomic order of the ring element.
		* @param bigMod is the addtional modulus needed for NTT operation.
		* @param bigRoot is the addtional root of unity w.r.t bigMod needed for NTT operation.
		* @return is the output result of the transform.
		*/
		VecType ForwardTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot, const usint cycloOrder);

		/**
		* Inverse transform.
		*
		* @param element is the element to perform the transform on.
		* @param root is the 2mth root of unity w.r.t the ring modulus.
		* @param cycloOrder is the cyclotomic order of the ring element.
		* @param bigMod is the addtional modulus needed for NTT operation.
		* @param bigRoot is the addtional root of unity w.r.t bigMod needed for NTT operation.
		* @return is the output result of the transform.
		*/
		VecType InverseTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot, const usint cycloOrder);

		/**
		* Destructor.
		*/
		void Destroy();
		
		/**
		* @brief Precomputes the root of unity and modulus needed for NTT operation in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		*/
		static void PreCompute(const usint cyclotoOrder, const IntType &modulus);

		/**
		* @brief Sets the precomputed root of unity and modulus needed for NTT operation in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		* @param nttMod is the modulus needed for the NTT operation in forward Bluestein transform.
		* @param nttRoot is the root of unity needed for the NTT operation in forward Bluestein transform.
		*/
		static void SetPreComputedNTTModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod, const IntType &nttRoot);
		
		/**
		* @brief Sets the precomputed root of unity and modulus needed for NTT operation and computes m_cyclotomicPolyReveseNTTMap,m_cyclotomicPolyNTTMap.
		* Always called after setting the cyclotomic polynomial.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		* @param nttMod is the modulus needed for the NTT operation in forward Bluestein transform.
		* @param nttRoot is the root of unity needed for the NTT operation in forward Bluestein transform.
		*/
		static void SetPreComputedNTTDivisionModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod, const IntType &nttRoot);

		/**
		* @brief Computes the inverse of the cyclotomic polynomial using Newton-Iteration method.
		* @param cycloPoly is the cyclotomic polynomial.
		* @param modulus is the modulus of the polynomial ring.
		* @return inverse polynomial. 
		*/
		static VecType InversePolyMod(const VecType &cycloPoly, const IntType &modulus, usint power);

	private:
		//pointer to the class to support sigleton class structure.
		static ChineseRemainderTransformArb *m_onlyInstance;
		//destructor
		~ChineseRemainderTransformArb() {}

		VecType Pad(const VecType& element, const usint cycloOrder, bool forward);

		VecType Drop(const VecType& element, const usint cycloOrder, bool forward, const IntType& bigMod, const IntType& bigRoot);

		//map to store the cyclotomic polynomial with polynomial ring's modulus as key.
		static std::map<IntType, VecType> m_cyclotomicPolyMap;

		//map to store the forward NTT transform of the inverse of cyclotomic polynomial with polynomial ring's modulus as key.
		static std::map<IntType, VecType> m_cyclotomicPolyReverseNTTMap;

		//map to store the forward NTT transform of the cyclotomic polynomial with polynomial ring's modulus as key.
		static std::map<IntType, VecType> m_cyclotomicPolyNTTMap;

		//map to store the root of unity table used in NTT based polynomial division.
		static std::map<IntType, VecType> m_rootOfUnityDivisionTableByModulus;

		//map to store the root of unity table for computing forward NTT of inverse cyclotomic polynomial used in NTT based polynomial division.
		static std::map<IntType, VecType> m_rootOfUnityDivisionInverseTableByModulus;

		//modulus used in NTT based polynomial division.
		static std::map<IntType, IntType> m_DivisionNTTModulus;

		//root of unity used in NTT based polynomial division.
		static std::map<IntType, IntType> m_DivisionNTTRootOfUnity;

		//dimension of the NTT transform in NTT based polynomial division.
		static std::map<usint, usint> m_nttDivisionDim;

	};



} // namespace lbcrypto ends

#endif
