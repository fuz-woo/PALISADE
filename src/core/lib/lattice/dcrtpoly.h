/**
 * @file dcrtpoly.h Represents integer lattice elements with double-CRT
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

#ifndef LBCRYPTO_LATTICE_DCRTPOLY_H
#define LBCRYPTO_LATTICE_DCRTPOLY_H

#include <vector>
#include <string>

#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../utils/exception.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"
#include "../lattice/poly.h"
#include "../math/nbtheory.h"
#include "../math/transfrm.h"
#include "../math/distrgen.h"

namespace lbcrypto
{

/**
* @brief Ideal lattice for the double-CRT representation.
* The implementation contains a vector of underlying native-integer lattices
* The double-CRT representation of polynomials is a common optimization for lattice encryption operations.
* Basically, it allows large-modulus polynamials to be represented as multiple smaller-modulus polynomials.
* The double-CRT representations are discussed theoretically here:
*   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology – CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin, Heidelberg
*/
template<typename ModType, typename IntType, typename VecType, typename ParmType>
class DCRTPolyImpl : public ILElement< DCRTPolyImpl<ModType,IntType,VecType,ParmType>,ModType,IntType,VecType>
{
public:
	typedef ParmType Params;
	typedef IntType Integer;
	typedef VecType Vector;

	typedef DCRTPolyImpl<ModType,IntType,VecType,ParmType> DCRTPolyType;
	typedef DiscreteGaussianGeneratorImpl<NativeInteger,NativeVector> DggType;
	typedef DiscreteUniformGeneratorImpl<NativeInteger,NativeVector> DugType;
	typedef TernaryUniformGeneratorImpl<NativeInteger,NativeVector> TugType;
	typedef BinaryUniformGeneratorImpl<NativeInteger,NativeVector> BugType;

	// this class contains an array of these:
	typedef PolyImpl<NativeInteger,NativeInteger,NativeVector,ILNativeParams> PolyType;

	// the composed polynomial type
	typedef PolyImpl<ModType,IntType,VecType,ILParamsImpl<IntType>> PolyLargeType;

	static const std::string GetElementName() {
		return "DCRTPolyImpl";
	}

	// CONSTRUCTORS

	/**
	* @brief Constructor that initialized m_format to EVALUATION and calls m_params to nothing
	*/
	DCRTPolyImpl();

	/**
	* Constructor that initializes parameters.
	*
	*@param params parameter set required for DCRTPoly.
	*@param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*@param initializeElementToZero
	*/
	DCRTPolyImpl(const shared_ptr<ParmType> params, Format format = EVALUATION, bool initializeElementToZero = false);

	const DCRTPolyType& operator=(const PolyLargeType& element);

	/**
	* @brief Constructor based on discrete Gaussian generator.
	*
	* @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the DCRTPoly with random numbers.
	* @param params parameter set required for DCRTPoly.
	* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	DCRTPolyImpl(const DggType &dgg, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	* @brief Constructor based on binary distribution generator. This is not implemented. Will throw a logic_error.
	*
	* @param &bug the input binary uniform generator. The bug will be the seed to populate the towers of the DCRTPoly with random numbers.
	* @param params parameter set required for DCRTPoly.
	* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	DCRTPolyImpl(const BugType &bug, const shared_ptr<ParmType> params, Format format = EVALUATION) {
		throw std::logic_error("Cannot use BinaryUniformGenerator with DCRTPoly; not implemented");
	}

	/**
	* @brief Constructor based on ternary distribution generator.
	*
	* @param &tug the input ternary uniform generator. The bug will be the seed to populate the towers of the DCRTPoly with random numbers.
	* @param params parameter set required for DCRTPoly.
	* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	DCRTPolyImpl(const TugType &tug, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	* @brief Constructor based on discrete uniform generator.
	*
	* @param &dug the input discrete Uniform Generator.
	* @param params the input params.
	* @param &format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	DCRTPolyImpl(DugType &dug, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	* @brief Construct using a single Poly. The Poly is copied into every tower. Each tower will be reduced to it's corresponding modulus  via GetModuli(at tower index). The format is derived from the passed in Poly.
	*
	* @param &element Poly to build other towers from.
	* @param params parameter set required for DCRTPoly.
	*/
	DCRTPolyImpl(const PolyLargeType &element, const shared_ptr<ParmType> params);

	/**
	* @brief Construct using an tower of ILVectro2ns. The params and format for the DCRTPoly will be derived from the towers.
	*
	* @param &towers vector of Polys which correspond to each tower of DCRTPoly.
	*/
	DCRTPolyImpl(const std::vector<PolyType> &elements);

	/**
	* @brief Create lambda that allocates a zeroed element for the case when it is called from a templated class
	* @param params the params to use.
	* @param format - EVALUATION or COEFFICIENT
	*/
	inline static function<unique_ptr<DCRTPolyType>()> MakeAllocator(const shared_ptr<ParmType> params, Format format) {
		return [=]() {
			return lbcrypto::make_unique<DCRTPolyType>(params, format, true);
		};
	}

	/**
	* @brief Allocator for discrete uniform distribution.
	*
	* @param params Params instance that is is passed.
	* @param resultFormat resultFormat for the polynomials generated.
	* @param stddev standard deviation for the discrete gaussian generator.
	* @return the resulting vector.
	*/
	inline static function<unique_ptr<DCRTPolyType>()> MakeDiscreteGaussianCoefficientAllocator(shared_ptr<ParmType> params, Format resultFormat, int stddev) {
		return [=]() {
			DggType dgg(stddev);
			auto ilvec = lbcrypto::make_unique<DCRTPolyType>(dgg, params, COEFFICIENT);
			ilvec->SetFormat(resultFormat);
			return ilvec;
		};
	}

	/**
	* @brief Allocator for discrete uniform distribution.
	*
	* @param params Params instance that is is passed.
	* @param format format for the polynomials generated.
	* @return the resulting vector.
	*/
	inline static function<unique_ptr<DCRTPolyType>()> MakeDiscreteUniformAllocator(shared_ptr<ParmType> params, Format format) {
		return [=]() {
			DugType dug;
			return lbcrypto::make_unique<DCRTPolyType>(dug, params, format);
		};
	}


	/**
	* @brief Copy constructor.
	*
	* @param &element DCRTPoly to copy from
	*/
	DCRTPolyImpl(const DCRTPolyType &element);

	/**
	* @brief Move constructor.
	*
	* @param &&element DCRTPoly to move from
	*/
	DCRTPolyImpl(const DCRTPolyType &&element);

	//CLONE OPERATIONS
	/**
	 * @brief Clone the object by making a copy of it and returning the copy
	 * @return new Element
	 */
	DCRTPolyType Clone() const {
		return std::move(DCRTPolyImpl(*this));
	}

	/**
	 * @brief Clone the object, but have it contain nothing
	 * @return new Element
	 */
	DCRTPolyType CloneEmpty() const {
		return std::move( DCRTPolyImpl() );
	}

	/**
	* @brief Clone method creates a new DCRTPoly and clones only the params. The tower values are empty. The tower values can be filled by another process/function or initializer list.
	*/
	DCRTPolyType CloneParametersOnly() const;

	/**
	* @brief Clone with noise.  This method creates a new DCRTPoly and clones the params. The tower values will be filled up with noise based on the discrete gaussian.
	*
	* @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the DCRTPoly with random numbers.
	* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
	*/
	DCRTPolyType CloneWithNoise(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, Format format = EVALUATION) const;

	/**
	* @brief Destructor.
	*/
	~DCRTPolyImpl();

	//GETTERS

	/**
	 * @brief returns the parameters of the element.
	 * @return the element parameter set.
	 */
	const shared_ptr<ParmType> GetParams() const {
		return m_params;
	}

	/**
	 * @brief returns the element's cyclotomic order
	 * @return returns the cyclotomic order of the element.
	 */
	const usint GetCyclotomicOrder() const {
		return m_params->GetCyclotomicOrder();
	}

	/**
	 * @brief returns the element's ring dimension
	 * @return returns the ring dimension of the element.
	 */
	const usint GetRingDimension() const {
		return m_params->GetRingDimension();
	}

	/**
	 * @brief returns the element's modulus
	 * @return returns the modulus of the element.
	 */
	const ModType &GetModulus() const {
		return m_params->GetModulus();
	}

	/**
	 * @brief returns the element's root of unity.
	 * @return the element's root of unity.
	 */
	const IntType &GetRootOfUnity() const {
		static IntType t(0);
		return t;
	}

	/**
	* @brief Get method for length of each component element.
	* NOTE assumes all components are the same size.
	*
	* @return length of the component element
	*/
	usint GetLength() const {
		if( m_vectors.size() == 0 )
			return 0;

		return m_vectors[0].GetValues().GetLength();
	}

	/**
	* @brief Get method of individual compoment elements.
	*
	* @param i index of component element to be returned.
	* @returns a reference to the component element at index i.
	*/
	const PolyType &GetElementAtIndex(usint i) const;

	/**
	* @brief Get method of the number of component elements, also known as the number of towers.
	*
	* @return the number of component elements.
	*/
	usint GetNumOfElements() const;

	/**
	* @brief Get method that returns a vector of all component elements.
	*
	* @returns a vector of the component elements.
	*/
	const std::vector<PolyType>& GetAllElements() const;

	/**
	* @brief Get method of the format.
	*
	* @return the format, either COEFFICIENT or EVALUATION
	*/
	Format GetFormat() const;

	/**
	 * @brief Write the element as \f$ \sum\limits{i=0}^{\lfloor {\log q/base} \rfloor} {(base^i u_i)} \f$ and
	 * return the vector of \f$ \left\{u_0, u_1,...,u_{\lfloor {\log q/base} \rfloor} \right\} \in R_{{base}^{\lceil {\log q/base} \rceil}} \f$;
	 * This is used as a subroutine in the relinearization procedure.
	 *
	 * @param baseBits is the number of bits in the base, i.e., \f$ base = 2^{baseBits} \f$.
	 * @return is the pointer where the base decomposition vector is stored
	 */
	std::vector<DCRTPolyType> BaseDecompose(usint baseBits, bool evalModeAnswer=true) const ;

	/**
	 * @brief Generate a vector of PolyImpl's as \f$ \left\{x, {base}*x, {base}^2*x, ..., {base}^{\lfloor {\log q/{base}} \rfloor} \right\}*x \f$,
	 * where \f$ x \f$ is the current PolyImpl object;
	 * used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element.
	 *
	 * @param baseBits is the number of bits in the base, i.e., \f$ base = 2^{baseBits} \f$.
	 * @return is the pointer where the base decomposition vector is stored
	 */
	std::vector<DCRTPolyType> PowersOfBase(usint baseBits) const ;

	/**
	 * CRT basis decomposition of c as [c qi/q]_qi
	 *
	 * @param &qDivqiInverse precomputed table of [qi_q]_qi
	 * @return is the pointer where the resulting vector is stored
	 */
	std::vector<DCRTPolyType> CRTDecompose(const std::vector<NativeInteger> &qDivqiInverse) const;

	//VECTOR OPERATIONS

	/**
	* @brief Assignment Operator.
	*
	* @param &rhs the copied element.
	* @return the resulting element.
	*/
	const DCRTPolyType& operator=(const DCRTPolyType &rhs);

	/**
	* @brief Move Assignment Operator.
	*
	* @param &rhs the copied element.
	* @return the resulting element.
	*/
	const DCRTPolyType& operator=(DCRTPolyType &&rhs);

	/**
	* @brief Initalizer list
	*
	* @param &rhs the list to initalized the element.
	* @return the resulting element.
	*/
	DCRTPolyType& operator=(std::initializer_list<uint64_t> rhs);

	/**
	* @brief Assignment Operator. The usint val will be set at index zero and all other indices will be set to zero.
	*
	* @param val is the usint to assign to index zero.
	* @return the resulting vector.
	*/
	DCRTPolyType& operator=(uint64_t val);

	/**
	* @brief Creates a Poly from a vector of signed integers (used for trapdoor sampling)
	*
	* @param &rhs the vector to set the PolyImpl to.
	* @return the resulting PolyImpl.
	*/
	DCRTPolyType& operator=(std::vector<int64_t> rhs);

	/**
	* @brief Creates a Poly from a vector of signed integers (used for trapdoor sampling)
	*
	* @param &rhs the vector to set the PolyImpl to.
	* @return the resulting PolyImpl.
	*/
	DCRTPolyType& operator=(std::vector<int32_t> rhs);

	/**
	 * @brief Unary minus on a element.
	 * @return additive inverse of the an element.
	 */
	DCRTPolyType operator-() const {
		DCRTPolyType all0(this->GetParams(), this->GetFormat(), true);
		return all0 - *this;
	}

	/**
	* @brief Equality operator.
	*
	* @param &rhs is the specified element to be compared with this element.
	* @return true if this element represents the same values as the specified element, false otherwise
	*/
	bool operator==(const DCRTPolyType &rhs) const;

	/**
	* @brief Performs an entry-wise addition over all elements of each tower with the towers of the element on the right hand side.
	*
	* @param &rhs is the element to add with.
	* @return is the result of the addition.
	*/
	const DCRTPolyType& operator+=(const DCRTPolyType &rhs);

	/**
	* @brief Performs an entry-wise subtraction over all elements of each tower with the towers of the element on the right hand side.
	*
	* @param &rhs is the element to subtract from.
	* @return is the result of the addition.
	*/
	const DCRTPolyType& operator-=(const DCRTPolyType &rhs);

	/**
	* @brief Permutes coefficients in a polynomial. Moves the ith index to the first one, it only supports odd indices.
	*
	* @param &i is the element to perform the automorphism transform with.
	* @return is the result of the automorphism transform.
	*/
	DCRTPolyType AutomorphismTransform(const usint &i) const {
		DCRTPolyType result(*this);
		for (usint k = 0; k < m_vectors.size(); k++) {
			result.m_vectors[k] = m_vectors[k].AutomorphismTransform(i);
		}
		return result;
	}

	/**
	* @brief Transpose the ring element using the automorphism operation
	*
	* @return is the result of the transposition.
	*/
	DCRTPolyType Transpose() const {
	
		if (m_format == COEFFICIENT)
			throw std::logic_error("DCRTPolyImpl element transposition is currently implemented only in the Evaluation representation.");
		else {
			usint m = m_params->GetCyclotomicOrder();
			return AutomorphismTransform(m - 1);
		}

	}

	/**
	* @brief Performs an addition operation and returns the result.
	*
	* @param &element is the element to add with.
	* @return is the result of the addition.
	*/
	DCRTPolyType Plus(const DCRTPolyType &element) const;

	/**
	* @brief Performs a multiplication operation and returns the result.
	*
	* @param &element is the element to multiply with.
	* @return is the result of the multiplication.
	*/
	DCRTPolyType Times(const DCRTPolyType &element) const;

	/**
	* @brief Performs a subtraction operation and returns the result.
	*
	* @param &element is the element to subtract from.
	* @return is the result of the subtraction.
	*/
	DCRTPolyType Minus(const DCRTPolyType &element) const;

	//SCALAR OPERATIONS

	/**
	* @brief Scalar addition - add an element to the first index of each tower.
	*
	* @param &element is the element to add entry-wise.
	* @return is the result of the addition operation.
	*/
	DCRTPolyType Plus(const IntType &element) const;

	/**
	* @brief Scalar subtraction - subtract an element to all entries.
	*
	* @param &element is the element to subtract entry-wise.
	* @return is the return value of the minus operation.
	*/
	DCRTPolyType Minus(const IntType &element) const;

	/**
	* @brief Scalar multiplication - multiply all entries.
	*
	* @param &element is the element to multiply entry-wise.
	* @return is the return value of the times operation.
	*/
	DCRTPolyType Times(const IntType &element) const;

	/**
	* @brief Scalar multiplication by an integer represented in CRT Basis.
	*
	* @param &element is the element to multiply entry-wise.
	* @return is the return value of the times operation.
	*/
	DCRTPolyType Times(const std::vector<NativeInteger> &element) const;

	/**
	* @brief Scalar multiplication followed by division and rounding operation - operation on all entries.
	*
	* @param &p is the element to multiply entry-wise.
	* @param &q is the element to divide entry-wise.
	* @return is the return value of the multiply, divide and followed by rounding operation.
	*/
	DCRTPolyType MultiplyAndRound(const IntType &p, const IntType &q) const;

	/**
	* @brief Scalar division followed by rounding operation - operation on all entries.
	*
	* @param &q is the element to divide entry-wise.
	* @return is the return value of the divide, followed by rounding operation.
	*/
	DCRTPolyType DivideAndRound(const IntType &q) const;

	/**
	* @brief Performs a negation operation and returns the result.
	*
	* @return is the result of the negation.
	*/
	DCRTPolyType Negate() const;

	const DCRTPolyType& operator+=(const IntType &element) {
		return *this = Plus(element);
	}

	/**
	* @brief Performs a subtraction operation and returns the result.
	*
	* @param &element is the element to subtract from.
	* @return is the result of the subtraction.
	*/
	const DCRTPolyType& operator-=(const IntType &element) {
		return *this = Minus(element);
	}

	/**
	* @brief Performs a multiplication operation and returns the result.
	*
	* @param &element is the element to multiply by.
	* @return is the result of the subtraction.
	*/
	const DCRTPolyType& operator*=(const IntType &element);

	/**
	* @brief Performs an multiplication operation and returns the result.
	*
	* @param &element is the element to multiply with.
	* @return is the result of the multiplication.
	*/
	const DCRTPolyType& operator*=(const DCRTPolyType &element);

	// multiplicative inverse operation
	/**
	* @brief Performs a multiplicative inverse operation and returns the result.
	*
	* @return is the result of the multiplicative inverse.
	*/
	DCRTPolyType MultiplicativeInverse() const;

	/**
	* @brief Perform a modulus by 2 operation.  Returns the least significant bit.
	*
	* @return is the resulting value.
	*/
	DCRTPolyType ModByTwo() const;

	/**
	* @brief Modulus - perform a modulus operation. Does proper mapping of [-modulus/2, modulus/2) to [0, modulus)
	*
	* @param modulus is the modulus to use.
	* @return is the return value of the modulus.
	*/
	DCRTPolyType Mod(const IntType &modulus) const {
		throw std::logic_error("Mod of an IntType not implemented on DCRTPoly");
	}

	// OTHER FUNCTIONS AND UTILITIES

	/**
	* @brief Get method that should not be used
	*
	* @return will throw a logic_error
	*/
	const VecType &GetValues() const {
		throw std::logic_error("GetValues not implemented on DCRTPoly");
	}

	/**
	* @brief Set method that should not be used, will throw an error.
	*
	* @param &values
	* @param format
	*/
	void SetValues(const VecType &values, Format format) {
		throw std::logic_error("SetValues not implemented on DCRTPoly");
	}

	/**
	* @brief Sets element at index
	*
	* @param index where the element should be set
	*/
	void SetElementAtIndex(usint index,const PolyType &element){
		m_vectors[index] = element;
	}

	/**
	* @brief Sets all values of element to zero.
	*/
	void SetValuesToZero();

	/**
	* @brief Adds "1" to every entry in every tower.
	*/
	void AddILElementOne();

	/**
	* @brief Add uniformly random values to all components except for the first one
	*/
	DCRTPolyType AddRandomNoise(const IntType &modulus) const {
		throw std::logic_error("AddRandomNoise is not currently implemented for DCRTPoly");
	}

	/**
	* @brief Make DCRTPoly Sparse. Sets every index of each tower not equal to zero mod the wFactor to zero.
	*
	* @param &wFactor ratio between the sparse and none-sparse values.
	*/
	void MakeSparse(const uint32_t &wFactor);

	/**
	* @brief Performs Poly::Decompose on each tower and adjusts the DCRTPoly.m_parameters accordingly. This method also reduces the ring dimension by half.
	*/
	void Decompose();

	/**
	* @brief Returns true if ALL the tower(s) are empty.
	* @return true if all towers are empty
	*/
	bool IsEmpty() const;

	/**
	* @brief Drops the last element in the double-CRT representation. The resulting DCRTPoly element will have one less tower.
	*/
	void DropLastElement();

	/**
	* @brief ModReduces reduces the DCRTPoly element's composite modulus by dropping the last modulus from the chain of moduli as well as dropping the last tower.
	*
	* @param plaintextModulus is the plaintextModulus used for the DCRTPoly
	*/
	void ModReduce(const IntType &plaintextModulus);

	/**
	* @brief Interpolates the DCRTPoly to an Poly based on the Chinese Remainder Transform Interpolation.
	* and then returns a Poly with that single element
	*
	* @return the interpolated ring element as a Poly object.
	*/
	PolyLargeType CRTInterpolate() const;

	NativePoly DecryptionCRTInterpolate(PlaintextModulus ptm) const;

	/**
	* @brief Computes Round(p/q*x) mod p as [\sum_i x_i*alpha_i + Round(\sum_i x_i*beta_i)] mod p for fast rounding in RNS;
	* used in the decryption of BFVrns
	*
	* @param &p 64-bit integer (often corresponds to the plaintext modulus)
	* @param &alpha a vector of precomputed integer factors mod p - for each q_i
	* @param &beta a vector of precomputed floating-point factors between 0 and 1 - for each q_i
	* @return the result of computation as a polynomial with native 64-bit coefficients
	*/
	PolyType ScaleAndRound(const typename PolyType::Integer &p, const std::vector<typename PolyType::Integer> &alpha,
			const std::vector<double> &beta) const;

	/**
	* @brief Switches polynomial from one CRT basis Q = q1*q2*...*qn to another CRT basis S = s1*s2*...*sn
	*
	* @param &params parameters for the CRT basis S
	* @param &qInvModqi a vector of precomputed integer factors (q/qi)^{-1} mod qi for all qi
	* @param &qDivqiModsi a matrix of precomputed integer factors (q/qi)^{-1} mod si for all si, qi combinations
	* @param &qModsi a vector of precomputed integer factors q mod si for all si
	* @return the polynomial in the CRT basis S
	*/
	DCRTPolyType SwitchCRTBasis(const shared_ptr<ParmType> params, const std::vector<typename PolyType::Integer> &qInvModqi,
			const std::vector<std::vector<typename PolyType::Integer>> &qDivqiModsi, const std::vector<typename PolyType::Integer> &qModsi) const;

	/**
	* @brief Expands polynomial in CRT basis Q = q1*q2*...*qn to a larger CRT basis Q*S, where S = s1*s2*...*sn;
	* uses SwtichCRTBasis as a subroutine; the result is in evaluation representation
	*
	* @param &paramsQS parameters for the expanded CRT basis Q*S
	* @param &params parameters for the CRT basis S
	* @param &qInvModqi a vector of precomputed integer factors (q/qi)^{-1} mod qi for all qi
	* @param &qDivqiModsi a matrix of precomputed integer factors (q/qi)^{-1} mod si for all si, qi combinations
	* @param &qModsi a vector of precomputed integer factors q mod si for all si
	*/
	void ExpandCRTBasis(const shared_ptr<ParmType> paramsQS, const shared_ptr<ParmType> params, const std::vector<typename PolyType::Integer> &qInvModqi,
			const std::vector<std::vector<typename PolyType::Integer>> &qDivqiModsi, const std::vector<typename PolyType::Integer> &qModsi);

	/**
	* @brief Computes Round(p/Q*x), where x is in the CRT basis Q*S,
	* as [\sum_{i=1}^n alpha_i*x_i + Round(\sum_{i=1}^n beta_i*x_i)]_si,
	* with the result in the Q CRT basis; used in homomorphic multiplication of BFVrns
	*
	* @param &params parameters for the CRT basis Q
	* @param &alpha a matrix of precomputed integer factors = {Floor[p*S*[(Q*S/vi)^{-1}]_{vi}/vi]}_si; for all combinations of vi, si; where vi is a prime modulus in Q*S
	* @param &beta a vector of precomputed floating-point factors between 0 and 1 = [p*S*(Q*S/vi)^{-1}]_{vi}/vi; - for each vi
	* @return the result of computation as a polynomial in the CRT basis Q
	*/
	DCRTPolyType ScaleAndRound(const shared_ptr<ParmType> params,
			const std::vector<std::vector<typename PolyType::Integer>> &alpha,
			const std::vector<double> &beta) const;

	/**
	* @brief Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
	*/
	void SwitchFormat();

	/**
	* @brief Switch modulus and adjust the values
	*
	* @param &modulus is the modulus to be set
	* @param &rootOfUnity is the corresponding root of unity for the modulus
	* @param &modulusArb is the modulus used for arbitrary cyclotomics CRT
	* @param &rootOfUnityArb is the corresponding root of unity for the modulus
	* ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus
	*/
	void SwitchModulus(const IntType &modulus, const IntType &rootOfUnity, const IntType &modulusArb = IntType(0), const IntType &rootOfUnityArb = IntType(0)) {
		throw std::logic_error("SwitchModulus not implemented on DCRTPoly");
	}

	/**
	* @brief Switch modulus at tower i and adjust the values
	*
	* @param index is the index for the tower
	* @param &modulus is the modulus to be set
	* @param &rootOfUnity is the corresponding root of unity for the modulus
	* ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus
	*/
	void SwitchModulusAtIndex(usint index, const IntType &modulus, const IntType &rootOfUnity);

	/**
	* @brief Determines if inverse exists
	*
	* @return is the Boolean representation of the existence of multiplicative inverse.
	*/
	bool InverseExists() const;

	/**
	* @brief Returns the infinity norm, basically the largest value in the ring element.
	*
	* @return is the largest value in the ring element.
	*/
	double Norm() const;

	//JSON FACILITY
	/**
	* @brief Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
	* Invokes nested serialization of Vector.
	*
	* @param serializationMap stores this object's serialized attribute name value pairs.
	* @return true on success
	*/
	bool Serialize(Serialized* serObj) const;

	/**
	* @brief Populate the object from the deserialization of the Setialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	bool Deserialize(const Serialized& serObj);

	/**
	 * @brief ostream operator
	 * @param os the input preceding output stream
	 * @param vec the element to add to the output stream.
	 * @return a resulting concatenated output stream
	 */
	friend inline std::ostream& operator<<(std::ostream& os, const DCRTPolyType& vec) {
		for( usint i=0; i<vec.GetAllElements().size(); i++ ) {
			os << i << ": ";
			os << vec.GetAllElements()[i] << std::endl;
		}
		return os;
	}
	/**
	 * @brief Element-element addition operator.
	 * @param a first element to add.
	 * @param b second element to add.
	 * @return the result of the addition operation.
	 */
	friend inline DCRTPolyType operator+(const DCRTPolyType &a, const DCRTPolyType &b) {
		return a.Plus(b);
	}
	/**
	 * @brief Element-integer addition operator.
	 * @param a first element to add.
	 * @param b integer to add.
	 * @return the result of the addition operation.
	 */
	friend inline DCRTPolyType operator+(const DCRTPolyType &a, const IntType &b) {
		return a.Plus(b);
	}
	
	/**
	 * @brief Integer-element addition operator.
	 * @param a integer to add.
	 * @param b element to add.
	 * @return the result of the addition operation.
	 */
	friend inline DCRTPolyType operator+(const IntType &a, const DCRTPolyType &b) {
		return b.Plus(a);
	}
	
	/**
	 * @brief Element-element subtraction operator.
	 * @param a element to subtract from.
	 * @param b element to subtract.
	 * @return the result of the subtraction operation.
	 */
	friend inline DCRTPolyType operator-(const DCRTPolyType &a, const DCRTPolyType &b) {
		return a.Minus(b);
	}
	
	/**
	 * @brief Element-integer subtraction operator.
	 * @param a element to subtract from.
	 * @param b integer to subtract.
	 * @return the result of the subtraction operation.
	 */
	friend inline DCRTPolyType operator-(const DCRTPolyType &a, const IntType &b) {
		return a.Minus(b);
	}
	
	/**
	 * @brief Element-element multiplication operator.
	 * @param a element to multiply.
	 * @param b element to multiply.
	 * @return the result of the multiplication operation.
	 */
	friend inline DCRTPolyType operator*(const DCRTPolyType &a, const DCRTPolyType &b) {
		return a.Times(b);
	}
	
	/**
	 * @brief Element-integer multiplication operator.
	 * @param a element to multiply.
	 * @param b integer to multiply.
	 * @return the result of the multiplication operation.
	 */
	friend inline DCRTPolyType operator*(const DCRTPolyType &a, const IntType &b) {
		return a.Times(b);
	}
	
	/**
	 * @brief Integer-element multiplication operator.
	 * @param a integer to multiply.
	 * @param b element to multiply.
	 * @return the result of the multiplication operation.
	 */
	friend inline DCRTPolyType operator*(const IntType &a, const DCRTPolyType &b) {
		return b.Times(a);
	}

private:
	shared_ptr<ParmType> m_params;

	// array of vectors used for double-CRT presentation
	std::vector<PolyType> m_vectors;

	// Either Format::EVALUATION (0) or Format::COEFFICIENT (1)
	Format m_format;
};
} // namespace lbcrypto ends

namespace lbcrypto
{

typedef DCRTPolyImpl<BigInteger, BigInteger, BigVector, ILDCRTParams<BigInteger>> DCRTPoly;

}



#endif
