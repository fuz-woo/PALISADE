/*
* @file bfv-dcrtpoly-impl.cpp - dcrtpoly implementation for the BFV scheme.
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

#include "cryptocontext.h"
#include "bfvrns.cpp"

namespace lbcrypto {

// Precomputation of CRT tables encryption, decryption, and homomorphic multiplication
template <>
bool LPCryptoParametersBFVrns<DCRTPoly>::PrecomputeCRTTables(){

	// read values for the CRT basis

	size_t size = GetElementParams()->GetParams().size();
	size_t n = GetElementParams()->GetRingDimension();

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);
	for (size_t i = 0; i < size; i++){
		moduli[i] = GetElementParams()->GetParams()[i]->GetModulus();
		roots[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
	}

	// computes the auxiliary CRT basis S=s1*s2*..sn used in homomorphic multiplication

	size_t sizeS = size + 1;

	vector<NativeInteger> moduliS(sizeS);
	vector<NativeInteger> rootsS(sizeS);

	moduliS[0] = NextPrime<NativeInteger>(moduli[size-1], 2 * n);
	rootsS[0] = RootOfUnity<NativeInteger>(2 * n, moduliS[0]);

	for (size_t i = 1; i < sizeS; i++)
	{
		moduliS[i] = NextPrime<NativeInteger>(moduliS[i-1], 2 * n);
		rootsS[i] = RootOfUnity<NativeInteger>(2 * n, moduliS[i]);
	}

	m_paramsS = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(2 * n, moduliS, rootsS));

	// stores the parameters for the auxiliary expanded CRT basis Q*S = v1*v2*...*vn used in homomorphic multiplication

	vector<NativeInteger> moduliExpanded(size + sizeS);
	vector<NativeInteger> rootsExpanded(size + sizeS);

	// populate moduli for CRT basis Q
	for (size_t i = 0; i < size; i++ ) {
		moduliExpanded[i] = moduli[i];
		rootsExpanded[i] = roots[i];
	}

	// populate moduli for CRT basis S
	for (size_t i = 0; i < sizeS; i++ ) {
		moduliExpanded[size + i] = moduliS[i];
		rootsExpanded[size + i] = rootsS[i];
	}

	m_paramsQS = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(2 * n, moduliExpanded, rootsExpanded));

	//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used in decryption

	std::vector<double> CRTDecryptionFloatTable(size);

	const BigInteger modulusQ = GetElementParams()->GetModulus();

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduli[i].ConvertToInt());
		CRTDecryptionFloatTable[i] = ((modulusQ.DividedBy(qi)).ModInverse(qi) * BigInteger(GetPlaintextModulus())).Mod(qi).ConvertToDouble()/qi.ConvertToDouble();
	}

	m_CRTDecryptionFloatTable = CRTDecryptionFloatTable;

	//compute the table of integer factors floor[(p*[(Q/qi)^{-1}]_qi)/qi]_p - used in decryption

	std::vector<NativeInteger> qDecryptionInt(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		BigInteger quotient = (divBy.ModInverse(qi))*BigInteger(GetPlaintextModulus())/qi;
		qDecryptionInt[vi] = quotient.Mod(GetPlaintextModulus()).ConvertToInt();
	}

	m_CRTDecryptionIntTable = qDecryptionInt;

	//compute the CRT delta table floor(Q/p) mod qi - used for encryption

	const BigInteger deltaBig = modulusQ.DividedBy(GetPlaintextModulus());

	std::vector<NativeInteger> CRTDeltaTable(size);

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduli[i].ConvertToInt());
		BigInteger deltaI = deltaBig.Mod(qi);
		CRTDeltaTable[i] = NativeInteger(deltaI.ConvertToInt());
	}

	m_CRTDeltaTable = CRTDeltaTable;

	//compute the (Q/qi)^{-1} mod qi table - used for homomorphic multiplication and key switching

	std::vector<NativeInteger> qInv(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		qInv[vi] = divBy.ModInverse(qi).Mod(qi).ConvertToInt();
	}

	m_CRTInverseTable = qInv;

	//compute the (Q/qi) mod qi table - used for key switching

	std::vector<NativeInteger> qDivqi(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		qDivqi[vi] = divBy.Mod(qi).ConvertToInt();
	}

	m_CRTqDivqiTable = qDivqi;

	// compute the (Q/qi) mod si table - used for homomorphic multiplication

	std::vector<std::vector<NativeInteger>> qDivqiModsi(sizeS);
	for( usint newvIndex = 0 ; newvIndex < sizeS; newvIndex++ ) {
		BigInteger si = BigInteger(moduliS[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < size; vIndex++ ) {
			BigInteger qi = BigInteger(moduli[vIndex].ConvertToInt());
			BigInteger divBy = modulusQ / qi;
			qDivqiModsi[newvIndex].push_back(divBy.Mod(si).ConvertToInt());
		}
	}

	m_CRTqDivqiModsiTable = qDivqiModsi;

	// compute the Q mod si table - used for homomorphic multiplication

	std::vector<NativeInteger> qModsi(sizeS);
	for( usint vi = 0 ; vi < sizeS; vi++ ) {
		BigInteger si = BigInteger(moduliS[vi].ConvertToInt());
		qModsi[vi] = modulusQ.Mod(si).ConvertToInt();
	}

	m_CRTqModsiTable = qModsi;

	// compute the [p*S*(Q*S/vi)^{-1}]_vi / vi table - used for homomorphic multiplication

	std::vector<double> precomputedDCRTMultFloatTable(size + sizeS);

	const BigInteger modulusS = m_paramsS->GetModulus();
	const BigInteger modulusQS = m_paramsQS->GetModulus();

	const BigInteger modulusP( GetPlaintextModulus() );

	for (size_t i = 0; i < size + sizeS; i++){
		BigInteger qi = BigInteger(moduliExpanded[i].ConvertToInt());
		precomputedDCRTMultFloatTable[i] =
				((modulusQS.DividedBy(qi)).ModInverse(qi)*modulusS*modulusP).Mod(qi).ConvertToDouble()/qi.ConvertToDouble();
	}

	m_CRTMultFloatTable = precomputedDCRTMultFloatTable;

	// compute the floor[p*S*[(Q*S/vi)^{-1}]_vi/vi] mod si table - used for homomorphic multiplication

	std::vector<std::vector<NativeInteger>> multInt(size+sizeS);
	for( usint newvIndex = 0 ; newvIndex < sizeS; newvIndex++ ) {
		BigInteger si = BigInteger(moduliS[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < size+sizeS; vIndex++ ) {
			BigInteger qi = BigInteger(moduliExpanded[vIndex].ConvertToInt());
			BigInteger num = modulusP*modulusS*((modulusQS.DividedBy(qi)).ModInverse(qi));
			BigInteger divBy = num / qi;
			multInt[vIndex].push_back(divBy.Mod(si).ConvertToInt());
		}
	}

	m_CRTMultIntTable = multInt;

	// compute the (S/si)^{-1} mod si table - used for homomorphic multiplication

	std::vector<NativeInteger> sInv(sizeS);
	for( usint vi = 0 ; vi < sizeS; vi++ ) {
		BigInteger si = BigInteger(moduliS[vi].ConvertToInt());
		BigInteger divBy = modulusS / si;
		sInv[vi] = divBy.ModInverse(si).Mod(si).ConvertToInt();
	}

	m_CRTSInverseTable = sInv;

	// compute (S/si) mod qi table - used for homomorphic multiplication

	std::vector<std::vector<NativeInteger>> sDivsiModqi(size);
	for( usint newvIndex = 0 ; newvIndex < size; newvIndex++ ) {
		BigInteger qi = BigInteger(moduli[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < sizeS; vIndex++ ) {
			BigInteger si = BigInteger(moduliS[vIndex].ConvertToInt());
			BigInteger divBy = modulusS / si;
			sDivsiModqi[newvIndex].push_back(divBy.Mod(qi).ConvertToInt());
		}
	}

	m_CRTsDivsiModqiTable = sDivsiModqi;

	// compute S mod qi table - used for homomorphic multiplication

	std::vector<NativeInteger> sModqi(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		sModqi[vi] = modulusS.Mod(qi).ConvertToInt();
	}

	m_CRTsModqiTable = sModqi;

	return true;

}

// Parameter generation for BFV-RNS
template <>
bool LPAlgorithmParamsGenBFVrns<DCRTPoly>::ParamsGen(shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount) const
{

	if (!cryptoParams)
		return false;

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoParams);

	double sigma = cryptoParamsBFVrns->GetDistributionParameter();
	double alpha = cryptoParamsBFVrns->GetAssuranceMeasure();
	double hermiteFactor = cryptoParamsBFVrns->GetSecurityLevel();
	double p = cryptoParamsBFVrns->GetPlaintextModulus();

	//bits per prime modulus
	size_t dcrtBits = 45;

	//Bound of the Gaussian error polynomial
	double Berr = sigma*sqrt(alpha);

	//Bound of the key polynomial
	double Bkey;

	//supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParamsBFVrns->GetMode() == RLWE)
		Bkey = sigma*sqrt(alpha);
	else
		Bkey = 1;

	//expansion factor delta
	auto delta = [](uint32_t n) -> double { return sqrt(n); };

	//norm of fresh ciphertext polynomial
	auto Vnorm = [&](uint32_t n) -> double { return Berr*(1+2*delta(n)*Bkey);  };

	//RLWE security constraint
	auto nRLWE = [&](double q) -> double { return log2(q / sigma) / (4 * log2(hermiteFactor));  };

	//initial values
	uint32_t n = 512;
	double q = 0;

	//only public key encryption and EvalAdd (optional when evalAddCount = 0) operations are supported
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	if ((evalMultCount == 0) && (keySwitchCount == 0)) {

		//Correctness constraint
		auto qBFV = [&](uint32_t n) -> double { return p*(2*((evalAddCount+1)*Vnorm(n) + evalAddCount*p) + p);  };

		//initial value
		q = qBFV(n);

		while (nRLWE(q) > n) {
			n = 2 * n;
			q = qBFV(n);
		}

	}
	// this case supports re-encryption and automorphism w/o any other operations
	else if ((evalMultCount == 0) && (keySwitchCount > 0) && (evalAddCount == 0)) {

		//base for relinearization
		double w = pow(2, dcrtBits);

		//Correctness constraint
		auto qBFV = [&](uint32_t n, double qPrev) -> double { return p*(2*(Vnorm(n) + keySwitchCount*delta(n)*(floor(log2(qPrev) / dcrtBits) + 1)*w*Berr) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qBFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q
		//changes the requirement for n, which is rare but still theortically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				qPrev = q;
			}

			q = qBFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qBFV(n, qPrev);
			}

		}

	}
	//Only EvalMult operations are used in the correctness constraint
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	else if ((evalAddCount == 0) && (evalMultCount > 0) && (keySwitchCount == 0))
	{

		//base for relinearization
		double w = pow(2, dcrtBits);

		//function used in the EvalMult constraint
		auto epsilon1 = [&](uint32_t n) -> double { return 4 / (delta(n)*Bkey);  };

		//function used in the EvalMult constraint
		auto C1 = [&](uint32_t n) -> double { return (1 + epsilon1(n))*delta(n)*delta(n)*p*Bkey;  };

		//function used in the EvalMult constraint
		auto C2 = [&](uint32_t n, double qPrev) -> double { return delta(n)*delta(n)*Bkey*(Bkey + p*p) + delta(n)*(floor(log2(qPrev) / dcrtBits) + 1)*w*Berr;  };

		//main correctness constraint
		auto qBFV = [&](uint32_t n, double qPrev) -> double { return p*(2 * (pow(C1(n), evalMultCount)*Vnorm(n) + evalMultCount*pow(C1(n), evalMultCount - 1)*C2(n, qPrev)) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qBFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q
		//changes the requirement for n, which is rare but still theoretically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				qPrev = q;
			}

			q = qBFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qBFV(n, qPrev);
			}

		}

	}

	size_t size = ceil((floor(log2(q - 1.0)) + 2.0) / (double)dcrtBits);

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);

	moduli[0] = FirstPrime<NativeInteger>(dcrtBits, 2 * n);
	roots[0] = RootOfUnity<NativeInteger>(2 * n, moduli[0]);

	for (size_t i = 1; i < size; i++)
	{
		moduli[i] = NextPrime<NativeInteger>(moduli[i-1], 2 * n);
		roots[i] = RootOfUnity<NativeInteger>(2 * n, moduli[i]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(2 * n, moduli, roots));

	cryptoParamsBFVrns->SetElementParams(params);

	return cryptoParamsBFVrns->PrecomputeCRTTables();

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrns<DCRTPoly>::Encrypt(const LPPublicKey<DCRTPoly> publicKey,
		DCRTPoly ptxt) const
{
	Ciphertext<DCRTPoly> ciphertext( new CiphertextImpl<DCRTPoly>(publicKey) );

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(publicKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	ptxt.SwitchFormat();
/*
	const std::vector<NativeInteger> &dTable = cryptoParams->GetCRTDeltaTable();
	Poly dTable2(elementParams, EVALUATION, true);
	for( size_t i=0; i<dTable.size(); i++ )
		dTable2.at(i) = Poly::Integer(dTable.at(i).ConvertToInt());
	DCRTPoly deltaTable( dTable2, elementParams );
*/

	const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename DCRTPoly::TugType tug;

	const DCRTPoly &p0 = publicKey->GetPublicElements().at(0);
	const DCRTPoly &p1 = publicKey->GetPublicElements().at(1);

	DCRTPoly u;

	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE)
		u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
	else
		u = DCRTPoly(tug, elementParams, Format::EVALUATION);

	DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
	DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

	DCRTPoly c0(elementParams);
	DCRTPoly c1(elementParams);

	c0 = p0*u + e1 + ptxt.Times(deltaTable);

	c1 = p1*u + e2;

	ciphertext->SetElements({ c0, c1 });

	return ciphertext;
}

template <>
DecryptResult LPAlgorithmBFVrns<DCRTPoly>::Decrypt(const LPPrivateKey<DCRTPoly> privateKey,
		const Ciphertext<DCRTPoly> ciphertext,
		NativePoly *plaintext) const
{
	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(privateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	const std::vector<DCRTPoly> &c = ciphertext->GetElements();

	const DCRTPoly &s = privateKey->GetPrivateElement();
	DCRTPoly sPower = s;

	DCRTPoly b = c[0];
	if(b.GetFormat() == Format::COEFFICIENT)
		b.SwitchFormat();

	DCRTPoly cTemp;
	for(size_t i=1; i<=ciphertext->GetDepth(); i++){
		cTemp = c[i];
		if(cTemp.GetFormat() == Format::COEFFICIENT)
			cTemp.SwitchFormat();

		b += sPower*cTemp;
		sPower *= s;
	}

	// Converts back to coefficient representation
	b.SwitchFormat();

	auto &p = cryptoParams->GetPlaintextModulus();

	const std::vector<double> &lyamTable = cryptoParams->GetCRTDecryptionFloatTable();
	const std::vector<NativeInteger> &invTable = cryptoParams->GetCRTDecryptionIntTable();

	// this is the resulting vector of coefficients;
	*plaintext = b.ScaleAndRound(p,invTable,lyamTable);

	return DecryptResult(plaintext->GetLength());

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrns<DCRTPoly>::Encrypt(const LPPrivateKey<DCRTPoly> privateKey,
		DCRTPoly ptxt) const
{
	Ciphertext<DCRTPoly> ciphertext( new CiphertextImpl<DCRTPoly>(privateKey) );

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(privateKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	ptxt.SwitchFormat();

	const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	DCRTPoly a(dug, elementParams, Format::EVALUATION);
	const DCRTPoly &s = privateKey->GetPrivateElement();
	DCRTPoly e(dgg, elementParams, Format::EVALUATION);

	DCRTPoly c0(a*s + e + ptxt.Times(deltaTable));
	DCRTPoly c1(elementParams, Format::EVALUATION, true);
	c1 -= a;

	ciphertext->SetElements({ c0, c1 });

	return ciphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalAdd(const Ciphertext<DCRTPoly> ciphertext,
	const Plaintext plaintext) const{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

	plaintext->GetEncodedElement<DCRTPoly>().SetFormat(EVALUATION);
	const DCRTPoly& ptElement = plaintext->GetEncodedElement<DCRTPoly>();

	std::vector<DCRTPoly> c(cipherTextElements.size());

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	c[0] = cipherTextElements[0] + ptElement.Times(deltaTable);

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalSub(const Ciphertext<DCRTPoly> ciphertext,
	const Plaintext plaintext) const{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

	plaintext->GetEncodedElement<DCRTPoly>().SetFormat(EVALUATION);
	const DCRTPoly& ptElement = plaintext->GetEncodedElement<DCRTPoly>();

	std::vector<DCRTPoly> c(cipherTextElements.size());

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	c[0] = cipherTextElements[0] - ptElement.Times(deltaTable);

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalMult(const Ciphertext<DCRTPoly> ciphertext1,
	const Ciphertext<DCRTPoly> ciphertext2) const {

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEBFVrns::EvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ciphertext1->GetCryptoContext()->GetCryptoParameters());
	//Check if the multiplication supports the depth
	if ( (ciphertext1->GetDepth() + ciphertext2->GetDepth()) > cryptoParamsBFVrns->GetMaxDepth() ) {
			std::string errMsg = "LPAlgorithmSHEBFVrns::EvalMult multiplicative depth is not supported";
			throw std::runtime_error(errMsg);
	}

	//Get the ciphertext elements
	std::vector<DCRTPoly> cipherText1Elements = ciphertext1->GetElements();
	std::vector<DCRTPoly> cipherText2Elements = ciphertext2->GetElements();

	size_t cipherText1ElementsSize = cipherText1Elements.size();
	size_t cipherText2ElementsSize = cipherText2Elements.size();
	size_t cipherTextRElementsSize = cipherText1ElementsSize + cipherText2ElementsSize - 1;

	std::vector<DCRTPoly> c(cipherTextRElementsSize);

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsBFVrns->GetElementParams();
	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();
	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsBFVrns->GetDCRTParamsQS();

	// Expands the CRT basis to Q*S; Outputs the polynomials in EVALUATION representation


	for(size_t i=0; i<cipherText1ElementsSize; i++)
		cipherText1Elements[i].ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
				cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	for(size_t i=0; i<cipherText2ElementsSize; i++)
		cipherText2Elements[i].ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
				cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	// Performs the multiplication itself

	bool *isFirstAdd = new bool[cipherTextRElementsSize];
	std::fill_n(isFirstAdd, cipherTextRElementsSize, true);

	for(size_t i=0; i<cipherText1ElementsSize; i++){
		for(size_t j=0; j<cipherText2ElementsSize; j++){

			if(isFirstAdd[i+j] == true){
				c[i+j] = cipherText1Elements[i] * cipherText2Elements[j];
				isFirstAdd[i+j] = false;
			}
			else{
				c[i+j] += cipherText1Elements[i] * cipherText2Elements[j];
			}
		}
	}

	delete []isFirstAdd;

	for(size_t i=0; i<cipherTextRElementsSize; i++){
		//converts to coefficient representation before rounding
		c[i].SwitchFormat();
		// Performs the scaling by p/q followed by rounding; the result is in the CRT basis S
		c[i] = c[i].ScaleAndRound(paramsS,cryptoParamsBFVrns->GetCRTMultIntTable(),cryptoParamsBFVrns->GetCRTMultFloatTable());
		// Converts from the CRT basis S to Q
		c[i] = c[i].SwitchCRTBasis(elementParams, cryptoParamsBFVrns->GetCRTSInverseTable(),
					cryptoParamsBFVrns->GetCRTsDivsiModqiTable(), cryptoParamsBFVrns->GetCRTsModqiTable());
	}

	newCiphertext->SetElements(c);
	newCiphertext->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

	return newCiphertext;

}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::KeySwitchGen(const LPPrivateKey<DCRTPoly> originalPrivateKey,
	const LPPrivateKey<DCRTPoly> newPrivateKey) const {

	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(newPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(newPrivateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const DCRTPoly &s = newPrivateKey->GetPrivateElement();

	const typename DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	const DCRTPoly &oldKey = originalPrivateKey->GetPrivateElement();

	const std::vector<NativeInteger> &qDivqiTable = cryptoParamsLWE->GetCRTqDivqiTable();

	// computes all [oldKey q/qi]_qi
	DCRTPoly oldKeyqDivqi = oldKey.Times(qDivqiTable);

	//std::vector<DCRTPoly> evalKeyElements(originalPrivateKey->GetPrivateElement().PowersOfBase(relinWindow));
	std::vector<DCRTPoly> evalKeyElements;
	std::vector<DCRTPoly> evalKeyElementsGenerated;

	for (usint i = 0; i < qDivqiTable.size(); i++)
	{
		// Generate a_i vectors
		DCRTPoly a(dug, elementParams, Format::EVALUATION);
		evalKeyElementsGenerated.push_back(a);

		// Creates an element with all zeroes
		DCRTPoly filtered(elementParams,EVALUATION,true);
		// Sets [oldKey q/qi]_qi
		filtered.SetElementAtIndex(i,oldKeyqDivqi.GetElementAtIndex(i));

		// Generate a_i * s + e - PowerOfBase(s^2)
		DCRTPoly e(dgg, elementParams, Format::EVALUATION);
		evalKeyElements.push_back(filtered - (a*s + e));
	}

	ek->SetAVector(std::move(evalKeyElements));
	ek->SetBVector(std::move(evalKeyElementsGenerated));

	return ek;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::KeySwitch(const LPEvalKey<DCRTPoly> ek,
	const Ciphertext<DCRTPoly> cipherText) const
{

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ek->GetCryptoParameters());

	LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

	const std::vector<DCRTPoly> &c = cipherText->GetElements();

	const std::vector<DCRTPoly> &b = evalKey->GetAVector();
	const std::vector<DCRTPoly> &a = evalKey->GetBVector();

	std::vector<DCRTPoly> digitsC2;

	DCRTPoly ct0(c[0]);

	//in the case of EvalMult, c[0] is initially in coefficient format and needs to be switched to evaluation format
	if (c.size() > 2)
		ct0.SwitchFormat();

	DCRTPoly ct1;

	if (c.size() == 2) //case of PRE or automorphism
	{
		digitsC2 = c[1].CRTDecompose(cryptoParamsLWE->GetCRTInverseTable());
		ct1 = digitsC2[0] * a[0];
	}
	else //case of EvalMult
	{
		digitsC2 = c[2].CRTDecompose(cryptoParamsLWE->GetCRTInverseTable());
		ct1 = c[1];
		//Convert ct1 to evaluation representation
		ct1.SwitchFormat();
		ct1 += digitsC2[0] * a[0];

	}

	ct0 += digitsC2[0] * b[0];

	for (usint i = 1; i < digitsC2.size(); ++i)
	{
		ct0 += digitsC2[i] * b[i];
		ct1 += digitsC2[i] * a[i];
	}

	newCiphertext->SetElements({ ct0, ct1 });

	return newCiphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrns<DCRTPoly>::EvalMultAndRelinearize(const Ciphertext<DCRTPoly> ciphertext1,
	const Ciphertext<DCRTPoly> ciphertext2, const vector<LPEvalKey<DCRTPoly>> &ek) const{

	Ciphertext<DCRTPoly> cipherText = this->EvalMult(ciphertext1, ciphertext2);

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ek[0]->GetCryptoParameters());

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	std::vector<DCRTPoly> c = cipherText->GetElements();

	if(c[0].GetFormat() == Format::COEFFICIENT)
		for(size_t i=0; i<c.size(); i++)
			c[i].SwitchFormat();

	DCRTPoly ct0(c[0]);
	DCRTPoly ct1(c[1]);
	// Perform a keyswitching operation to result of the multiplication. It does it until it reaches to 2 elements.
	//TODO: Maybe we can change the number of keyswitching and terminate early. For instance; perform keyswitching until 4 elements left.
	for(size_t j = 0; j<=cipherText->GetDepth()-2; j++){
		size_t index = cipherText->GetDepth()-2-j;
		LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

		const std::vector<DCRTPoly> &b = evalKey->GetAVector();
		const std::vector<DCRTPoly> &a = evalKey->GetBVector();

		std::vector<DCRTPoly> digitsC2 = c[index+2].CRTDecompose(cryptoParamsLWE->GetCRTInverseTable());

		for (usint i = 0; i < digitsC2.size(); ++i){
			ct0 += digitsC2[i] * b[i];
			ct1 += digitsC2[i] * a[i];
		}
	}

	newCiphertext->SetElements({ ct0, ct1 });

	return newCiphertext;

}

template <>
DecryptResult LPAlgorithmMultipartyBFVrns<DCRTPoly>::MultipartyDecryptFusion(const vector<Ciphertext<DCRTPoly>>& ciphertextVec,
		NativePoly *plaintext) const
{

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(ciphertextVec[0]->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	const auto &p = cryptoParams->GetPlaintextModulus();

	const std::vector<DCRTPoly> &cElem = ciphertextVec[0]->GetElements();
	DCRTPoly b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<DCRTPoly> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}

	const std::vector<double> &lyamTable = cryptoParams->GetCRTDecryptionFloatTable();
	const std::vector<NativeInteger> &invTable = cryptoParams->GetCRTDecryptionIntTable();

	// this is the resulting vector of coefficients;
	*plaintext = b.ScaleAndRound(p,invTable,lyamTable);

	return DecryptResult(plaintext->GetLength());

}


template class LPCryptoParametersBFVrns<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBFVrns<DCRTPoly>;
template class LPAlgorithmBFVrns<DCRTPoly>;
template class LPAlgorithmSHEBFVrns<DCRTPoly>;
template class LPAlgorithmMultipartyBFVrns<DCRTPoly>;
template class LPAlgorithmParamsGenBFVrns<DCRTPoly>;

}
