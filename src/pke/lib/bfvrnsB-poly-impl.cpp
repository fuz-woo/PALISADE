/*
* @file bfvrnsB-poly-impl.cpp - poly implementation for the BFVrns scheme using approximation techniques.
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
#include "bfvrnsB.cpp"

namespace lbcrypto {

#define NOPOLY \
		std::string errMsg = "BFVrnsB does not support Poly. Use DCRTPoly instead."; \
		throw std::runtime_error(errMsg);

#define NONATIVEPOLY \
		std::string errMsg = "BFVrnsB does not support NativePoly. Use DCRTPoly instead."; \
		throw std::runtime_error(errMsg);

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB() : m_numq(0), m_numB(0) {
	NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(): m_numq(0), m_numB(0) {
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(const LPCryptoParametersBFVrnsB &rhs): m_numq(0), m_numB(0) {
	NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(const LPCryptoParametersBFVrnsB &rhs): m_numq(0), m_numB(0) {
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(shared_ptr<typename Poly::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth): m_numq(0), m_numB(0) {
	NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(shared_ptr<typename NativePoly::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth): m_numq(0), m_numB(0) {
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrnsB<Poly>::LPCryptoParametersBFVrnsB(shared_ptr<typename Poly::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth): m_numq(0), m_numB(0) {
	NOPOLY
}

template <>
LPCryptoParametersBFVrnsB<NativePoly>::LPCryptoParametersBFVrnsB(shared_ptr<typename NativePoly::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth): m_numq(0), m_numB(0) {
	NONATIVEPOLY
}

// Parameter generation for BFV-RNS
template <>
bool LPCryptoParametersBFVrnsB<Poly>::PrecomputeCRTTables(){
	NOPOLY
}

template <>
bool LPCryptoParametersBFVrnsB<NativePoly>::PrecomputeCRTTables(){
	NONATIVEPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrnsB<Poly>::LPPublicKeyEncryptionSchemeBFVrnsB(){
	NOPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrnsB<NativePoly>::LPPublicKeyEncryptionSchemeBFVrnsB(){
	NONATIVEPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrnsB<Poly>::ParamsGen(shared_ptr<LPCryptoParameters<Poly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits) const
{
	NOPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrnsB<NativePoly>::ParamsGen(shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrnsB<Poly>::Encrypt(const LPPublicKey<Poly> publicKey,
		Poly ptxt) const
{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrnsB<NativePoly>::Encrypt(const LPPublicKey<NativePoly> publicKey,
		NativePoly ptxt) const
{
	NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmBFVrnsB<Poly>::Decrypt(const LPPrivateKey<Poly> privateKey,
		ConstCiphertext<Poly> ciphertext,
		NativePoly *plaintext) const
{
	NOPOLY
}

template <>
DecryptResult LPAlgorithmBFVrnsB<NativePoly>::Decrypt(const LPPrivateKey<NativePoly> privateKey,
		ConstCiphertext<NativePoly> ciphertext,
		NativePoly *plaintext) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrnsB<Poly>::Encrypt(const LPPrivateKey<Poly> privateKey,
		Poly ptxt) const
{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrnsB<NativePoly>::Encrypt(const LPPrivateKey<NativePoly> privateKey,
		NativePoly ptxt) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalMult(ConstCiphertext<Poly> ciphertext1,
	ConstCiphertext<Poly> ciphertext2) const {
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalMult(ConstCiphertext<NativePoly> ciphertext1,
	ConstCiphertext<NativePoly> ciphertext2) const {
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalAdd(ConstCiphertext<Poly> ct,
		ConstPlaintext pt) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalAdd(ConstCiphertext<NativePoly> ct,
		ConstPlaintext pt) const{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalSub(ConstCiphertext<Poly> ct,
	ConstPlaintext pt) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalSub(ConstCiphertext<NativePoly> ct,
	ConstPlaintext pt) const{
	NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBFVrnsB<Poly>::KeySwitchGen(const LPPrivateKey<Poly> originalPrivateKey,
	const LPPrivateKey<Poly> newPrivateKey) const {
	NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::KeySwitchGen(const LPPrivateKey<NativePoly> originalPrivateKey,
	const LPPrivateKey<NativePoly> newPrivateKey) const {
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::KeySwitch(const LPEvalKey<Poly> keySwitchHint,
	ConstCiphertext<Poly> cipherText) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::KeySwitch(const LPEvalKey<NativePoly> keySwitchHint,
	ConstCiphertext<NativePoly> cipherText) const{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrnsB<Poly>::EvalMultAndRelinearize(ConstCiphertext<Poly> ct1,
	ConstCiphertext<Poly> ct, const vector<LPEvalKey<Poly>> &ek) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrnsB<NativePoly>::EvalMultAndRelinearize(ConstCiphertext<NativePoly> ct1,
	ConstCiphertext<NativePoly> ct, const vector<LPEvalKey<NativePoly>> &ek) const{
	NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsB<Poly>::MultipartyDecryptFusion(const vector<Ciphertext<Poly>>& ciphertextVec,
		NativePoly *plaintext) const {
	NOPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsB<NativePoly>::MultipartyDecryptFusion(const vector<Ciphertext<NativePoly>>& ciphertextVec,
		NativePoly *plaintext) const {
	NONATIVEPOLY
}

template class LPCryptoParametersBFVrnsB<Poly>;
template class LPPublicKeyEncryptionSchemeBFVrnsB<Poly>;
template class LPAlgorithmBFVrnsB<Poly>;
template class LPAlgorithmSHEBFVrnsB<Poly>;
template class LPAlgorithmMultipartyBFVrnsB<Poly>;
template class LPAlgorithmParamsGenBFVrnsB<Poly>;

template class LPCryptoParametersBFVrnsB<NativePoly>;
template class LPPublicKeyEncryptionSchemeBFVrnsB<NativePoly>;
template class LPAlgorithmBFVrnsB<NativePoly>;
template class LPAlgorithmSHEBFVrnsB<NativePoly>;
template class LPAlgorithmMultipartyBFVrnsB<NativePoly>;
template class LPAlgorithmParamsGenBFVrnsB<NativePoly>;

}
