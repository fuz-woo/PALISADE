/*
* @file bfvrns-poly-impl.cpp - poly implementation for the BFVrns scheme.
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

#define NOPOLY \
		std::string errMsg = "BFVrns does not support Poly. Use DCRTPoly instead."; \
		throw std::runtime_error(errMsg);

#define NONATIVEPOLY \
		std::string errMsg = "BFVrns does not support NativePoly. Use DCRTPoly instead."; \
		throw std::runtime_error(errMsg);

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(){
	NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(){
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(const LPCryptoParametersBFVrns &rhs){
	NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(const LPCryptoParametersBFVrns &rhs){
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(shared_ptr<typename Poly::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(shared_ptr<typename NativePoly::Params> params,
		const PlaintextModulus &plaintextModulus,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	NONATIVEPOLY
}

template <>
LPCryptoParametersBFVrns<Poly>::LPCryptoParametersBFVrns(shared_ptr<typename Poly::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	NOPOLY
}

template <>
LPCryptoParametersBFVrns<NativePoly>::LPCryptoParametersBFVrns(shared_ptr<typename NativePoly::Params> params,
		EncodingParams encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		MODE mode,
		int depth,
		int maxDepth){
	NONATIVEPOLY
}

// Parameter generation for BFV-RNS
template <>
bool LPCryptoParametersBFVrns<Poly>::PrecomputeCRTTables(){
	NOPOLY
}

template <>
bool LPCryptoParametersBFVrns<NativePoly>::PrecomputeCRTTables(){
	NONATIVEPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrns<Poly>::LPPublicKeyEncryptionSchemeBFVrns(){
	NOPOLY
}

template <>
LPPublicKeyEncryptionSchemeBFVrns<NativePoly>::LPPublicKeyEncryptionSchemeBFVrns(){
	NONATIVEPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrns<Poly>::ParamsGen(shared_ptr<LPCryptoParameters<Poly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount) const
{
	NOPOLY
}

template <>
bool LPAlgorithmParamsGenBFVrns<NativePoly>::ParamsGen(shared_ptr<LPCryptoParameters<NativePoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrns<Poly>::Encrypt(const LPPublicKey<Poly> publicKey,
		Poly ptxt) const
{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrns<NativePoly>::Encrypt(const LPPublicKey<NativePoly> publicKey,
		NativePoly ptxt) const
{
	NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmBFVrns<Poly>::Decrypt(const LPPrivateKey<Poly> privateKey,
		const Ciphertext<Poly> ciphertext,
		NativePoly *plaintext) const
{
	NOPOLY
}

template <>
DecryptResult LPAlgorithmBFVrns<NativePoly>::Decrypt(const LPPrivateKey<NativePoly> privateKey,
		const Ciphertext<NativePoly> ciphertext,
		NativePoly *plaintext) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmBFVrns<Poly>::Encrypt(const LPPrivateKey<Poly> privateKey,
		Poly ptxt) const
{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmBFVrns<NativePoly>::Encrypt(const LPPrivateKey<NativePoly> privateKey,
		NativePoly ptxt) const
{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalMult(const Ciphertext<Poly> ciphertext1,
	const Ciphertext<Poly> ciphertext2) const {
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalMult(const Ciphertext<NativePoly> ciphertext1,
	const Ciphertext<NativePoly> ciphertext2) const {
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalAdd(const Ciphertext<Poly> ct,
	const Plaintext pt) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalAdd(const Ciphertext<NativePoly> ct,
	const Plaintext pt) const{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalSub(const Ciphertext<Poly> ct,
	const Plaintext pt) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalSub(const Ciphertext<NativePoly> ct,
	const Plaintext pt) const{
	NONATIVEPOLY
}

template <>
LPEvalKey<Poly> LPAlgorithmSHEBFVrns<Poly>::KeySwitchGen(const LPPrivateKey<Poly> originalPrivateKey,
	const LPPrivateKey<Poly> newPrivateKey) const {
	NOPOLY
}

template <>
LPEvalKey<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::KeySwitchGen(const LPPrivateKey<NativePoly> originalPrivateKey,
	const LPPrivateKey<NativePoly> newPrivateKey) const {
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::KeySwitch(const LPEvalKey<Poly> keySwitchHint,
	const Ciphertext<Poly> cipherText) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::KeySwitch(const LPEvalKey<NativePoly> keySwitchHint,
	const Ciphertext<NativePoly> cipherText) const{
	NONATIVEPOLY
}

template <>
Ciphertext<Poly> LPAlgorithmSHEBFVrns<Poly>::EvalMultAndRelinearize(const Ciphertext<Poly> ct1,
	const Ciphertext<Poly> ct, const vector<LPEvalKey<Poly>> &ek) const{
	NOPOLY
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHEBFVrns<NativePoly>::EvalMultAndRelinearize(const Ciphertext<NativePoly> ct1,
	const Ciphertext<NativePoly> ct, const vector<LPEvalKey<NativePoly>> &ek) const{
	NONATIVEPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrns<Poly>::MultipartyDecryptFusion(const vector<Ciphertext<Poly>>& ciphertextVec,
		NativePoly *plaintext) const {
	NOPOLY
}

template <>
DecryptResult LPAlgorithmMultipartyBFVrns<NativePoly>::MultipartyDecryptFusion(const vector<Ciphertext<NativePoly>>& ciphertextVec,
		NativePoly *plaintext) const {
	NONATIVEPOLY
}

template class LPCryptoParametersBFVrns<Poly>;
template class LPPublicKeyEncryptionSchemeBFVrns<Poly>;
template class LPAlgorithmBFVrns<Poly>;
template class LPAlgorithmSHEBFVrns<Poly>;
template class LPAlgorithmMultipartyBFVrns<Poly>;
template class LPAlgorithmParamsGenBFVrns<Poly>;

template class LPCryptoParametersBFVrns<NativePoly>;
template class LPPublicKeyEncryptionSchemeBFVrns<NativePoly>;
template class LPAlgorithmBFVrns<NativePoly>;
template class LPAlgorithmSHEBFVrns<NativePoly>;
template class LPAlgorithmMultipartyBFVrns<NativePoly>;
template class LPAlgorithmParamsGenBFVrns<NativePoly>;

}
