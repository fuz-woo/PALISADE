/*
 * @file cryptocontext.cpp -- Control for encryption operations.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#include "cryptocontext.h"
#include "utils/serializablehelper.h"

namespace lbcrypto {

template <typename Element>
void CryptoContext<Element>::EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> key) {

	if( key == NULL || key->GetCryptoContext() != this )
		throw std::logic_error("Key passed to EvalMultKeyGen were not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();

	shared_ptr<LPEvalKey<Element>> k = GetEncryptionAlgorithm()->EvalMultKeyGen(key);
	if( evalMultKeys.size() == 0 )
		evalMultKeys.push_back(k);
	else
		evalMultKeys[0] = k;

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalMultKeyGen, currentDateTime() - start) );
	}

}

template <typename Element>
void CryptoContext<Element>::EvalSumKeyGen(
	const shared_ptr<LPPrivateKey<Element>> privateKey,
	const shared_ptr<LPPublicKey<Element>> publicKey) {

	if( privateKey == NULL || privateKey->GetCryptoContext() != this ) {
		throw std::logic_error("Private key passed to EvalSumKeyGen were not generated with this crypto context");
	}

	if( publicKey != NULL && publicKey->GetCryptoContext() != this ) {
		throw std::logic_error("Public key passed to EvalSumKeyGen were not generated with this crypto context");
	}

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto evalKeys = GetEncryptionAlgorithm()->EvalSumKeyGen(privateKey,publicKey);

	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSumKeyGen, currentDateTime() - start) );
	}
	evalSumKeys = *evalKeys;
}

template <typename Element>
const std::map<usint, shared_ptr<LPEvalKey<Element>>>& CryptoContext<Element>::GetEvalSumKey() const {
	return evalSumKeys;
}

template <typename Element>
shared_ptr<Ciphertext<Element>> CryptoContext<Element>::EvalSum(const shared_ptr<Ciphertext<Element>> ciphertext, usint batchSize) const {

	if( ciphertext == NULL || ciphertext->GetCryptoContext() != this )
		throw std::logic_error("Information passed to EvalAdd was not generated with this crypto context");

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalSum(ciphertext, batchSize, evalSumKeys);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalSum, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Ciphertext<Element>> CryptoContext<Element>::EvalInnerProduct(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2, usint batchSize) const {

	if( ct1 == NULL || ct2 == NULL || ct1->GetCryptoContext() != this || ct2->GetCryptoContext() != this )
		throw std::logic_error("Information passed to EvalAdd was not generated with this crypto context");

	auto evalMultKey = GetEvalMultKey();

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys, evalMultKey);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalInnerProduct, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Ciphertext<Element>>
CryptoContext<Element>::EvalCrossCorrelation(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize,
		usint indexStart, usint length) const {

	//need to add exception handling

	auto evalMultKey = GetEvalMultKey();

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalCrossCorrelation(x, y, batchSize, indexStart, length, evalSumKeys, evalMultKey);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalCrossCorrelation, currentDateTime() - start) );
	}
	return rv;
}

template <typename Element>
shared_ptr<Matrix<RationalCiphertext<Element>>>
CryptoContext<Element>::EvalLinRegressBatched(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
		const shared_ptr<Matrix<RationalCiphertext<Element>>> y, usint batchSize) const
{
	//need to add exception handling

	auto evalMultKey = GetEvalMultKey();

	double start = 0;
	if( doTiming ) start = currentDateTime();
	auto rv = GetEncryptionAlgorithm()->EvalLinRegressBatched(x, y, batchSize, evalSumKeys, evalMultKey);
	if( doTiming ) {
		timeSamples->push_back( TimingInfo(OpEvalLinRegressionBatched, currentDateTime() - start) );
	}
	return rv;
}

template <typename T>
bool
CryptoContext<T>::Serialize(Serialized* serObj) const
{
	serObj->SetObject();

	Serialized ccser(rapidjson::kObjectType, &serObj->GetAllocator());

	Serialized pser(rapidjson::kObjectType, &serObj->GetAllocator());
	if( !params->Serialize(&pser) )
		return false;
	ccser.AddMember("Params", pser.Move(), serObj->GetAllocator());

	Serialized kser(rapidjson::kObjectType, &serObj->GetAllocator());

	if( this->evalMultKeys.size() > 0 ) {
		SerializeVectorOfPointers<LPEvalKey<T>>("EvalMultKeys", "LPEvalKey", this->evalMultKeys, &ccser);
	}

	if( this->evalSumKeys.size() > 0 ) {
		SerializeMapOfPointers("EvalSumKeys", T::GetElementName(), this->evalSumKeys, &ccser);
	}

	ccser.AddMember("Schemes", std::to_string(this->scheme->GetEnabled()), serObj->GetAllocator());

	serObj->AddMember("CryptoContext", ccser.Move(), serObj->GetAllocator());

	return true;
}

// returns a shared pointer to a parameter object of the proper type; we deserialize into this object
template <typename Element>
static shared_ptr<LPCryptoParameters<Element>> GetParameterObject(string& parmstype) {

	if (parmstype == "LPCryptoParametersLTV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersLTV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersBV<Element>());
	}
	else if (parmstype == "LPCryptoParametersFV") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersFV<Element>());
	}
	else if (parmstype == "LPCryptoParametersStehleSteinfeld") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersStehleSteinfeld<Element>());
	}
	else if (parmstype == "LPCryptoParametersNull") {
		return shared_ptr<LPCryptoParameters<Element>>(new LPCryptoParametersNull<Element>());
	}

	return shared_ptr<LPCryptoParameters<Element>>();
}

// helper for deserialization of contexts
template <typename Element>
static shared_ptr<LPPublicKeyEncryptionScheme<Element>> GetSchemeObject(string& parmstype) {

	if (parmstype == "LPCryptoParametersLTV") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeLTV<Element>());
	}
	else if (parmstype == "LPCryptoParametersBV") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeBV<Element>());
	}
	else if (parmstype == "LPCryptoParametersFV") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeFV<Element>());
	}
	else if (parmstype == "LPCryptoParametersStehleSteinfeld") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>());
	}
	else if (parmstype == "LPCryptoParametersNull") {
		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>(new LPPublicKeyEncryptionSchemeNull<Element>());
	}

	return shared_ptr<LPPublicKeyEncryptionScheme<Element>>();
}

/**
* Create a PALISADE CryptoContext from a serialization
* @param serObj - the serialization
* @param noKeys - if true, do not deserialize the keys
* @return new context
*/
template <typename Element>
shared_ptr<CryptoContext<Element>>
CryptoContextFactory<Element>::DeserializeAndCreateContext(const Serialized& serObj, bool noKeys) {

	Serialized::ConstMemberIterator mIter = serObj.FindMember("CryptoContext");
	if( mIter == serObj.MemberEnd() )
		throw std::logic_error("Serialization is not of a CryptoContext");

	// mIter->value has params and keys

	Serialized::ConstMemberIterator pIter = mIter->value.FindMember("Params");
	if( pIter == mIter->value.MemberEnd() )
		throw std::logic_error("Serialization is missing Params");

	// get parms type
	Serialized temp(rapidjson::kObjectType);
	auto parmValue = SerialItem(pIter->value, temp.GetAllocator());

	string parmName;
	pIter = parmValue.FindMember("LPCryptoParametersType");
	if (pIter == parmValue.MemberEnd()) {
		throw std::logic_error("Parameter serialization is missing Parameter type");
	}

	parmName = pIter->value.GetString();

	pIter = parmValue.FindMember(parmName);
	if (pIter == parmValue.MemberEnd()) {
		throw std::logic_error("Parameter serialization is missing Parameter value");
	}

	Serialized parm(rapidjson::kObjectType);
	parm.AddMember(SerialItem(pIter->name, parm.GetAllocator()), SerialItem(pIter->value, parm.GetAllocator()), parm.GetAllocator());

	shared_ptr<LPCryptoParameters<Element>> cp = GetParameterObject<Element>(parmName);

	if (cp == NULL) {
		throw std::logic_error("Unable to create crypto parameters");
	}

	if (!cp->Deserialize(parm)) {
		throw std::logic_error("Unable to deserialize crypto parameters for " + parmName);
	}

	shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme = GetSchemeObject<Element>(parmName);

	shared_ptr<CryptoContext<Element>> cc(new CryptoContext<Element>(cp, scheme));

	Serialized::ConstMemberIterator sIter = mIter->value.FindMember("Schemes");
	if( sIter != mIter->value.MemberEnd() ) {
		usint schemeBits = std::stoi(sIter->value.GetString());
		cc->Enable(schemeBits);
	}


	if( noKeys )
		return cc;

	// sadly we cannot DeserializeVectorOfPointers because of polymorphism in the pointer type...
	vector<shared_ptr<LPEvalKey<Element>>> evalMultKeys;
	Serialized::ConstMemberIterator kIter = mIter->value.FindMember("EvalMultKeys");
	if( kIter != mIter->value.MemberEnd() ) {

		Serialized kser(rapidjson::kObjectType);
		kser.AddMember(SerialItem(kIter->name, kser.GetAllocator()), SerialItem(kIter->value, kser.GetAllocator()), kser.GetAllocator());

		Serialized ktemp(rapidjson::kObjectType);
		auto keyValue = SerialItem(kIter->value, ktemp.GetAllocator());

		Serialized::ConstMemberIterator t = keyValue.FindMember("Length");
		if( t == keyValue.MemberEnd() )
			throw std::logic_error("Unable to find number of eval mult keys in serialization of crypto context");
		usint nKeys = std::stoi(t->value.GetString());

		t = keyValue.FindMember("Typename");
		if( t == keyValue.MemberEnd() )
			throw std::logic_error("Unable to find eval mult key type in serialization of crypto context");
		string ty = t->value.GetString();

		t = keyValue.FindMember("Members");
		if( t == keyValue.MemberEnd() )
			throw std::logic_error("Unable to find eval mult keys in serialization of crypto context");
		const SerialItem& members = t->value;

		for( size_t k = 0; k < nKeys; k++ ) {

			shared_ptr<LPEvalKey<Element>> kp;

			Serialized::ConstMemberIterator eIt = members.FindMember( std::to_string(k) );
			if( eIt == members.MemberEnd() )
				throw std::logic_error("Unable to find eval mult key #" + std::to_string(k) + " in serialization of crypto context");

			auto keyMember = SerialItem(eIt->value, ktemp.GetAllocator());
			Serialized kser(rapidjson::kObjectType);

			Serialized::ConstMemberIterator t = keyMember.MemberBegin();
			while( t != keyMember.MemberEnd() ) {
				kser.AddMember(SerialItem(t->name, kser.GetAllocator()), SerialItem(t->value, kser.GetAllocator()), kser.GetAllocator());
				t++;
			}

			kp = cc->deserializeEvalKey(kser);

			evalMultKeys.push_back(kp);
		}

		cc->SetEvalMultKeys(evalMultKeys);
	}

	map<usint,shared_ptr<LPEvalKey<Element>>> evalSumKeys;
	kIter = mIter->value.FindMember("EvalSumKeys");

	if( kIter != mIter->value.MemberEnd() ) {
		Serialized esKeys(rapidjson::kObjectType);
		esKeys.AddMember(SerialItem(kIter->name, parm.GetAllocator()), SerialItem(kIter->value, parm.GetAllocator()), parm.GetAllocator());

		Serialized::ConstMemberIterator t = kIter->value.FindMember("Members");
		if( t == kIter->value.MemberEnd() )
			throw std::logic_error("Unable to find eval sum keys in serialization of crypto context");
		const SerialItem& members = t->value;

		for( Serialized::ConstMemberIterator mI = members.MemberBegin(); mI != members.MemberEnd(); mI++ ) {

			shared_ptr<LPEvalKey<Element>> kp;

			usint k = std::stoi( mI->name.GetString() );

			Serialized kser(rapidjson::kObjectType);
			auto keyMember = SerialItem(mI->value, kser.GetAllocator());

			Serialized::ConstMemberIterator t = keyMember.MemberBegin();
			while( t != keyMember.MemberEnd() ) {
				kser.AddMember(SerialItem(t->name, kser.GetAllocator()), SerialItem(t->value, kser.GetAllocator()), kser.GetAllocator());
				t++;
			}

			kp = cc->deserializeEvalKey(kser);

			evalSumKeys[k] = kp;
		}

		cc->SetEvalSumKeys(evalSumKeys);
	}

	return cc;
}

// factory methods for the different schemes

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextLTV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersLTV<T>> params( new LPCryptoParametersLTV<T>(
			ep,
			BigInteger(plaintextmodulus),
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextLTV(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersLTV<T>> params(new LPCryptoParametersLTV<T>(
		ep,
		encodingParams,
		stDev,
		assuranceMeasure,
		securityLevel,
		relinWindow,
		depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}


template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(
		const usint plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in LTV context constructor");

	usint depth = numAdds + numMults + numKeyswitches + 1;

	shared_ptr<typename T::Params> ep( new typename T::Params(0, BigInteger(0), BigInteger(0)) );

	shared_ptr<LPCryptoParametersLTV<T>> params( new LPCryptoParametersLTV<T>() );

	params->SetElementParams(ep);
	params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	params->SetAssuranceMeasure(9.0);
	params->SetDepth(depth);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeLTV<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContext<T>(params, scheme);
}

template <typename T>
CryptoContext<T>
CryptoContextFactory<T>::genCryptoContextLTV(
	shared_ptr<EncodingParams> encodingParams, float securityLevel, usint relinWindow, float dist,
	unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches)
{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in LTV context constructor");

	usint depth = numAdds + numMults + numKeyswitches + 1;

	shared_ptr<typename T::Params> ep(new typename T::Params(0, BigInteger::ZERO, BigInteger::ZERO));

	shared_ptr<LPCryptoParametersLTV<T>> params(new LPCryptoParametersLTV<T>());

	params->SetElementParams(ep);
	params->SetEncodingParams(encodingParams);
	//params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	params->SetAssuranceMeasure(9.0);
	params->SetDepth(depth);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeLTV<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return CryptoContext<T>(params, scheme);
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextFV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, const std::string& delta,
		MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
		const std::string& bigmodulusarb, const std::string& bigrootofunityarb)
{
	shared_ptr<LPCryptoParametersFV<T>> params(
			new LPCryptoParametersFV<T>(ep,
					BigInteger(plaintextmodulus),
					stDev,
					assuranceMeasure,
					securityLevel,
					relinWindow,
					BigInteger(delta),
					mode,
					BigInteger(bigmodulus),
					BigInteger(bigrootofunity),
					BigInteger(bigmodulusarb),
					BigInteger(bigrootofunityarb),
					depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeFV<T>() );

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextFV(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev, const std::string& delta,
	MODE mode, const std::string& bigmodulus, const std::string& bigrootofunity, int depth, int assuranceMeasure, float securityLevel,
	const std::string& bigmodulusarb, const std::string& bigrootofunityarb)
{
	shared_ptr<LPCryptoParametersFV<T>> params(
		new LPCryptoParametersFV<T>(ep,
			encodingParams,
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			BigInteger(delta),
			mode,
			BigInteger(bigmodulus),
			BigInteger(bigrootofunity),
			BigInteger(bigmodulusarb),
			BigInteger(bigrootofunityarb),
			depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeFV<T>());

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextFV(
		const usint plaintextModulus, float securityLevel, usint relinWindow, float dist,
		unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode)
{
	int nonZeroCount = 0;

	if( numAdds > 0 ) nonZeroCount++;
	if( numMults > 0 ) nonZeroCount++;
	if( numKeyswitches > 0 ) nonZeroCount++;

	if( nonZeroCount > 1 )
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in FV context constructor");

	shared_ptr<typename T::Params> ep( new typename T::Params(0, BigInteger(0), BigInteger(0)) );

	shared_ptr<LPCryptoParametersFV<T>> params( new LPCryptoParametersFV<T>() );

	params->SetElementParams(ep);
	params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	params->SetMode(mode);
	params->SetAssuranceMeasure(9.0);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeFV<T>() );

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextFV(
	shared_ptr<EncodingParams> encodingParams, float securityLevel, usint relinWindow, float dist,
	unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches, MODE mode)
{
	int nonZeroCount = 0;

	if (numAdds > 0) nonZeroCount++;
	if (numMults > 0) nonZeroCount++;
	if (numKeyswitches > 0) nonZeroCount++;

	if (nonZeroCount > 1)
		throw std::logic_error("only one of (numAdds,numMults,numKeyswitches) can be nonzero in FV context constructor");

	shared_ptr<typename T::Params> ep(new typename T::Params(0, BigInteger::ZERO, BigInteger::ZERO));

	shared_ptr<LPCryptoParametersFV<T>> params(new LPCryptoParametersFV<T>());

	params->SetElementParams(ep);
	params->SetEncodingParams(encodingParams);
	//params->SetPlaintextModulus(typename T::Integer(plaintextModulus));
	params->SetSecurityLevel(securityLevel);
	params->SetRelinWindow(relinWindow);
	params->SetDistributionParameter(dist);
	params->SetMode(mode);
	params->SetAssuranceMeasure(9.0);

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeFV<T>());

	scheme->ParamsGen(params, numAdds, numMults, numKeyswitches);

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}


template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextBV(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev,
		MODE mode, int depth)
{
	shared_ptr<LPCryptoParametersBV<T>> params( new LPCryptoParametersBV<T>(
		ep,
		BigInteger(plaintextmodulus),
		stDev,
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode, //Mode of noise generation
		depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeBV<T>() );

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextBV(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev,
	MODE mode, int depth)
{
	shared_ptr<LPCryptoParametersBV<T>> params(new LPCryptoParametersBV<T>(
		ep,
		encodingParams,
		stDev,
		9, // assuranceMeasure,
		1.006, // securityLevel,
		relinWindow, // Relinearization Window
		mode, //Mode of noise generation
		depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeBV<T>());

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}


template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
		const usint plaintextmodulus,
		usint relinWindow, float stDev, float stDevStSt, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params( new LPCryptoParametersStehleSteinfeld<T>(
			ep,
			BigInteger(plaintextmodulus),
			stDev,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			stDevStSt,
			depth) );

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>());

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextStehleSteinfeld(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams,
	usint relinWindow, float stDev, float stDevStSt, int depth, int assuranceMeasure, float securityLevel)
{
	shared_ptr<LPCryptoParametersStehleSteinfeld<T>> params(new LPCryptoParametersStehleSteinfeld<T>(
		ep,
		encodingParams,
		stDev,
		assuranceMeasure,
		securityLevel,
		relinWindow,
		stDevStSt,
		depth));

	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeStehleSteinfeld<T>());

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextNull(shared_ptr<typename T::Params> ep,
		const usint ptModulus)
{
	shared_ptr<LPCryptoParametersNull<T>> params( new LPCryptoParametersNull<T>(ep, BigInteger(ptModulus)) );
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme( new LPPublicKeyEncryptionSchemeNull<T>() );

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

template <typename T>
shared_ptr<CryptoContext<T>>
CryptoContextFactory<T>::genCryptoContextNull(shared_ptr<typename T::Params> ep,
	shared_ptr<EncodingParams> encodingParams)
{
	shared_ptr<LPCryptoParametersNull<T>> params(new LPCryptoParametersNull<T>(ep, encodingParams));
	shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme(new LPPublicKeyEncryptionSchemeNull<T>());

	return shared_ptr<CryptoContext<T>>(new CryptoContext<T>(params, scheme));
}

// the methods below allow me to deserialize a json object into this context
// ... which will only succeed if the object was serialized from this context,
// ... or from another context with identical parameters

template <typename T>
shared_ptr<LPPublicKey<T>>
CryptoContext<T>::deserializePublicKey(const Serialized& serObj)
{
	if( CryptoContextHelper::matchContextToSerialization(this, serObj) == false ) {
		return shared_ptr<LPPublicKey<T>>();
	}

	shared_ptr<LPPublicKey<T>> key( new LPPublicKey<T>(this) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPPublicKey<T>>();
}

template <typename T>
shared_ptr<LPPrivateKey<T>>
CryptoContext<T>::deserializeSecretKey(const Serialized& serObj)
{
	if( CryptoContextHelper::matchContextToSerialization(this, serObj) == false ) {
		return shared_ptr<LPPrivateKey<T>>();
	}

	shared_ptr<LPPrivateKey<T>> key( new LPPrivateKey<T>(this) );

	if( key->Deserialize(serObj) )
		return key;

	return shared_ptr<LPPrivateKey<T>>();
}

template <typename T>
shared_ptr<Ciphertext<T>>
CryptoContext<T>::deserializeCiphertext(const Serialized& serObj)
{
	if( CryptoContextHelper::matchContextToSerialization(this, serObj) == false ) {
		return shared_ptr<Ciphertext<T>>();
	}

	shared_ptr<Ciphertext<T>> ctxt( new Ciphertext<T>(this) );

	if( ctxt->Deserialize(serObj) )
		return ctxt;

	return shared_ptr<Ciphertext<T>>();
}

template <typename T>
shared_ptr<LPEvalKey<T>>
CryptoContext<T>::deserializeEvalKey(const Serialized& serObj)
{
	Serialized::ConstMemberIterator nIt = serObj.FindMember("Object");
	if( nIt == serObj.MemberEnd() )
		return 0;

	shared_ptr<LPEvalKey<T>> key;
	string oname = nIt->value.GetString();
	if( oname == "EvalKeyRelin" ) {
		LPEvalKeyRelin<T> *k = new LPEvalKeyRelin<T>(this);
		if( k->Deserialize(serObj) == false )
			return 0;

		key.reset( k );
	}

	else if( oname == "EvalKeyNTRURelin" ) {
		LPEvalKeyNTRURelin<T> *k = new LPEvalKeyNTRURelin<T>(this);
		if( k->Deserialize(serObj) == false )
			return 0;

		key.reset( k );
	}
	else if( oname == "EvalKeyNTRU" ) {
		LPEvalKeyNTRU<T> *k = new LPEvalKeyNTRU<T>(this);
		if( k->Deserialize(serObj) == false )
			return 0;

		key.reset( k );
	}
	else
		throw std::logic_error("Unrecognized Eval Key type '" + oname + "'");

	return key;
}

}

