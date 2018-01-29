/*
* @file cryptocontexthelper-impl.cpp - cryptocontext helper class implementation
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

#include "palisade.h"

#include "cryptocontext.h"
#include "cryptocontexthelper.h"
#include "utils/parmfactory.h"
#include "utils/rapidjson/filewritestream.h"

namespace lbcrypto {

static bool
getValueForName(const map<string,string>& allvals, const string key, string& value)
{
	map<string,string>::const_iterator it = allvals.find(key);
	if( it == allvals.end() ) {
		std::cerr << key << " element is missing" << std::endl;
		return false;
	}

	value = it->second;
	return true;
}

template <typename Element>
static CryptoContext<Element>
buildContextFromSerialized(const map<string,string>& s, shared_ptr<typename Element::Params> parms, EncodingParams ep = 0)
{
	std::string parmtype;
	std::string plaintextModulus;
	std::string ring;
	std::string modulus;
	std::string rootOfUnity;
	std::string relinWindow;
	std::string stDev;
	std::string stDevStSt;
	std::string secLevel;

	if( !getValueForName(s, "parameters", parmtype) ) {
		std::cerr << "parameters element is missing" << std::endl;
		return 0;
	}

	if( parmtype == "LTV" ) {
		if( !getValueForName(s, "plaintextModulus", plaintextModulus) ||
				!getValueForName(s, "relinWindow", relinWindow) ||
				!getValueForName(s, "stDev", stDev) ) {
			return 0;
		}

		if( ep.get() != 0 )
			return CryptoContextFactory<Element>::genCryptoContextLTV(parms, ep,
					stoul(relinWindow), stof(stDev));

		return CryptoContextFactory<Element>::genCryptoContextLTV(parms, stoul(plaintextModulus),
				stoul(relinWindow), stof(stDev));
	}
	else if( parmtype == "StehleSteinfeld" ) {
		if( !getValueForName(s, "plaintextModulus", plaintextModulus) ||
				!getValueForName(s, "relinWindow", relinWindow) ||
				!getValueForName(s, "stDev", stDev) ||
				!getValueForName(s, "stDevStSt", stDevStSt) ) {
			return 0;
		}

		return CryptoContextFactory<Element>::genCryptoContextStehleSteinfeld(parms, stoul(plaintextModulus),
				stoul(relinWindow), stof(stDev), stof(stDevStSt));
	}
	else if( parmtype == "BFV" ) {
		if( !getValueForName(s, "plaintextModulus", plaintextModulus) ||
				!getValueForName(s, "securityLevel", secLevel) )
			return 0;

		return CryptoContextFactory<Element>::genCryptoContextBFV(stoul(plaintextModulus), stof(secLevel), 16, 4,
				0, 0, 1);

	}
	else if( parmtype == "BFVrns" ) {
		if( !getValueForName(s, "plaintextModulus", plaintextModulus) ||
				!getValueForName(s, "securityLevel", secLevel) )
			return 0;

		return CryptoContextFactory<Element>::genCryptoContextBFVrns(stoul(plaintextModulus), stof(secLevel), 4,
				0, 0, 1);

	}
	else if( parmtype == "BGV" ) {
		if( !getValueForName(s, "plaintextModulus", plaintextModulus) ||
				!getValueForName(s, "relinWindow", relinWindow) ||
				!getValueForName(s, "stDev", stDev) ) {
			return 0;
		}

		return CryptoContextFactory<Element>::genCryptoContextBGV(parms,
				stoul(plaintextModulus), stoul(relinWindow), stof(stDev));
	}
	else if( parmtype == "Null" ) {
		if( !getValueForName(s, "plaintextModulus", plaintextModulus) ) {
			return 0;
		}

		auto ptm = stoul(plaintextModulus);
		return CryptoContextFactory<Element>::genCryptoContextNull(parms->GetCyclotomicOrder(), ptm);
	}
	else {
		throw std::logic_error("Unrecognized parmtype " + parmtype + " in buildContextFromSerialized");
	}

	return 0;
}

// forward declaration of DeserializeCryptoParameters
template <typename Element>
inline shared_ptr<LPCryptoParameters<Element>> DeserializeCryptoParameters(const Serialized &serObj);

// forward declaration of DeserializeAndValidateCryptoParameters
template <typename Element>
inline shared_ptr<LPCryptoParameters<Element>> DeserializeAndValidateCryptoParameters(const Serialized& serObj, const LPCryptoParameters<Element>& curP);

/** This function is used to deserialize the Crypto Parameters
*
* @param &serObj object to be serialized
*
* @return the parameters or null on failure
*/
template <typename Element>
inline shared_ptr<LPCryptoParameters<Element>> DeserializeCryptoParameters(const Serialized &serObj)
{
	Serialized::ConstMemberIterator cit = serObj.FindMember("CryptoContext");
	if (cit == serObj.MemberEnd()) return 0;

	cit = cit->value.FindMember("Params");
	if (cit == serObj.MemberEnd()) return 0;

	LPCryptoParameters<Element>* parmPtr = 0;

	Serialized::ConstMemberIterator it = cit->value.FindMember("LPCryptoParametersType");
	if (it == serObj.MemberEnd()) return 0;
	std::string type = it->value.GetString();

	if (type == "LPCryptoParametersLTV") {
		parmPtr = new LPCryptoParametersLTV<Element>();
	}
	else if (type == "LPCryptoParametersStehleSteinfeld") {
		parmPtr = new LPCryptoParametersStehleSteinfeld<Element>();
	}
	else if (type == "LPCryptoParametersBGV") {
		parmPtr = new LPCryptoParametersBGV<Element>();
	}
	else if (type == "LPCryptoParametersNull") {
		parmPtr = new LPCryptoParametersNull<Element>();
	}
	else if (type == "LPCryptoParametersBFV") {
		parmPtr = new LPCryptoParametersBFV<Element>();
	}
	else if (type == "LPCryptoParametersBFVrns") {
		parmPtr = new LPCryptoParametersBFVrns<Element>();
	}
	else
		return 0;

	it = cit->value.FindMember(type);
	if (it == serObj.MemberEnd()) return 0;

	Serialized temp(rapidjson::kObjectType);
	temp.AddMember(SerialItem(it->name, temp.GetAllocator()), SerialItem(it->value, temp.GetAllocator()), temp.GetAllocator());

	if (!parmPtr->Deserialize(temp)) {
		delete parmPtr;
		return 0;
	}

	return shared_ptr<LPCryptoParameters<Element>>(parmPtr);
}

/** This function is used to deserialize the Crypto Parameters, to compare them to the existing parameters,
* and to fail if they do not match
*
* @param &serObj object to be desrialized
* @param &curP LPCryptoParameters to validate against
*
* @return the parameters or null on failure
*/
template <typename Element>
inline shared_ptr<LPCryptoParameters<Element>> DeserializeAndValidateCryptoParameters(const Serialized& serObj, const LPCryptoParameters<Element>& curP)
{
	LPCryptoParameters<Element>* parmPtr = DeserializeCryptoParameters<Element>(serObj);

	if (parmPtr == 0) return 0;

	// make sure the deserialized parms match the ones in the current context
	if (*parmPtr == curP)
		return parmPtr;

	delete parmPtr;
	return 0;
}

CryptoContext<Poly>
CryptoContextHelper::getNewContext(const string& parmset, EncodingParams ep)
{
	std::string parmtype;
	std::string ring;
	std::string modulus;
	std::string rootOfUnity;

	map<string, map<string,string>>::iterator it = CryptoContextParameterSets.find(parmset);

	if( it == CryptoContextParameterSets.end() ) {
		return 0;
	}

	if( !getValueForName(it->second, "parameters", parmtype) ) {
		std::cerr << "parameters element is missing" << std::endl;
		return 0;
	}

	// BFV uses parm generation so we skip this code for BFV
	shared_ptr<typename Poly::Params> parms;
	if(( parmtype != "BFV" ) && ( parmtype != "BFVrns" )) {
		if( !getValueForName(it->second, "ring", ring) ||
				!getValueForName(it->second, "modulus", modulus) ||
				!getValueForName(it->second, "rootOfUnity", rootOfUnity) ) {
			return 0;
		}

		parms.reset( new typename Poly::Params(stoul(ring),
								typename Poly::Integer(modulus),
								typename Poly::Integer(rootOfUnity)));
	}

	return buildContextFromSerialized<Poly>(it->second, parms, ep);
}

CryptoContext<DCRTPoly>
CryptoContextHelper::getNewDCRTContext(const string& parmset, usint numTowers, usint primeBits)
{
	std::string parmtype;
	std::string ring;
	std::string plaintextModulus;

	map<string, map<string,string>>::iterator it = CryptoContextParameterSets.find(parmset);

	if( it == CryptoContextParameterSets.end() ) {
		return 0;
	}

	if( !getValueForName(it->second, "parameters", parmtype) ) {
		std::cerr << "parameters element is missing" << std::endl;
		return 0;
	}

	// BFV uses parm generation so we skip this code for BFV
	shared_ptr<DCRTPoly::Params> parms;
	if(( parmtype != "BFV" ) && ( parmtype != "BFVrns" )) {
		if( !getValueForName(it->second, "ring", ring) ||
				!getValueForName(it->second, "plaintextModulus", plaintextModulus) ) {
			return 0;
		}

		parms = GenerateDCRTParams<DCRTPoly::Integer>(stoul(ring), numTowers, primeBits);

	}
	return buildContextFromSerialized<DCRTPoly>(it->second, parms);
}


static void printSet(std::ostream& out, string key, map<string,string>& pset)
{
	out << "Parameter set: " << key << std::endl;

	for( auto P : pset ) {
		out << "  " << P.first << ": " << P.second << std::endl;
	}
}

void
CryptoContextHelper::printParmSet(std::ostream& out, string parmset)
{
	auto it = CryptoContextParameterSets.find(parmset);
	if( it == CryptoContextParameterSets.end() ) {
		out << "Parameter set " << parmset << " is unknown" << std::endl;
	}
	else
		printSet(out, it->first, it->second);

}


void
CryptoContextHelper::printAllParmSets(std::ostream& out)
{
	for( auto S : CryptoContextParameterSets ) {
		printSet(out, S.first, S.second);
	}
}

void
CryptoContextHelper::printAllParmSetNames(std::ostream& out)
{
	map<string, map<string,string>>::iterator it = CryptoContextParameterSets.begin();

	out << it->first;

	for( it++; it != CryptoContextParameterSets.end(); it++ ) {
		out << ", " << it->first;
	}
	out << std::endl;
}

void
CryptoContextHelper::printParmSetNamesByFilter(std::ostream& out, const string &filter)
{
	size_t counter = 0;
	for (map<string, map<string, string>>::iterator it = CryptoContextParameterSets.begin(); it != CryptoContextParameterSets.end(); it++) {
		if (it->first.find(filter) != string::npos) {
			if (counter == 0)
				out << it->first;
			else
				out << ", " << it->first;
			counter++;
		}
	}
	out << std::endl;

}

void
CryptoContextHelper::printParmSetNamesByExcludeFilter(std::ostream& out, const string &filter)
{

	size_t counter = 0;
	for (map<string, map<string, string>>::iterator it = CryptoContextParameterSets.begin(); it != CryptoContextParameterSets.end(); it++) {
		if (it->first.find(filter) == string::npos) {
			if (counter == 0)
				out << it->first;
			else
				out << ", " << it->first;
			counter++;
		}
	}
	out << std::endl;

}

}
