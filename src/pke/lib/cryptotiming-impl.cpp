/**
 * @file cryptotimin-impl.cpp -- Definitions for taking timings of crypto operations
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met, 
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
 * @section DESCRIPTION
 *
 * This code provides support for the holding and maintenance of cryptosystem parameters.
 *
 */

#include "cryptocontext.h"
#include "inttypes.h"
#include <iostream>
#include <string>
#include <map>
using std::string;
using std::map;

namespace lbcrypto {

struct FeatureMap {
	OpType op;
	string	name;
	PKESchemeFeature	feat;
};

static struct FeatureMap FeatureMap[] = {
	{ OpNOOP, "NONE", ENCRYPTION },
	{ OpKeyGen, "KeyGen", ENCRYPTION },
	{ OpMultiPartyKeyGenKey, "MultipartyKeyGen(key)", MULTIPARTY },
	{ OpMultiPartyKeyGenKeyvec, "MultipartyKeyGen(vector<key>)", MULTIPARTY },
	{ OpMultiPartyDecryptLead, "MultiPartyDecryptLead", MULTIPARTY },
	{ OpMultiPartyDecryptMain, "MultiPartyDecryptMain", MULTIPARTY },
	{ OpMultiPartyDecryptFusion, "MultiPartyDecryptFusion", MULTIPARTY },
	{ OpSparseKeyGen, "SparseKeyGen", ENCRYPTION },
	{ OpReKeyGenPubPri, "ReKeyGen(pubkey,privkey)", PRE },
	{ OpReKeyGenPriPri, "ReKeyGen(privkey,privkey)", PRE },
	{ OpEvalMultKeyGen, "EvalMultKeyGen", SHE },
	{ OpEncryptPub, "EncryptPub", ENCRYPTION },
	{ OpEncryptPriv, "EncryptPriv", ENCRYPTION },
	{ OpEncryptPlain, "EncryptPlain", ENCRYPTION },
	{ OpEncrypt, "Encrypt", ENCRYPTION },
	{ OpEncryptMatrixPlain, "EncryptMatrix(intplaintext)", ENCRYPTION },
	{ OpEncryptMatrixPacked, "EncryptMatrix(packedintplaintext)", ENCRYPTION },
	{ OpDecrypt, "Decrypt", ENCRYPTION },
	{ OpDecryptMatrixPlain, "DecryptMatrix(intplaintext)", ENCRYPTION },
	{ OpDecryptMatrixPacked, "DecryptMatrix(packedintplaintext)", ENCRYPTION },
	{ OpReEncrypt, "ReEncrypt", PRE },
	{ OpEvalAdd, "EvalAdd", SHE },
	{ OpEvalAddMatrix, "EvalAddMatrix", SHE },
	{ OpEvalAddPlain, "EvalAddPlain", SHE },
	{ OpEvalNeg, "EvalNeg", SHE },
	{ OpEvalNegMatrix, "EvalNegMatrix", SHE },
	{ OpEvalSub, "EvalSub", SHE },
	{ OpEvalSubMatrix, "EvalSubMatrix", SHE },
	{ OpEvalSubPlain, "EvalSubPlain", SHE },
	{ OpEvalMult, "EvalMult", SHE },
	{ OpEvalMultMatrix, "EvalMultMatrix", SHE },
	{ OpEvalAutomorphismKeyGen, "EvalAutomorphismKeyGen", SHE },
	{ OpEvalAutomorphismI, "EvalAutomorphism(I,K)", SHE },
	{ OpEvalAutomorphismK, "EvalAutomorphism(K)", SHE },
	{ OpEvalMultPlain, "EvalMult", SHE },
	{ OpLinRegression, "LinRegression", SHE },
	{ OpKeySwitch, "KeySwitch", SHE },
	{ OpKeySwitchGen, "KeySwitchGen", SHE },
	{ OpModReduce, "ModReduce", LEVELEDSHE },
	{ OpModReduceRational, "ModReduceRational", LEVELEDSHE },
	{ OpModReduceMatrix, "ModReduceMatrix", LEVELEDSHE },
	{ OpLevelReduce, "LevelReduce", LEVELEDSHE },
	{ OpRingReduce, "RingReduce", LEVELEDSHE },
	{ OpComposedEvalMult, "ComposedEvalMult", LEVELEDSHE },
	{ OpEvalSumKeyGen, "EvalSumKeyGen", SHE },
	{ OpEvalSum, "EvalSum", ENCRYPTION },
	{ OpEvalInnerProduct, "EvalInnerProduct", ENCRYPTION },
	{ OpEvalCrossCorrelation, "EvalCrossCorrelation", ENCRYPTION },
	{ OpEvalLinRegressionBatched, "EvalLinRegressionBatched", ENCRYPTION }
};

map<OpType,string> OperatorName;
map<OpType,PKESchemeFeature> OperatorFeat;
map<string,OpType> OperatorType;

class FeatureMapBuilder {
public:
	FeatureMapBuilder() {
		struct FeatureMap *m = FeatureMap;
		for( size_t i=0; i < sizeof(FeatureMap)/sizeof(FeatureMap[0]); i++,m++ ) {
			OperatorName[m->op] = m->name;
			OperatorType[m->name] = m->op;
			OperatorFeat[m->op] = m->feat;
		}
	}
	virtual ~FeatureMapBuilder() {}
};

static FeatureMapBuilder __mapper;

std::ostream& operator<<(std::ostream& out, const OpType& op) {
	out << OperatorName[op];
	return out;
}

bool TimingStatistics::Serialize(Serialized *serObj) const {
	serObj->SetObject();
	SerialItem statMap(rapidjson::kObjectType);

	statMap.AddMember("operation", OperatorName[operation], serObj->GetAllocator());
	statMap.AddMember("samples", std::to_string(samples), serObj->GetAllocator());
	statMap.AddMember("startup", std::to_string(startup), serObj->GetAllocator());
	statMap.AddMember("min", std::to_string(min), serObj->GetAllocator());
	statMap.AddMember("max", std::to_string(max), serObj->GetAllocator());
	statMap.AddMember("average", std::to_string(average), serObj->GetAllocator());

	serObj->AddMember("TimingStatistics", statMap.Move(), serObj->GetAllocator());

	return true;
}

bool TimingStatistics::Deserialize(const Serialized& serObj) {
	Serialized::ConstMemberIterator mIter = serObj.FindMember("TimingStatistics");
	if( mIter == serObj.MemberEnd() ) return false;

	SerialItem::ConstMemberIterator pIt;

	if( (pIt = mIter->value.FindMember("operation")) == mIter->value.MemberEnd() )
		return false;
	operation = OperatorType[ pIt->value.GetString() ];
	if( (pIt = mIter->value.FindMember("samples")) == mIter->value.MemberEnd() )
		return false;
	samples = std::stoi( pIt->value.GetString() );
	if( (pIt = mIter->value.FindMember("startup")) == mIter->value.MemberEnd() )
		return false;
	startup = std::stod( pIt->value.GetString() );
	if( (pIt = mIter->value.FindMember("min")) == mIter->value.MemberEnd() )
		return false;
	min = std::stod( pIt->value.GetString() );
	if( (pIt = mIter->value.FindMember("max")) == mIter->value.MemberEnd() )
		return false;
	max = std::stod( pIt->value.GetString() );
	if( (pIt = mIter->value.FindMember("average")) == mIter->value.MemberEnd() )
		return false;
	average = std::stod( pIt->value.GetString() );

	return false;
}

}

