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
		{ OpNOOP, "No Op", ENCRYPTION },
		{ OpUnknown, "Unknown", ENCRYPTION },
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
		{ OpEvalMultMany, "EvalMultMany", SHE },
		{ OpEvalMultMatrix, "EvalMultMatrix", SHE },
		{ OpEvalAutomorphismKeyGen, "EvalAutomorphismKeyGen", SHE },
		{ OpEvalAutomorphismI, "EvalAutomorphism(I,K)", SHE },
		{ OpEvalAutomorphismK, "EvalAutomorphism(K)", SHE },
		{ OpEvalMultPlain, "EvalMultPlain", SHE },
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
		{ OpEvalAtIndexKeyGen, "EvalAtIndexKeyGen", SHE },
		{ OpEvalSum, "EvalSum", SHE },
		{ OpEvalAtIndex, "EvalAtIndex", SHE },
		{ OpEvalInnerProduct, "EvalInnerProduct", SHE },
		{ OpEvalCrossCorrelation, "EvalCrossCorrelation", SHE },
		{ OpEvalLinRegressionBatched, "EvalLinRegressionBatched", SHE },
		{ OpEvalMerge, "EvalMerge", SHE },
		{ OpEvalRightShift, "EvalRightShift", SHE }
};

map<OpType,string> OperatorName;
map<OpType,PKESchemeFeature> OperatorFeat;
map<string,OpType> OperatorType;

// this class has a single static instance whose constructor makes the maps declared just above
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
	statMap.AddMember("argcnt", std::to_string(argcnt), serObj->GetAllocator());
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
	if( (pIt = mIter->value.FindMember("argcnt")) == mIter->value.MemberEnd() )
		return false;
	argcnt = std::stod( pIt->value.GetString() );
	if( (pIt = mIter->value.FindMember("average")) == mIter->value.MemberEnd() )
		return false;
	average = std::stod( pIt->value.GetString() );

	return false;
}

template<typename Element>
Plaintext
MakeRandomPlaintext(CryptoContext<Element> cc, PlaintextEncodings pte) {

	auto maxval = cc->GetCryptoParameters()->GetPlaintextModulus() / 2;
	vector<int64_t> vec;
	vector<uint64_t> uvec;
	auto maxentry = cc->GetRingDimension();

	// Depending on encoding, will need a random integer, vector, or string
	auto randomUInt = [&]() {
		return (uint64_t)(rand() % maxval);
	};

	auto randomInt = [&]() {
		return (int64_t)(randomUInt() * ((rand() % 1) > 0 ? 1 : -1));
	};

	auto randomUIntVec = [&]() {
		uvec.clear();
		for( size_t n=0; n<maxentry; n++ )
			uvec.push_back( randomUInt() );
	};

	auto randomIntVec = [&]() {
		vec.clear();
		for( size_t n=0; n<maxentry; n++ )
			vec.push_back( randomInt() );
	};

	auto randomString = [&]() {
		string s;
		for( size_t n=0; n<maxentry; n++ )
			s.push_back( 'a' + rand()%26 );
		return s;
	};

	switch(pte) {
	default:
		throw std::logic_error("Unknown plaintext encoding type");

	case Scalar: {
		return cc->MakeScalarPlaintext(randomInt());
	}

	case Integer: {
		return cc->MakeIntegerPlaintext(randomInt());
	}

	case Fractional: {
		return cc->MakeFractionalPlaintext(randomInt());
	}

	case CoefPacked: {
		randomIntVec();
		return cc->MakeCoefPackedPlaintext(vec);
	}

	case Packed: {
		randomUIntVec();
		return cc->MakePackedPlaintext(uvec);
	}

	case String: {
		return cc->MakeStringPlaintext(randomString());
	}
	}

	return Plaintext();
}

template Plaintext MakeRandomPlaintext(CryptoContext<Poly> cc, PlaintextEncodings pte);
template Plaintext MakeRandomPlaintext(CryptoContext<DCRTPoly> cc, PlaintextEncodings pte);
template Plaintext MakeRandomPlaintext(CryptoContext<NativePoly> cc, PlaintextEncodings pte);

template<typename Element>
void
generateTimings(TimingStatisticsMap& stats,
		CryptoContext<Element> cc,
		PlaintextEncodings pte,
		bool verbose,
		int maxIterations,
		bool PrintSizes) {

	static vector<PKESchemeFeature> features( {ENCRYPTION, PRE, SHE, FHE, LEVELEDSHE, MULTIPARTY} );
	const unsigned int NumInputs = 16;

	// enable all the features
	// remember the ones that were successfully enabled in tmask
	// be silent about failures
	usint tmask = 0;
	for( auto f : features ) {
		try {
			cc->Enable(f);
			tmask |= f;
		} catch(...) {}
	}

	if( verbose ) cout << *cc->GetCryptoParameters() << endl;

	// make NumInputs random vectors
	Plaintext inputs[NumInputs];
	for( size_t i = 0; i < NumInputs; i++ )
		inputs[i] = MakeRandomPlaintext(cc, pte);

	// note we can NOT use the TimingInfo on a Windows platform because
	// of clock granularity (or lack thereof)
	// Therefore we simply repeat the calls and calculate an average

	TimeVar t;
	double span;

	// ENCRYPTION: KeyGen, Encrypt (2 kinds) and Decrypt

	if( verbose )
		cerr << "ENCRYPTION" << endl;

	LPKeyPair<Element> kp;
	Ciphertext<Element> crypt;

	if( tmask & ENCRYPTION ) {
		kp = cc->KeyGen();
		TIC(t);
		for( int reps=0; reps < maxIterations; reps++ ) {
			kp = cc->KeyGen();
		}
		span = TOC_MS(t);
		stats[TimingStatisticsKey(OpKeyGen)] = TimingStatistics(OpKeyGen, maxIterations, span);

		Plaintext decrypted;

		crypt = cc->Encrypt(kp.publicKey, inputs[0]);
		TIC(t);
		for( int reps=0; reps < maxIterations; reps++ ) {
			crypt = cc->Encrypt(kp.publicKey, inputs[0]);
		}
		span = TOC_MS(t);
		stats[TimingStatisticsKey(OpEncryptPub)] = TimingStatistics(OpType::OpEncryptPub, maxIterations, span);

		auto crypt2 = cc->Encrypt(kp.publicKey, inputs[0]);
		TIC(t);
		for( int reps=0; reps < maxIterations; reps++ ) {
			crypt2 = cc->Encrypt(kp.secretKey, inputs[0]);
		}
		span = TOC_MS(t);
		stats[TimingStatisticsKey(OpEncryptPriv)] = TimingStatistics(OpType::OpEncryptPriv, maxIterations, span);

		TIC(t);
		for( int reps=0; reps < maxIterations; reps++ ) {
			cc->Decrypt(kp.secretKey, crypt, &decrypted);
		}
		span = TOC_MS(t);
		stats[TimingStatisticsKey(OpDecrypt)] = TimingStatistics(OpType::OpDecrypt, maxIterations, span);
	}

	// PKE: ReKeyGen and ReEncrypt

	if( verbose )
		cerr << "PRE" << endl;

	Ciphertext<Element> recrypt;
	LPEvalKey<Element> rekey1, rekey2;

	if( tmask & PRE ) {
		bool runPubPri = true, runPriPri = true;
		LPKeyPair<Element> kp1 = cc->KeyGen();
		LPKeyPair<Element> kp2 = cc->KeyGen();

		crypt = cc->Encrypt(kp1.publicKey, inputs[0]);

		Plaintext decrypted;

		try {
			rekey1 = cc->ReKeyGen(kp2.publicKey, kp1.secretKey);
			recrypt = cc->ReEncrypt(rekey1, crypt);
		} catch(exception& e) {
			cout << e.what() << endl;
			runPubPri = false;
		}

		try {
			rekey2 = cc->ReKeyGen(kp2.secretKey, kp1.secretKey);
			recrypt = cc->ReEncrypt(rekey2, crypt);
		} catch(exception& e) {
			cout << e.what() << endl;
			runPriPri = false;
		}

		if( runPubPri ) {
			TIC(t);
			for( int reps=0; reps < maxIterations; reps++ ) {
				rekey1 = cc->ReKeyGen(kp2.publicKey, kp1.secretKey);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpReKeyGenPubPri)] = TimingStatistics(OpType::OpReKeyGenPubPri, maxIterations, span);

			TIC(t);
			for( int reps=0; reps < maxIterations; reps++ ) {
				recrypt = cc->ReEncrypt(rekey1, crypt);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpReEncrypt)] = TimingStatistics(OpType::OpReEncrypt, maxIterations, span);

			TIC(t);
			for( int reps=0; reps < maxIterations; reps++ ) {
				cc->Decrypt(kp2.secretKey, recrypt, &decrypted);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpDecrypt)] = TimingStatistics(OpType::OpDecrypt, maxIterations, span);
		}

		if( runPriPri ) {
			TIC(t);
			for( int reps=0; reps < maxIterations; reps++ ) {
				rekey2 = cc->ReKeyGen(kp2.secretKey, kp1.secretKey);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpReKeyGenPriPri)] = TimingStatistics(OpType::OpReKeyGenPriPri, maxIterations, span);

			TIC(t);
			for( int reps=0; reps < maxIterations; reps++ ) {
				recrypt = cc->ReEncrypt(rekey2, crypt);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpReEncrypt)] = TimingStatistics(OpType::OpReEncrypt, maxIterations, span);

			TIC(t);
			for( int reps=0; reps < maxIterations; reps++ ) {
				cc->Decrypt(kp2.secretKey, recrypt, &decrypted);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpDecrypt)] = TimingStatistics(OpType::OpDecrypt, maxIterations, span);
		}
	}

	// SHE: EvalAdd/Sub/Neg/Mult; binary with ciphers and one cipher one pre

	if( verbose )
		cerr << "SHE" << endl;

	if( tmask & SHE ) {
		LPKeyPair<Element> kp = cc->KeyGen();
		try {
			vector<int32_t> indexList;
			for( int ii = 1; ii <= 32; ii++ )
				indexList.push_back( -ii );

			cc->EvalMultKeyGen(kp.secretKey);
			cc->EvalSumKeyGen(kp.secretKey);
			cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

			auto crypt0 = cc->Encrypt(kp.publicKey, inputs[0]);
			auto crypt1 = cc->Encrypt(kp.publicKey, inputs[1]);

			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				cc->EvalAdd(crypt0, crypt1);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpEvalAdd)] = TimingStatistics(OpType::OpEvalAdd, maxIterations, span);

			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				cc->EvalAdd(crypt0, inputs[1]);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpEvalAddPlain)] = TimingStatistics(OpType::OpEvalAddPlain, maxIterations, span);

			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				cc->EvalSub(crypt0, crypt1);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpEvalSub)] = TimingStatistics(OpType::OpEvalSub, maxIterations, span);

			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				cc->EvalSub(crypt0, inputs[1]);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpEvalSubPlain)] = TimingStatistics(OpType::OpEvalSubPlain, maxIterations, span);

			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				cc->EvalMult(crypt0, crypt1);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpEvalMult)] = TimingStatistics(OpType::OpEvalMult, maxIterations, span);

			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				cc->EvalMult(crypt0, inputs[1]);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpEvalMultPlain)] = TimingStatistics(OpType::OpEvalMultPlain, maxIterations, span);

			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				cc->EvalNegate(crypt0);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpEvalNeg)] = TimingStatistics(OpType::OpEvalNeg, maxIterations, span);

			vector<Ciphertext<Element>> ciphers;
			Ciphertext<Element> merged;
			for( int nct : vector<int>({2,4,8,16}) ) {
				for(int i=0; i<nct; i++)
					ciphers.push_back( cc->Encrypt(kp.publicKey, inputs[i]) );

				merged = cc->EvalMerge(ciphers);
				TIC(t);
				for (int reps = 0; reps < maxIterations; reps++) {
					cc->EvalMerge(ciphers);
				}
				span = TOC_MS(t);
				stats[TimingStatisticsKey(OpEvalMerge,nct)] = TimingStatistics(OpType::OpEvalMerge, maxIterations, span, nct);
			}

			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				cc->EvalInnerProduct(merged,merged,NumInputs);
			}
			span = TOC_MS(t);
			stats[TimingStatisticsKey(OpEvalInnerProduct)] = TimingStatistics(OpType::OpEvalInnerProduct, maxIterations, span);

			bool hasMR = true;
			TIC(t);
			for (int reps = 0; reps < maxIterations; reps++) {
				try {
					cc->ModReduce(crypt0);
				} catch( exception& e ) {
					cout << e.what() << endl;
					hasMR = false;
					break;
				}
			}
			if( hasMR ) {
				span = TOC_MS(t);
				stats[TimingStatisticsKey(OpModReduce)] = TimingStatistics(OpType::OpModReduce, maxIterations, span);
			}
		} catch(exception& e) {
			cout << e.what() << endl;
		}
	}

	// FHE: bootstrap, nothing yet

	// LEVELEDSHE

	// MULTIPARTY

	if( verbose )
		cerr << "Results:" << endl;

	Serialized ser;
	string str;

#define PSSIZE(msg,x) { \
		Serialized ser; string str; \
		if( (x)->Serialize(&ser) ) {\
			SerializableHelper::SerializationToString(ser, str); \
			cout << (msg) << str.length() << endl; \
		} \
}

	if( PrintSizes ) {
		cout << endl;
		cout << "Plaintext: array of " << cc->GetRingDimension() << " "
				<< (sizeof(int64_t) * 8) << " bit integers: "
				<< cc->GetRingDimension()*sizeof(int64_t) << endl;

		//cout << "Plaintext size: " << sizeof( *inputs[0] ) << endl;
		PSSIZE("Public key size: ", kp.publicKey );
		PSSIZE("Private key size: ", kp.secretKey );
		PSSIZE("Ciphertext size : ", crypt );
		if( rekey1 ) PSSIZE("PRE Key 1 size: ", rekey1 );
		if( rekey2 ) PSSIZE("PRE Key 2 size: ", rekey2 );
	}
}

template
void
generateTimings(
		TimingStatisticsMap& stats,
		CryptoContext<Poly> cc,
		PlaintextEncodings pte,
		bool verbose, int maxIterations,
		bool PrintSizes);

template
void
generateTimings(
		TimingStatisticsMap& stats,
		CryptoContext<DCRTPoly> cc,
		PlaintextEncodings pte,
		bool verbose, int maxIterations,
		bool PrintSizes);

template
void
generateTimings(
		TimingStatisticsMap& stats,
		CryptoContext<NativePoly> cc,
		PlaintextEncodings pte,
		bool verbose, int maxIterations,
		bool PrintSizes);

}

