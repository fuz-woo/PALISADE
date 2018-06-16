/**
 * @file cryptotiming.h -- Definitions for taking timings of crypto operations
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
 *
 * @section DESCRIPTION
 *
 * This code provides support for timing crypto operations
 *
 */

#ifndef CRYPTOTIMING_H_
#define CRYPTOTIMING_H_

// this is included by cryptocontext.h only

namespace lbcrypto {

// this enum is used to identify the various operations when doing timings
enum OpType {
	OpNOOP,
	OpUnknown,
	OpKeyGen,
	OpMultiPartyKeyGenKey, OpMultiPartyKeyGenKeyvec,
	OpMultiPartyDecryptLead, OpMultiPartyDecryptMain, OpMultiPartyDecryptFusion,
	OpSparseKeyGen,
	OpReKeyGenPubPri, OpReKeyGenPriPri,
	OpEvalMultKeyGen,
	OpKeySwitchGen,
	OpEncryptPub, OpEncryptPriv, OpEncryptPlain,
	OpEncrypt, OpEncryptMatrixPlain, OpEncryptMatrixPacked,
	OpDecrypt, OpDecryptMatrixPlain, OpDecryptMatrixPacked,
	OpReEncrypt,
	OpEvalAdd, OpEvalAddMatrix, OpEvalAddPlain,
	OpEvalSub, OpEvalSubMatrix, OpEvalSubPlain,
	OpEvalMult, OpEvalMultMany, OpEvalMultMatrix, OpEvalMultPlain,
	OpEvalNeg, OpEvalNegMatrix,
	OpEvalAutomorphismKeyGen,
	OpEvalAutomorphismI,
	OpEvalAutomorphismK,
	OpLinRegression, OpKeySwitch,
	OpModReduce, OpModReduceRational, OpModReduceMatrix, OpLevelReduce, OpRingReduce, OpComposedEvalMult,
	OpEvalSumKeyGen, OpEvalSum, OpEvalInnerProduct, OpEvalCrossCorrelation, OpEvalLinRegressionBatched,
	OpEvalAtIndexKeyGen,OpEvalAtIndex,
	OpEvalMerge, OpEvalRightShift,
};

extern std::map<OpType,string> OperatorName;
extern std::map<OpType,PKESchemeFeature> OperatorFeat;
extern std::map<string,OpType> OperatorType;

extern std::ostream& operator<<(std::ostream& out, const OpType& op);

// this class represents a timing sample
class TimingInfo {
public:
	OpType	operation;
	usint	numArgs;
	double	timeval;
	TimingInfo(OpType o, double t, usint na=2) : operation(o), numArgs(na), timeval(t) {}
};

inline std::ostream& operator<<(std::ostream& out, const TimingInfo& t) {
	out << t.operation << "(" << t.numArgs << "): " << t.timeval;
	return out;
}

class TimingStatisticsKey {
public:
	OpType	operation;
	usint	argcnt;

	TimingStatisticsKey(OpType op, usint argcnt = 2) {
		this->operation = op;
		this->argcnt = argcnt;
	}

	bool operator<(const TimingStatisticsKey& k2) const {
		if( operation < k2.operation ) return true;
		else if( operation == k2.operation ) {
			if( argcnt < k2.argcnt ) return true;
		}
		return false;
	}

	friend inline ostream& operator<<(ostream& out, const TimingStatisticsKey& k) {
		return out << k.operation << "(" << k.argcnt << ")";
	}
};

class TimingStatistics;
typedef map<TimingStatisticsKey,TimingStatistics> TimingStatisticsMap;


// timing samples are collected into a TimingStatistics
class TimingStatistics {
public:
	OpType	operation;
	usint	samples;
	double	average;
	usint	argcnt;

	TimingStatistics() :
		operation(OpNOOP), samples(0), average(0), argcnt(0) {}
	TimingStatistics(OpType op, usint samples, double total, usint argcnt = 2) {
		this->operation = op;
		this->samples = samples;
		this->average = total/samples;
		this->argcnt = argcnt;
	}
	bool Serialize(Serialized* serObj) const;
	bool Deserialize(const Serialized& serObj);

	// collect a vector of samples into a map of statistics
	static void GenStatisticsMap( vector<TimingInfo>& times, TimingStatisticsMap& stats ) {
		for( TimingInfo& sample : times ) {
			TimingStatistics& st = stats[ TimingStatisticsKey(sample.operation,sample.numArgs) ];
			if( st.operation == OpNOOP ) {
				st.operation = sample.operation;
				st.average = sample.timeval;
				st.samples = 1;
				st.argcnt = sample.numArgs;
			} else {
				st.average = ((st.average * st.samples) + sample.timeval)/(st.samples + 1);
				st.samples++;
			}
		}
	}
};

inline std::ostream& operator<<(std::ostream& out, const TimingStatistics& t) {
	out << "[" << t.operation << "(" << t.argcnt << "), count=" << t.samples << ",avg=" << t.average << "ms]";
	return out;
}

// this method is used to make a sample plaintext of a given encoding type, for
// use in statistics and benchmarking tools

template<typename Element>
extern Plaintext
MakeRandomPlaintext(CryptoContext<Element> cc, PlaintextEncodings pte);

template<typename Element>
extern void
generateTimings(TimingStatisticsMap& stats,
		CryptoContext<Element> cc,
		PlaintextEncodings pte,
		bool verbose = false,
		int maxIterations = 100,
		bool PrintSizes = false);

}

#endif /* CRYPTOTIMING_H_ */
