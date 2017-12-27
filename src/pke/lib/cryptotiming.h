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

// these variables are used to track timings
enum OpType {
	OpNOOP,
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
	OpEvalMult, OpEvalMultMatrix, OpEvalMultPlain,
	OpEvalNeg, OpEvalNegMatrix,
	OpEvalAutomorphismKeyGen,
	OpEvalAutomorphismI,
	OpEvalAutomorphismK,
	OpLinRegression, OpKeySwitch,
	OpModReduce, OpModReduceRational, OpModReduceMatrix, OpLevelReduce, OpRingReduce, OpComposedEvalMult,
	OpEvalSumKeyGen, OpEvalSum, OpEvalInnerProduct, OpEvalCrossCorrelation, OpEvalLinRegressionBatched,
};

class TimingInfo {
public:
	OpType	operation;
	double	timeval;
	TimingInfo(OpType o, double t) : operation(o), timeval(t) {}
};

class TimingStatistics {
public:
	OpType	operation;
	usint	samples;
	double	startup;
	bool	wasCalled;
	double	min;
	double	max;
	double	average;

	TimingStatistics() : operation(OpNOOP), samples(0), startup(0), wasCalled(false),
			min(std::numeric_limits<double>::max()),
			max(std::numeric_limits<double>::min()), average(0) {}
	TimingStatistics(double startup, double min, double max, double average) : operation(OpNOOP), samples(0),
			startup(startup), wasCalled(false),
			min(min), max(max), average(average) {}
	bool Serialize(Serialized* serObj) const;
	bool Deserialize(const Serialized& serObj);
	const TimingStatistics operator+(const TimingStatistics& op) const {
		return TimingStatistics( startup, min + op.min, max + op.max, average + op.average);
	}
	TimingStatistics& operator+=(const TimingStatistics& op) {
		startup = op.startup, min += op.min, max += op.max, average += op.average;
		return *this;
	}
	double GetEstimate() {
		if( wasCalled ) return average;
		wasCalled = true;
		return startup;
	}
};

extern std::map<OpType,string> OperatorName;
extern std::map<OpType,PKESchemeFeature> OperatorFeat;
extern std::map<string,OpType> OperatorType;

extern std::ostream& operator<<(std::ostream& out, const OpType& op);

inline std::ostream& operator<<(std::ostream& out, const TimingInfo& t) {
	out << t.operation << ": " << t.timeval;
	return out;
}

inline std::ostream& operator<<(std::ostream& out, const TimingStatistics& t) {
	out << "(startup=" << t.startup << ",min=" << t.min << ",max=" << t.max << ",avg=" << t.average << ")";
	return out;
}

}

#endif /* CRYPTOTIMING_H_ */
