/**
 * @file demo-timing.cpp -- Demonstrate the use of the TimingInfo feature of the CryptoContext
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
 * reads file of needed timings; generates timings for estimator
 *
 */

#include "palisade.h"
#include "cryptocontextgen.h"
#include "cryptocontextparametersets.h"
using namespace lbcrypto;
using std::cout;

#include <fstream>
#include <unordered_set>
using std::istream;
using std::ostream;
using std::unordered_set;

void
usage(string progname, const string& msg = "") {
	if( msg.length() > 0 ) {
		cerr << msg << endl;
	}
	cerr << "Usage is:" << endl;
	cerr << progname <<
			" [-v] [-i iteration_count] [-printsizes] [-dcrt|-poly|-native] [-cfile SERIALIZATION-FILE | -cpre PREDEFINED ]"
			<< endl;
	cerr << "      -poly is the default" << endl;
}

int
main(int argc, char *argv[])
{
	bool verbose = false;
	bool printsizes = false;
	int MaxIterations = 100;

	enum Element { POLY, DCRT, NATIVE } element = POLY;
	string ctxtFile;
	string ctxtName;

	for( int i=1; i<argc; i++ ) {
		string arg( argv[i] );

		if( arg == "-v" )
			verbose = true;
		else if( arg == "-dcrt" )
			element = DCRT;
		else if( arg == "-poly" )
			element = POLY;
		else if( arg == "-native" )
			element = NATIVE;
		else if( arg == "-printsizes" )
			printsizes = true;
		else if( arg == "-i" ) {
			if( i+1 == argc ) {
				usage("Filename missing after -cfile");
				return 1;
			}
			MaxIterations = stoi(argv[++i]);
		}
		else if( arg == "-cfile" ) {
			if( i+1 == argc ) {
				usage("Filename missing after -cfile");
				return 1;
			}
			ctxtFile = argv[++i];
		}
		else if( arg == "-cpre" ) {
			if( i+1 == argc ) {
				usage("Context name missing after -cpre");
				return 1;
			}
			ctxtName = argv[++i];
		}
		else {
			usage(argv[0], "Unrecognized argument " + arg);
			return 1;
		}
	}

	CryptoContext<Poly> cc;
	CryptoContext<DCRTPoly> dcc;
	CryptoContext<NativePoly> ncc;

	if( ctxtFile.length() == 0 && ctxtName.length() == 0 ) {
		usage(argv[0], "Must specify -cfile or -cpre");
		return 1;
	}

	if( ctxtFile.length() > 0 && ctxtName.length() > 0 ) {
		usage(argv[0], "Must specify -cfile or -cpre, not both!");
		return 1;
	}

	if( ctxtFile.length() > 0 ) {
		ifstream in( ctxtFile );
		if( !in.is_open() ) {
			cout << "Cannot open input file " << ctxtFile << endl;
			return 1;
		}

		Serialized serObj;
		if( SerializableHelper::StreamToSerialization(in, &serObj) == false ) {
			cout << "Input file could not be deserialized" << endl;
			return 1;
		}

		if( element == POLY )
			cc = CryptoContextFactory<Poly>::DeserializeAndCreateContext(serObj);
		else if( element == DCRT )
			dcc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(serObj);
		else
			ncc = CryptoContextFactory<NativePoly>::DeserializeAndCreateContext(serObj);

	}
	else {
		if( !knownParameterSet(ctxtName) ) {
			cout << ctxtName << " is not a known parameter set name" << endl;
			cout << "Choices are: ";
			CryptoContextHelper::printAllParmSetNames(cout);
			return 1;
		}

		if( element == POLY )
			cc = CryptoContextHelper::getNewContext(ctxtName);
		else if( element == DCRT )
			dcc = CryptoContextHelper::getNewDCRTContext(ctxtName, 3, 20);
		else {

		}
	}

	if( cc == 0 && dcc == 0 && ncc == 0 ) {
		cout << "Unable to create CryptoContext" << endl;
		return 1;
	}

	TimingStatisticsMap stats;

	if( element == POLY ) {
		generateTimings(stats, cc, CoefPacked, verbose, MaxIterations, printsizes);
		cout << *cc->GetElementParams() << endl;
		cout << *cc->GetEncodingParams() << endl;
	}
	else if( element == DCRT ) {
		generateTimings(stats, dcc, CoefPacked, verbose, MaxIterations, printsizes);
		cout << *dcc->GetElementParams() << endl;
		cout << *dcc->GetEncodingParams() << endl;
	}
	else {
		generateTimings(stats, ncc, CoefPacked, verbose, MaxIterations, printsizes);
		cout << *ncc->GetElementParams() << endl;
		cout << *ncc->GetEncodingParams() << endl;
	}

	// read them out
	for( auto &tstat : stats ) {
		cout << tstat.second << endl;
		cout << tstat.second.operation << ": " << tstat.second.average <<endl;
	}

}
