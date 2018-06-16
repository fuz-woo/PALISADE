/*
 * @file 
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

#include <string>
#include <iostream>
using namespace std;

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "utils/serializablehelper.h"

using namespace lbcrypto;

enum CmdMode { INTMODE, BYTEMODE } CommandMode = BYTEMODE;
enum ElMode { POLY, DCRT } ElementMode = POLY;

usint	IntVectorLen = 10; // default value

void usage(const string& cmd, const string& msg = "");

template<typename Element>
using cmdparser = void (*)(CryptoContext<Element> ctx, string cmd, int argc, char *argv[]);

template<typename Element>
void
reencrypter(CryptoContext<Element> ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string ciphertextname(argv[0]);
	string rekeyname(argv[1]);
	string reciphertextname(argv[2]);

	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(rekeyname, &kser) == false ) {
		cerr << "Could not read re encryption key" << endl;
		return;
	}

	LPEvalKey<Element> evalKey = ctx->deserializeEvalKey(kser);
	if( evalKey == NULL ) {
		cerr << "Could not deserialize re encryption key" << endl;
		return;
	}

	ofstream outCt(reciphertextname, ios::binary);
	if( !outCt.is_open() ) {
		cerr << "Could not open re-encryption output file";
		return;
	}

	ifstream inCt(ciphertextname, ios::binary);
	if( !inCt.is_open() ) {
		cerr << "Could not open ciphertext input file" << endl;
		outCt.close();
		return;
	}

	ctx->ReEncryptStream(evalKey, inCt, outCt);

	inCt.close();
	outCt.close();
	return;
}

template<typename Element>
void
decrypter(CryptoContext<Element> ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string ciphertextname(argv[0]);
	string prikeyname(argv[1]);
	string cleartextname(argv[2]);

	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(prikeyname, &kser) == false ) {
		cerr << "Could not read private key" << endl;
		return;
	}

	LPPrivateKey<Element> sk = ctx->deserializeSecretKey(kser);
	if( !sk ) {
		cerr << "Could not decrypt private key" << endl;
		return;
	}

	ofstream outF(cleartextname, ios::binary);
	if( !outF.is_open() ) {
		cerr << "Could not open cleartext file";
		return;
	}

	ifstream inCt(ciphertextname, ios::binary);
	if( !inCt.is_open() ) {
		cerr << "Could not open ciphertext" << endl;
		outF.close();
		return;
	}

	if( CommandMode == BYTEMODE ) {
		ctx->DecryptStream(sk, inCt, outF);
	}
	else {
		Serialized	kser;
		if( SerializableHelper::ReadSerializationFromFile(ciphertextname, &kser) == false ) {
			cerr << "Could not read ciphertext" << endl;
			return;
		}

		// Initialize the public key containers.
		Ciphertext<Element> ct = ctx->deserializeCiphertext(kser);
		if( ct == NULL ) {
			cerr << "Could not deserialize ciphertext" << endl;
			return;
		}

		// Decrypt and write out the integers
		Plaintext iPlaintext;

		// now decrypt iPlaintext
		ctx->Decrypt(sk, ct, &iPlaintext);

		for( size_t i=0; i<IntVectorLen; i++ )
			outF << iPlaintext->GetCoefPackedValue()[i] << " ";
		outF << endl;
	}

	inCt.close();
	outF.close();

	return;
}

template<typename Element>
void
encrypter(CryptoContext<Element> ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string plaintextname(argv[0]);
	string pubkeyname(argv[1]);
	string ciphertextname(argv[2]);

	ofstream ctSer(ciphertextname, ios::binary);
	if( !ctSer.is_open() ) {
		cerr << "could not open output file " << ciphertextname << endl;
		return;
	}

	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(pubkeyname, &kser) == false ) {
		cerr << "Could not read public key" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPublicKey<Element> pk = ctx->deserializePublicKey(kser);

	if( !pk ) {
		cerr << "Could not deserialize public key" << endl;
		ctSer.close();
		return;
	}

	// fetch the plaintext to be encrypted
	ifstream inf(plaintextname, ios::binary);
	if( !inf.is_open() ) {
		cerr << "could not read plaintext file " << plaintextname << endl;
		ctSer.close();
		return;
	}

	if( CommandMode == BYTEMODE ) {
		ctx->EncryptStream(pk, inf, ctSer);
	}
	else {
		ctSer.close();

		vector<int64_t> intVector;
		for( size_t i=0; i<IntVectorLen; i++ ) {
			int val;

			inf >> val;
			if( !inf.good() ) {
				break;
			}

			intVector.push_back(val);
		}

		// pull in file full of integers and do the encryption
		Plaintext iPlaintext = ctx->MakeCoefPackedPlaintext(intVector);

		// now encrypt iPlaintext
		Ciphertext<Element> ciphertext = ctx->Encrypt(pk, iPlaintext);

		Serialized cSer;
		if( ciphertext->Serialize(&cSer) ) {
			if( !SerializableHelper::WriteSerializationToFile(cSer, ciphertextname) ) {
				cerr << "Error writing serialization of ciphertext to " + ciphertextname << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing ciphertext" << endl;
			return;
		}
	}

	inf.close();
	ctSer.close();
	return;
}

template<typename Element>
void
rekeymaker(CryptoContext<Element> ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string pubname(argv[0]);
	string privname(argv[1]);
	string rekeyname(argv[2]);

	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(pubname, &kser) == false ) {
		cerr << "Could not read public key" << endl;
		return;
	}

	// Initialize the public key containers.
	LPPublicKey<Element> pk = ctx->deserializePublicKey(kser);

	Serialized	kser2;
	if( SerializableHelper::ReadSerializationFromFile(privname, &kser2) == false ) {
		cerr << "Could not read private key" << endl;
		return;
	}

	LPPrivateKey<Element> sk = ctx->deserializeSecretKey(kser2);

	if( !pk ) {
		cerr << "Could not deserialize public key" << endl;
		return;
	}

	if( !sk ) {
		cerr << "Could not deserialize private key" << endl;
		return;
	}

	LPEvalKey<Element> evalKey = ctx->ReKeyGen(pk, sk);

	if( evalKey ) {
		Serialized evalK;

		if( evalKey->Serialize(&evalK) ) {
			if( !SerializableHelper::WriteSerializationToFile(evalK, rekeyname) ) {
				cerr << "Error writing serialization of recryption key to " + rekeyname << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing recryption key" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating recryption key" << endl;
	}

	return;
}

template<typename Element>
void
keymaker(CryptoContext<Element> ctx, string cmd, int argc, char *argv[]) {
	if( argc != 1 ) {
		usage(cmd, "missing keyname");
		return;
	}

	string keyname(argv[0]);

	// Initialize the public key containers.
	LPKeyPair<Element> kp = ctx->KeyGen();

	if( kp.publicKey && kp.secretKey ) {
		ctx->EvalMultKeyGen(kp.secretKey);

		Serialized ctxSer;
		if( ctx->Serialize(&ctxSer) ) {
			if( !SerializableHelper::WriteSerializationToFile(ctxSer, keyname + "CTXT") ) {
				cerr << "Error writing serialization of cryptocontext to " + keyname + "CTXT" << endl;
				return;
			}
		}
		else {
			cerr << "Could not serialize crypto context" << endl;
			return;
		}

		Serialized emKeys;
		if( ctx->SerializeEvalMultKey(&emKeys) ) {
			if( !SerializableHelper::WriteSerializationToFile(emKeys, keyname + "EMK") ) {
				cerr << "Error writing serialization of eval mult keys to " + keyname + "EMK" << endl;
				return;
			}
		}
		else {
			cerr << "Could not serialize eval mult keys" << endl;
			return;
		}

		Serialized pubK, privK;

		if( kp.publicKey->Serialize(&pubK) ) {
			if( !SerializableHelper::WriteSerializationToFile(pubK, keyname + "PUB") ) {
				cerr << "Error writing serialization of public key to " + keyname + "PUB" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing public key" << endl;
			return;
		}

		if( kp.secretKey->Serialize(&privK) ) {
			if( !SerializableHelper::WriteSerializationToFile(privK, keyname + "PRI") ) {
				cerr << "Error writing serialization of private key to " + keyname + "PRI" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing private key" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating keys" << endl;
	}

	return;
}

template<typename Element>
void
evaladder(CryptoContext<Element> ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string cipher1name(argv[0]);
	string cipher2name(argv[1]);
	string cipheraddname(argv[2]);

	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(cipher1name, &kser) == false ) {
		cerr << "Could not read cipher1" << endl;
		return;
	}

	// Initialize the public key containers.
	Ciphertext<Element> c1 = ctx->deserializeCiphertext(kser);

	if( !c1 ) {
		cerr << "Could not deserialize cipher1" << endl;
		return;
	}

	Serialized	kser2;
	if( SerializableHelper::ReadSerializationFromFile(cipher2name, &kser2) == false ) {
		cerr << "Could not read cipher2" << endl;
		return;
	}

	// Initialize the public key containers.
	Ciphertext<Element> c2 = ctx->deserializeCiphertext(kser2);

	if( !c2 ) {
		cerr << "Could not deserialize cipher2" << endl;
		return;
	}

	Ciphertext<Element> cdsum = ctx->EvalAdd(c1, c2);

	Serialized cSer;
	if( cdsum->Serialize(&cSer) ) {
		if( !SerializableHelper::WriteSerializationToFile(cSer, cipheraddname) ) {
				cerr << "Error writing serialization of ciphertext to " + cipheraddname << endl;
				return;
		}
	}
	else {
		cerr << "Error serializing ciphertext" << endl;
		return;
	}

	return;
}

template<typename Element>
void
evalmulter(CryptoContext<Element> ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string cipher1name(argv[0]);
	string cipher2name(argv[1]);
	string ciphermulname(argv[2]);

	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(cipher1name, &kser) == false ) {
		cerr << "Could not read cipher1" << endl;
		return;
	}

	// Initialize the public key containers.
	Ciphertext<Element> c1 = ctx->deserializeCiphertext(kser);

	if( !c1 ) {
		cerr << "Could not deserialize cipher1" << endl;
		return;
	}

	Serialized	kser2;
	if( SerializableHelper::ReadSerializationFromFile(cipher2name, &kser2) == false ) {
		cerr << "Could not read cipher2" << endl;
		return;
	}

	// Initialize the public key containers.
	Ciphertext<Element> c2 = ctx->deserializeCiphertext(kser2);

	if( !c2 ) {
		cerr << "Could not deserialize cipher2" << endl;
		return;
	}

	Ciphertext<Element> cdsum = ctx->EvalMult(c1, c2);

	Serialized cSer;
	if( cdsum->Serialize(&cSer) ) {
		if( !SerializableHelper::WriteSerializationToFile(cSer, ciphermulname) ) {
				cerr << "Error writing serialization of ciphertext to " + ciphermulname << endl;
				return;
		}
	}
	else {
		cerr << "Error serializing ciphertext" << endl;
		return;
	}

	return;
}


struct {
	string				command;
	cmdparser<Poly>		func;
	cmdparser<DCRTPoly>	dfunc;
	string				helpline;
} cmds[] = {
		{"makekey", keymaker<Poly>, keymaker<DCRTPoly>, " [optional parms] keyname\n"
		"\tcreate a new keypair\n\t\tsave keynamePUB, keynamePRI, keynameCTXT and keynameEMK"},
		{"makerekey", rekeymaker<Poly>, rekeymaker<DCRTPoly>, " [optional parms] pubkey_file secretkey_file rekey_file\n"
		"\tcreate a re-encryption key from the contents of pubkey_file and secretkey_file\n\tsave in rekey_file"},
		{"encrypt", encrypter<Poly>, encrypter<DCRTPoly>, " [optional parms] plaintext_file pubkey_file ciphertext_file\n"
		"\tencrypt the contents of plaintext_file using the contents of pubkey_file\n\tsave results in ciphertext_file"},
		{"reencrypt", reencrypter<Poly>, reencrypter<DCRTPoly>, " [optional parms] encrypted_file rekey_file reencrypted_file\n"
		"\treencrypt the contents of encrypted_file using the contents of rekey_file\n\tsave results in reencrypted_file"},
		{"decrypt", decrypter<Poly>, decrypter<DCRTPoly>, " [optional parms] ciphertext_file prikey_file cleartext_file\n"
		"\tdecrypt the contents of ciphertext_file using the contents of prikey_file\n\tsave results in cleartext_file"},
		{"evaladd", evaladder<Poly>, evaladder<DCRTPoly>, " [optional parms] ciphertext1 ciphertext2 addresult\n"
		"\teval-add both ciphertexts\n\tsave result in addresult"},
		{"evalmult", evalmulter<Poly>, evalmulter<DCRTPoly>, " [optional parms] ciphertext1 ciphertext2 multresult\n"
		"\teval-mult both ciphertexts\n\tsave result in multresult"},
};

void
usage(const string& cmd, const string& msg)
{
	if( msg.length() > 0 )
		cerr << msg << endl;

	for( size_t i=0; i<sizeof(cmds)/sizeof(cmds[0]); i++ ) {
		if( cmd == "ALL" || cmd == cmds[i].command )
			cerr << "palisade " << cmds[i].command << cmds[i].helpline << endl;
	}

	cerr << endl;
	cerr << "[optional params] are:" << endl;
	cerr << "-poly: (default) use Poly" << endl;
	cerr << "-dcrt: use DCRTPoly instead of Poly" << endl;
	cerr << "-integers: use integer plaintext with " << IntVectorLen << " integers\n\tplaintext file is ascii ints delimited by whitespace" << endl;
	cerr << "-intlen N: use integer plaintext with N integers; default is " << IntVectorLen << endl;
	cerr << "-list: list all the parameter sets, then exit" << endl;
	cerr << "-use parmset: use the parameter set named parmset from the parameter file" << endl;
	cerr << "-from keyname: use the serialization of keynameCTXT and EMK for the crypto context" << endl;
}

int
main( int argc, char *argv[] )
{
	if( argc < 2 ) {
		usage("ALL");
		return 1;
	}

	if( string(argv[1]) == "-list" ) {
		CryptoContextHelper::printAllParmSetNames(cout);
		return 0;
	}

	CryptoContext<Poly> ctx;
	CryptoContext<DCRTPoly> dctx;

	int cmdidx = 1;
	while( cmdidx < argc ) {
		string arg(argv[cmdidx]);
		if( arg == "-integers" ) {
			CommandMode = INTMODE;
			cmdidx++;
		}

		else if( arg == "-intlen" && cmdidx+1 < argc ) {
			CommandMode = INTMODE;
			IntVectorLen = stoi( string(argv[cmdidx + 1]) );
			cmdidx+= 2;
		}

		else if( arg == "-use" && cmdidx+1 < argc) {
			if( ElementMode == POLY ) {
				ctx = CryptoContextHelper::getNewContext( string(argv[cmdidx+1]) );
				if( !ctx ) {
					cerr << "Could not construct a crypto context" << endl;
					return 1;
				}
			}
			else if( ElementMode == DCRT ) {
				dctx = CryptoContextHelper::getNewDCRTContext( string(argv[cmdidx+1]), 5, 32 );
				if( !dctx ) {
					cerr << "Could not construct a dcrt crypto context" << endl;
					return 1;
				}
			}

			cmdidx += 2;
		}
		else if( arg == "-from" && cmdidx+1 < argc ) {
			Serialized	cser;
			string cfile( string(argv[cmdidx+1])+"CTXT" );
			if( SerializableHelper::ReadSerializationFromFile(cfile, &cser) ) {
				if( ElementMode == POLY )
					ctx = CryptoContextFactory<Poly>::DeserializeAndCreateContext(cser);
				else if( ElementMode == DCRT )
					dctx = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(cser);
			}
			else {
				cerr << "Could not construct a crypto context from the file " << cfile << endl;
				return 1;
			}

			// now get the keys
			Serialized kser;
			bool result = false;
			string kfile( string(argv[cmdidx+1])+"EMK" );
			if( SerializableHelper::ReadSerializationFromFile(kfile, &kser) ) {
				if( ElementMode == POLY )
					result = ctx->DeserializeEvalMultKey(kser);
				else if( ElementMode == DCRT )
					result = dctx->DeserializeEvalMultKey(kser);
			}

			if( !result ) {
				cerr << "Could not get evalmult keys from the file " << kfile << endl;
				return 1;
			}

			cmdidx += 2;
		}
		else if( arg == "-dcrt" ) {
			ElementMode = DCRT;
			cmdidx++;
		}
		else if( arg == "-poly" ) {
			ElementMode = POLY;
			cmdidx++;
		}
		else
			break;
	}

	if( !ctx && !dctx ) {
		cout << "Defaulting to LTV5" << endl;
		if( ElementMode == POLY )
			ctx = CryptoContextHelper::getNewContext( "LTV5" );
		else if( ElementMode == DCRT )
			dctx = CryptoContextHelper::getNewDCRTContext( "LTV5", 5, 32 );
	}

	if( !ctx && !dctx ) {
		cerr << "Unable to create a crypto context" << endl;
		return 1;
	}

	if( cmdidx >= argc ) {
		usage("ALL");
		return 1;
	}

	if( ElementMode == POLY ) {
		ctx->Enable(ENCRYPTION);
		ctx->Enable(PRE);
		ctx->Enable(SHE);
	}
	else if( ElementMode == DCRT ) {
		dctx->Enable(ENCRYPTION);
		dctx->Enable(PRE);
		dctx->Enable(SHE);
	}

	bool	rancmd = false;
	string userCmd(argv[cmdidx]);
	for( size_t i=0; i<(sizeof(cmds)/sizeof(cmds[0])); i++ ) {
		if( cmds[i].command == string(userCmd) ) {
			if( ElementMode == POLY )
				(*cmds[i].func)(ctx, cmds[i].command, argc-1-cmdidx, &argv[cmdidx + 1]);
			else if( ElementMode == DCRT )
				(*cmds[i].dfunc)(dctx, cmds[i].command, argc-1-cmdidx, &argv[cmdidx + 1]);
			rancmd = true;
			break;
		}
	}

	if( !rancmd ) {
		usage("ALL", "invalid command " + userCmd);
		return 1;
	}

	return 0;
}
