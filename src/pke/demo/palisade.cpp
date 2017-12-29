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
usint	IntVectorLen = 10; // default value

void usage(const string& cmd, const string& msg = "");

typedef void (*cmdparser)(CryptoContext<Poly> ctx, string cmd, int argc, char *argv[]);

void
reencrypter(CryptoContext<Poly> ctx, string cmd, int argc, char *argv[]) {
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

	LPEvalKey<Poly> evalKey = ctx->deserializeEvalKey(kser);
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

void
decrypter(CryptoContext<Poly> ctx, string cmd, int argc, char *argv[]) {
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

	LPPrivateKey<Poly> sk = ctx->deserializeSecretKey(kser);
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
		Ciphertext<Poly> ct = ctx->deserializeCiphertext(kser);
		if( ct == NULL ) {
			cerr << "Could not deserialize ciphertext" << endl;
			return;
		}

		// Decrypt and write out the integers
		Plaintext iPlaintext;

		// now decrypt iPlaintext
		ctx->Decrypt(sk, ct, &iPlaintext);

		outF << iPlaintext << endl;
	}

	inCt.close();
	outF.close();

	return;
}

void
encrypter(CryptoContext<Poly> ctx, string cmd, int argc, char *argv[]) {
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
	LPPublicKey<Poly> pk = ctx->deserializePublicKey(kser);

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
		Ciphertext<Poly> ciphertext = ctx->Encrypt(pk, iPlaintext);

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

void
rekeymaker(CryptoContext<Poly> ctx, string cmd, int argc, char *argv[]) {
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
	LPPublicKey<Poly> pk = ctx->deserializePublicKey(kser);

	Serialized	kser2;
	if( SerializableHelper::ReadSerializationFromFile(privname, &kser2) == false ) {
		cerr << "Could not read private key" << endl;
		return;
	}

	LPPrivateKey<Poly> sk = ctx->deserializeSecretKey(kser2);

	if( !pk ) {
		cerr << "Could not deserialize public key" << endl;
		return;
	}

	if( !sk ) {
		cerr << "Could not deserialize private key" << endl;
		return;
	}

	LPEvalKey<Poly> evalKey = ctx->ReKeyGen(pk, sk);

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

void
keymaker(CryptoContext<Poly> ctx, string cmd, int argc, char *argv[]) {
	if( argc != 1 ) {
		usage(cmd, "missing keyname");
		return;
	}

	string keyname(argv[0]);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = ctx->KeyGen();

	if( kp.publicKey && kp.secretKey ) {
		Serialized pubK, privK;

		if( kp.publicKey->Serialize(&pubK) ) {
			if( !SerializableHelper::WriteSerializationToFile(pubK, keyname + "PUB.txt") ) {
				cerr << "Error writing serialization of public key to " + keyname + "PUB.txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing public key" << endl;
			return;
		}

		if( kp.secretKey->Serialize(&privK) ) {
			if( !SerializableHelper::WriteSerializationToFile(privK, keyname + "PRI.txt") ) {
				cerr << "Error writing serialization of private key to " + keyname + "PRI.txt" << endl;
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

void
evaladder(CryptoContext<Poly> ctx, string cmd, int argc, char *argv[]) {
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
	Ciphertext<Poly> c1 = ctx->deserializeCiphertext(kser);

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
	Ciphertext<Poly> c2 = ctx->deserializeCiphertext(kser2);

	if( !c2 ) {
		cerr << "Could not deserialize cipher2" << endl;
		return;
	}

	cout << "EvalAdd-ing:" << endl;
	for( size_t i=0; i<IntVectorLen; i++ ) cout << c1->GetElement().at(i) << " ";
	cout << endl;
	for( size_t i=0; i<IntVectorLen; i++ ) cout << c2->GetElement().at(i) << " ";
	cout << endl;
	Ciphertext<Poly> cdsum = ctx->EvalAdd(c1, c2);
	cout << "Result:" << endl;
	for( size_t i=0; i<IntVectorLen; i++ ) cout << cdsum->GetElement().at(i) << " ";
	cout << endl;

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

//	if( !er.isValid ) {
//		cerr << "failed to encrypt" << endl;
//	}

	return;
}

void
evalmulter(CryptoContext<Poly> ctx, string cmd, int argc, char *argv[]) {
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
	Ciphertext<Poly> c1 = ctx->deserializeCiphertext(kser);

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
	Ciphertext<Poly> c2 = ctx->deserializeCiphertext(kser2);

	if( !c2 ) {
		cerr << "Could not deserialize cipher2" << endl;
		return;
	}

	cout << "EvalMult-ing:" << endl;
	for( size_t i=0; i<IntVectorLen; i++ ) cout << c1->GetElement().at(i) << " ";
	cout << endl;
	for( size_t i=0; i<IntVectorLen; i++ ) cout << c2->GetElement().at(i) << " ";
	cout << endl;
	Ciphertext<Poly> cdsum = ctx->EvalMult(c1, c2);
	cout << "Result:" << endl;
	for( size_t i=0; i<IntVectorLen; i++ ) cout << cdsum->GetElement().at(i) << " ";
	cout << endl;

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

//	if( !er.isValid ) {
//		cerr << "failed to encrypt" << endl;
//	}

	return;
}


struct {
	string		command;
	cmdparser	func;
	string		helpline;
} cmds[] = {
		{"makekey", keymaker, " [optional parms] keyname\n"
		"\tcreate a new keypair and save in keyfilePUB.txt and keyfilePRI.txt"},
		{"makerekey", rekeymaker, " [optional parms] pubkey_file secretkey_file rekey_file\n"
		"\tcreate a re-encryption key from the contents of pubkey_file and secretkey_file, save in rekey_file"},
		{"encrypt", encrypter, " [optional parms] plaintext_file pubkey_file ciphertext_file\n"
		"\tencrypt the contents of plaintext_file using the contents of pubkey_file, save results in ciphertext_file"},
		{"reencrypt", reencrypter, " [optional parms] encrypted_file rekey_file reencrypted_file\n"
		"\treencrypt the contents of encrypted_file using the contents of rekey_file, save results in reencrypted_file"},
		{"decrypt", decrypter,  " [optional parms] ciphertext_file prikey_file cleartext_file\n"
		"\tdecrypt the contents of ciphertext_file using the contents of prikey_file, save results in cleartext_file"},
		{"evaladd", evaladder, " [optional parms] ciphertext1 ciphertext2 addresult\n"
		"\teval-add both ciphertexts\n"},
		{"evalmult", evalmulter, " [optional parms] ciphertext1 ciphertext2 addresult\n"
		"\teval-mult both ciphertexts\n"},
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
	cerr << "-integers: indicates system should use int plaintext instead of byte plaintext: plaintext file is ascii ints delimited by whitespace" << endl;
	cerr << "-intlen N: when using integers, indicates number of integers in the int plaintext; default is 5. activates -integers mode" << endl;
	cerr << "-list filename: list all the parameter sets in the file filename, then exit" << endl;
	cerr << "-use filename parmset: use the parameter set named parmset from the parameter file" << endl;
	cerr << "-from filename: use the deserialization of filename to set the crypto context" << endl;
}

int
main( int argc, char *argv[] )
{
	if( argc < 2 ) {
		usage("ALL");
		return 1;
	}

	if( string(argv[1]) == "-list" && argc == 3) {
		CryptoContextHelper::printAllParmSets(cout);
		return 0;
	}

	CryptoContext<Poly> ctx;

	int cmdidx = 1;
	while( cmdidx < argc ) {
		if( string(argv[cmdidx]) == "-integers" ) {
			CommandMode = INTMODE;
			cmdidx++;
		}

		else if( string(argv[cmdidx]) == "-intlen" && cmdidx+1 < argc ) {
			CommandMode = INTMODE;
			IntVectorLen = stoi( string(argv[cmdidx + 1]) );
			cmdidx+= 2;
		}

		else if( string(argv[cmdidx]) == "-use" && cmdidx+1 < argc) {
			ctx = CryptoContextHelper::getNewContext( string(argv[cmdidx+1]) );
			if( !ctx ) {
				usage("ALL", "Could not construct a crypto context");
				return 1;
			}

			cmdidx += 2;
		}
		else if( string(argv[cmdidx]) == "-from" && cmdidx+1 < argc ) {
			Serialized	kser;
			if( SerializableHelper::ReadSerializationFromFile(string(argv[cmdidx+1]), &kser) ) {
				ctx = CryptoContextFactory<Poly>::DeserializeAndCreateContext(kser);
			}

			cmdidx += 2;
		}
		else
			break;
	}

	if( !ctx ) {
		cout << "Defaulting to LTV5" << endl;
		ctx = CryptoContextHelper::getNewContext( "LTV5" );
	}

	if( !ctx ) {
		usage("ALL", "Unable to create a crypto context");
		return 1;
	}

	if( cmdidx >= argc ) {
		usage("ALL");
		return 1;
	}

	ctx->Enable(ENCRYPTION);
	ctx->Enable(PRE);
	ctx->Enable(SHE);

	bool	rancmd = false;
	string userCmd(argv[cmdidx]);
	for( size_t i=0; i<(sizeof(cmds)/sizeof(cmds[0])); i++ ) {
		if( cmds[i].command == string(userCmd) ) {
			(*cmds[i].func)(ctx, cmds[i].command, argc-1-cmdidx, &argv[cmdidx + 1]);
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
