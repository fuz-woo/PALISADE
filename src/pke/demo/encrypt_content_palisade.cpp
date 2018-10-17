#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <random>
#include <stdio.h>
#include <unistd.h>

#include "../lib/cryptocontext.h"
#include "../lib/cryptocontexthelper.h"
#include "../lib/cryptocontexthelper-impl.cpp"
#include "../lib/utils/serializable.h"
#include "../lib/utils/serializablehelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

#include <cstdio>

using namespace std;
using namespace lbcrypto;
using namespace rapidjson;


struct EncInfo
{
    CryptoContext<Poly> cryptocontext;
    LPKeyPair<Poly> keypair;
};

EncInfo info;

//const int IntVectorLen = 10;

int generate_crypto_context() {
	usint m = 22;
	usint p = 2069;

	BigInteger modulusP(p);
	
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	info.cryptocontext = cc;

	PackedEncoding::SetParams(m, encodingParams);

	return 1;
}


int generate_keys_and_write_to_files(){
cout << "Here is the context I am using: " << *info.cryptocontext->GetCryptoParameters() << endl;
	LPKeyPair<Poly> kp = info.cryptocontext->KeyGen();
	info.keypair = kp;
	info.cryptocontext->EvalSumKeyGen(kp.secretKey);
	info.cryptocontext->EvalMultKeyGen(kp.secretKey);
	
	Serialized pubK, privK;
	if ( kp.publicKey->Serialize(&pubK) ) {
		if (!SerializableHelper::WriteSerializationToFile(pubK, "./encryption_info_pubK.txt") ) {
			cerr << "Error writing serialization of public key to ./encryption_info_pubK.txt" << endl;
			return 0;
		}
	} else {
		cerr << "Error serializing public key" << endl;
		return 0;
	}
	if ( kp.secretKey->Serialize(&privK) ) {
		if (!SerializableHelper::WriteSerializationToFile(privK, "./encryption_info_priK.txt") ) {
			cerr << "Error writing serialization of public key to ./encryption_info_priK.txt" << endl;
			return 0;
		}
	} else {
		cerr << "Error serializing private key" << endl;
		return 0;
	}
	
	vector<uint64_t> *v = new vector<uint64_t>();
	v->push_back(86);
cout << "Here's my vector" << *v << endl;
	Ciphertext<Poly> ciphertext;
	vector<uint64_t> vectorOfInts = move(*v);
	Plaintext intArray = info.cryptocontext->MakePackedPlaintext(vectorOfInts);
cout << "I am about to encrypt this: " << intArray << endl;

	ciphertext = info.cryptocontext->Encrypt(info.keypair.publicKey, intArray);
	Serialized cSer;
	string str;
	if ( ciphertext->Serialize(&cSer) ) {
		if( !SerializableHelper::WriteSerializationToFile(cSer, "./ctxt_check.txt") ) {
			cerr << "Error writing serialization of ciphertext to ctxt_check.txt" << endl;
			return 0;
		}
	} else {
		cerr << "Error serializing ciphertext" << endl;
		return 0;
	}
		
	return 1;
}


int read_public_key_from_file(){
	Serialized kser;
	if ( SerializableHelper::ReadSerializationFromFile("./encryption_info_pubK.txt", &kser) == false ) {
		cerr << "Could not read public key" << endl;
		return 0;
	}

	LPPublicKey<Poly> pk = info.cryptocontext->deserializePublicKey(kser);
	if ( !pk ) {
		cerr << "Could not deserialize public key" << endl;
		return 0;
	}
	info.keypair.publicKey = pk;

	return 1;
}

int read_private_key_from_file(){
	Serialized kser;
	FILE* fp = fopen("./encryption_info_priK.txt", "r");
	char readBuffer[65536];
	FileReadStream sSK(fp, readBuffer, sizeof(readBuffer));
	//SerialItem a(kArrayType);
	kser.ParseStream(sSK);
	fclose(fp);
	
	info.cryptocontext = CryptoContextFactory<Poly>::DeserializeAndCreateContext(kser);
	LPPrivateKey<Poly> sk = info.cryptocontext->deserializeSecretKey(kser);
	info.keypair.secretKey = sk;

cout << *info.cryptocontext->GetCryptoParameters() << endl;

	if ( !sk ) {
		cerr << "Could not deserialize public key" << endl;
		return 0;
	}

	Serialized cSer;
	FILE* fp2 = fopen("./ctxt_check.txt", "r");
	char readBuffer2[65536];
	FileReadStream sCTXT(fp2, readBuffer2, sizeof(readBuffer));
	cSer.ParseStream(sCTXT);
	fclose(fp2);
	if( SerializableHelper::ReadSerializationFromFile("./ctxt_check.txt", &cSer) == false ) {
		cerr << "Could not read ciphertext" << endl;
		return 0;
	}
		Plaintext iPlaintext;
			
	Ciphertext<Poly> ct = info.cryptocontext->deserializeCiphertext(cSer);
	if( ct == NULL ) {
		cerr << "Could not deserialize ciphertext" << endl;
		return 0;
	}

	//Ciphertext<Poly> ciphertext( { ct } );


//auto m = info.cryptocontext->GetElementParams()->GetCyclotomicOrder();
////auto modulusQ = info.cryptocontext->GetElementParams()->GetModulus();
////auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
////ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);
//PackedEncoding::SetParams(m, info.cryptocontext->GetEncodingParams());
	info.cryptocontext->Decrypt(sk, ct, &iPlaintext);	

cout << *iPlaintext << endl;
cout << iPlaintext->GetPackedValue()[0] << " is value" << endl;
	if ( 86 == iPlaintext->GetPackedValue()[0] ) {
		cout << "Cryptocontext generated successfully!" << endl;
		cout << 1;
		return 1;
	} else {
		cout << 0;
		return 0;		
	}
	return 1;
}

vector<uint64_t> split(const string &s, char delim) {
    stringstream ss(s);
    string item;
    vector<uint64_t> tokens;
    while (getline(ss, item, delim)) {
        tokens.push_back(stod(item));
		}
    return tokens;
}

int encrypt_content( string& content_file ) {
	ifstream file ( content_file );
	string value;
	vector<uint64_t> tokens;
	string output_filename = content_file;
	output_filename.replace(output_filename.end()-4,output_filename.end(),"_enc.txt");
	ofstream enc_file( output_filename, ios::out | ios::binary );
	OStreamWrapper oo(enc_file);
	
	Writer<OStreamWrapper> ww(oo);
	
	ww.StartArray();

//	Serialized serial;
//	SerialItem a(kArrayType);
//	Serialized::AllocatorType& allocator = serial.GetAllocator();
	
	if ( !file.good() ) {
		cerr << "Failed to open input plaintext file" << endl;
		return 0;
	}

	if( !enc_file.is_open() ) {
		cerr << "could not open output file " << output_filename << endl;
		return 0;
	}
	while ( file.good() ) {	
		vector<uint64_t> *v = new vector<uint64_t>();
		getline ( file, value ); 
		tokens = split(value, ',');
		for ( vector<uint64_t>::size_type i = 0; i != tokens.size(); i++ ) {
			v->push_back(tokens[i]);
		}

		Ciphertext<Poly> ciphertext;
		vector<uint64_t> vectorOfInts = move(*v);
		Plaintext intArray = info.cryptocontext->MakePackedPlaintext(vectorOfInts); // TODO INCORPORATE NEGATIVE VALUES AS WELL
	
		ciphertext = info.cryptocontext->Encrypt(info.keypair.publicKey, intArray);

		Serialized cSer;
		string str;
		if ( ciphertext->Serialize(&cSer) ) {
			//cSer.Accept(ww);
			SerializableHelper::SerializationToString(cSer,str);
			ww.String(str);
//			a.PushBack(cSer, allocator);
		} else {
			cerr << "Error serializing ciphertext" << endl;
			return 0;
		}
	}
	ww.EndArray();
	file.close();
	enc_file.close();
	return 1;
}


bool FileExists( const string& name ) {
	ifstream file(name);
    if(!file) {
        return false;
    } else {
        return true;
	}
}


bool which_bool(string val) {
	if (val == "0") { return false; }
	return true;
}

int main(int argc, char** argv){
	if (argc < 2) {
		printf("ERROR IN NUMBER OF ARGUMENTS FOR ENCRYPTING CONTENT.\n");
	} else {
		string content_file = argv[1];
		bool exists = FileExists("./encryption_info_priK.txt") and FileExists("./encryption_info_pubK.txt");
		if (exists) {
			if ( read_private_key_from_file() == false) {
				cerr << "Failed to read private key from file" << endl;
				return 0;
			}
			
			if ( read_public_key_from_file() == false ) {
				cerr << "Failed to read public key from file" << endl;
			}

			encrypt_content(content_file);
		} else {
			if ( generate_crypto_context() == false) {
				cerr << "Failed to generate cryptocontext" << endl;
			}
            cout << 1;
			/*int is_written =*/ generate_keys_and_write_to_files();
			encrypt_content(content_file);
		}
	}
	return 0;
}
//make makeencryptcontent
//./encrypt_content ./Sample1_vecs.csv
