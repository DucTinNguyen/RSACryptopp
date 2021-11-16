#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "rsa.h"
#include "osrng.h"
#include "hex.h"
#include "base64.h"
#include "pem.h"
#include "pem_common.h"
#include "pem_common.cpp"
#include "pem_read.cpp"
#include "pem_write.cpp"
#include "integer.h"
#include <iostream>	
#include <string>
#include<fstream>
#include<sstream>

using namespace std;
using namespace CryptoPP;
AutoSeededRandomPool rng;
void GenerateKeyAutomatic()
{	
	
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 3072);
	
	//Create Keys
	RSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(rng, 3072);
	Base64Encoder privatesink(new FileSink("C:\\Users\\Asus\\Desktop\\PrivateKey.txt"));
	privateKey.DEREncode(privatesink);
	privatesink.MessageEnd();

	RSA::PublicKey publicKey(privateKey);
	Base64Encoder publicShink(new FileSink("C:\\Users\\Asus\\Desktop\\PublicKey.txt"));
	publicKey.DEREncode(publicShink);
	publicShink.MessageEnd();
}

Integer Encryption(string plaintext)
{
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 3072);
	const Integer& p = params.GetPrime1();
	const Integer& q = params.GetPrime2();
	const Integer& n = params.GetModulus();
	const Integer& e = params.GetPublicExponent();
	const Integer& d = params.GetPrivateExponent();
	cout << "====================================INFORMATION KEYS:=====================================" << endl;
	cout << "n: " << n << endl;
	cout << "e: " << e << endl;
	cout << "===============================================================================================" << endl;
	//Create Public key and set values
	RSA::PublicKey publicKey;
	publicKey.Initialize(n, e);
	Integer M, C;
	M = Integer((const byte*)plaintext.data(), plaintext.size());
	//Print Ciphertext
	C = publicKey.ApplyFunction(M);
	cout << "Ciphertext: " << hex << C << endl;
	return C;
}
void Decryption(Integer resultCipher)
{
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 3072);
	const Integer& p = params.GetPrime1();
	const Integer& q = params.GetPrime2();
	const Integer& n = params.GetModulus();
	const Integer& e = params.GetPublicExponent();
	const Integer& d = params.GetPrivateExponent();

	RSA::PrivateKey privateKey;
	privateKey.Initialize(n, e, d);
	//
	Integer R;
	R = privateKey.CalculateInverse(rng, resultCipher);
	size_t req = R.MinEncodedSize();
	string text_recover;
	text_recover.resize(req);
	R.Encode((byte*)text_recover.data(), text_recover.size());
	cout << "TEXT RECOVERED: " << text_recover;
}

void EncryptPlaintextFromKeyBoard()
{
	string plaintextType;
	getline(cin >> ws, plaintextType);
	cout << "PLAIN TEXT FROM KEYBOARD: " << plaintextType << endl;
	Integer result = Encryption(plaintextType);
	//write data to file
	ofstream f;
	f.open("C:\\Users\\Asus\\Desktop\\filrEncryp1.txt");
	f << result;
	f.close();
	
}

void EncryptPlaintextFromFile()
{
	string plaintextRead;
	ifstream f;
	f.open("C:\\Users\\Asus\\Desktop\\PlaintextFile.txt");
	getline(f, plaintextRead);
	f.close();
	cout << "Noi dung file: ";
	cout<< plaintextRead;
	cout << endl;
	Integer result = Encryption(plaintextRead);
	//write data to file
	ofstream f1;
	f1.open("C:\\Users\\Asus\\Desktop\\fileEncrypt2.txt");
	f1 << result;
	f1.close();
}
void EncryptionChoice()
{
	cout << "1. Nhap plaintext tu ban phim. \n";
	cout << "2. Doc du lieu tu file co san. \n";
	int choice;
	cout << "Nhap su lua chon cua ban: ";
	cin >> choice;
	switch (choice)
	{
	case 1:
		EncryptPlaintextFromKeyBoard();
		break;
	case 2:
		EncryptPlaintextFromFile();
		break;
	}
}
void DecryptFromTypeKeyBoard()
{
	Integer x;
	cout << "Type value hex: ";
	cin >> hex >> x;

	Integer c(x);
	Decryption(c);
	cout << endl;
}
void DecryptFromFile()
{
	string c;
	//READ FILE fileEncrypt1.txt
	ifstream fs;
	fs.open("C:\\Users\\Asus\\Desktop\\filrEncryp1.txt");
	getline(fs, c);
	
	Integer i;
	istringstream(c) >> i;
	Decryption(i);
	cout << endl;
}
void DecryptionChoice()
{
	cout << "1. Nhap cipher text tu ban phim. \n";
	cout << "2. Doc du lieu tu file ma hoa. \n";
	int choice;
	cout << "Nhap su lua chon cua ban: ";
	cin >> choice;
	switch (choice)
	{
	case 1:
		DecryptFromTypeKeyBoard();
		break;
	case 2:
		DecryptFromFile();
		break;
	}
}

void menu()
{
	cout << "PLEASE TYPE YOUR SELECTION: \n";
	cout << "1. Cho phep lua chon chuc nang sinh khoa ngau nhien(ma hoa xuat ra cac file).\n"; 
	cout << "2. PlainText(ma hoa): Cho phep nhap tu ban phim hoac doc du lieu tu file co san. \n";
	cout << "3. CipherText(giai ma):Cho phep nhap vao duoi dang Hex hoac doc du lieu tu file ma hoa.\n";
	cout << "4. Secret Key / Public Key: Cho phep doc du lieu tu file.\n";
	cout << "Su lua chon cua ban la: ";
}
int main(int argc, char* argv[])
{
	while (true)
	{
		menu();
		int choice;
		cin >> choice;
		switch (choice)
		{
			case 1:
			{
				GenerateKeyAutomatic();
				cout << "TAO KEY THANH CONG -- VUI LONG KIEM TRA FILE O MUC DESKTOP";
				break;
			}
			case 2:
			{
				EncryptionChoice();
				break;
			}
			case 3:
			{
				DecryptionChoice();
				break;
			}
		}
		cout << endl;
	}
		
		
	
	return 0;
}
