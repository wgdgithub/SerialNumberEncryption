#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <io.h>
#include <fstream>
#include <string>
#include <filesystem>
#include <codecvt>
#include <windows.h>
#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"


using namespace std;
namespace fs = std::filesystem;

void readSN(string& csproductID);
bool compareSN(string csproductID);
std::string aes_encrypt_ecb_hex(std::string data, unsigned char* key, int keylen);
std::string aes_decrypt_ecb_hex(std::string hex_data, unsigned char* key, int keylen);
bool isValidChar(char c);
bool isValidStringSame(const std::string& str1, const std::string& str2);

int main()
{
	/** 密文存储文件路径*/
	fs::path currentPath = ".";
	fs::path filePath = currentPath / "a.txt";

	/** 密文文件存在*/
	if (fs::exists(filePath))
	{
		string csproductID; //存储主板序列号
		readSN(csproductID); //读取密文文件正确的序列号存入csproductID
		if (csproductID == "decrypt erro")
		{
			//不能运行
			std::cout << "fail" << std::endl;
			exit(1);
		}

		
		bool result = compareSN(csproductID);

		if (result)
		{
			//可以运行
			std::cout << "success" << std::endl;
			exit(0);
		}
		else
		{
			//不能运行
			std::cout << "fail" << std::endl;
			exit(1);
		}
	}
	else
	{
		//向a.txt存入序列号密文
		system("wmic csproduct get UUID> temp.txt");
		ifstream file("temp.txt");
		string line;
		string csproductID;
		int n = 1;
		while (std::getline(file, line)) {
			if (n == 2)
			{
				csproductID = line;
			}
			n++; 
		}
		file.close();
		remove("temp.txt");

		csproductID.erase(std::remove_if(csproductID.begin(), csproductID.end(), ::isspace), csproductID.end());

		string cipherID = aes_encrypt_ecb_hex(csproductID, (unsigned char*)"159753", 16);

		ofstream outfile("a.txt");
		if (!outfile)
		{
			exit(1);
		}
		
		cipherID.erase(std::remove_if(cipherID.begin(), cipherID.end(), ::isspace), cipherID.end());

		outfile << cipherID;
		
		//可以运行
		cout << "success" << endl;
		system("pause");
	}
}

//读取密文文件正确的序列号
void readSN(string& csproductID)
{
	cout << "开始读取密文文件..." << endl;

	/** 读取密文文件加密后的内容，存入aes_csproductID*/
	std::ifstream file("a.txt");
	std::string aes_csproductID;
	std::string line;
	while (std::getline(file, line)) {
		aes_csproductID = line;
	}
	file.close();
	
	cout << "密文内容：" << aes_csproductID << endl;
	cout << "开始解密..." << endl;

	/** 解密，明文存入csproductID*/
	csproductID = aes_decrypt_ecb_hex(aes_csproductID, (unsigned char*)"159753", 16);
	cout << "解密后的明文：" << csproductID << endl;

}

bool compareSN(string csproductID)
{
	cout << "开始读取本地设备的序列号" << endl;
	system("wmic csproduct get UUID > temp.txt");
	
	std::ifstream file("temp.txt");
	std::string line;
	std::string local_csproductID;
	int n = 1;

	while (std::getline(file, line)) {
		if (n == 2)
		{
			local_csproductID = line;
		}
		n++;
	}
	file.close();

	cout << local_csproductID << endl;
	local_csproductID.erase(std::remove_if(local_csproductID.begin(), local_csproductID.end(), ::isspace), local_csproductID.end());

	csproductID.erase(std::remove_if(csproductID.begin(), csproductID.end(), ::isspace), csproductID.end());

	if (isValidStringSame(local_csproductID, csproductID))
	{
		cout << "密钥相同" << endl;
		remove("temp.txt");
		return true;
	}

	remove("temp.txt");
	return false;
}

// aes ebc 加密（输出 hex） 
std::string aes_encrypt_ecb_hex(std::string data, unsigned char* key, int keylen)
{
    std::string encrypt_str;

    try
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecb_encription(key, keylen);
        CryptoPP::StreamTransformationFilter stf_encription(
            ecb_encription,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(encrypt_str)),
            CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING
        );
        stf_encription.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length() + 1);
        stf_encription.MessageEnd();
    }
    catch (std::exception e) {
        std::cout << e.what() << std::endl;
    }

    return encrypt_str;
}

// aes ebc 解密（输出 hex）
std::string aes_decrypt_ecb_hex(std::string hex_data, unsigned char* key, int keylen)
{
    try
    {
        std::string aes_encrypt_data;
        CryptoPP::HexDecoder decoder;
        decoder.Attach(new CryptoPP::StringSink(aes_encrypt_data));
        decoder.Put(reinterpret_cast<const unsigned char*>(hex_data.c_str()), hex_data.length());
        decoder.MessageEnd();
		 
        std::string decrypt_data;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption ebc_description(key, keylen);
        CryptoPP::StreamTransformationFilter stf_description(
            ebc_description,
            new CryptoPP::StringSink(decrypt_data),
            CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING
        );

        stf_description.Put(
            reinterpret_cast<const unsigned char*>(aes_encrypt_data.c_str()),
            aes_encrypt_data.length()
        );
        stf_description.MessageEnd();

        return decrypt_data;
    }
    catch (std::exception e) {
        std::cout << e.what() << std::endl;
        return "decrypt erro";
    }
}

bool isValidChar(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == '-';
}

bool isValidStringSame(const std::string& str1, const std::string& str2) {
	int i = 0, j = 0;
	int len1 = str1.length(), len2 = str2.length();

	// 遍历两个字符串，直到至少一个字符串被完全遍历  
	while (i < len1 && j < len2) {
		// 跳过无效字符  
		while (i < len1 && !isValidChar(str1[i])) i++;
		while (j < len2 && !isValidChar(str2[j])) j++;

		// 如果一个字符串已经遍历完，但另一个还有有效字符，则它们不相同  
		if (i == len1 || j == len2) break;

		// 比较当前有效字符是否相同  
		if (str1[i] != str2[j]) return false;

		// 移动指针到下一个字符  
		i++;
		j++;
	} 
	return true;
}