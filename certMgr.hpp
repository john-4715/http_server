#ifndef __CA_ISSUE_CERTIFICATE_H__
#define __CA_ISSUE_CERTIFICATE_H__

#include "openssl_base.hpp"
#include <iostream>
#include <string>

#define KEY_LENGTH 4096
#define DAYS_VALID 365
#define SERIAL 0x1
#define YEARS 1

bool validCertExpir(std::string certificate);

int read_file_to_memory(const char *filename, std::string &strData);

// 从内存加载csr
X509_REQ *load_csr_from_memory(const unsigned char *csr_data, size_t csr_len);

// 从文件中加载证书
X509 *load_cert(const char *filename);

bool saveContentToFile(const std::string &content, const std::string &filename);
// 生成自签名
bool generate_ca_certificate(std::string cakey_path, std::string cacert_path);
// 颁发证书
bool sign_clientcert(std::string csrfile, std::string cafile, std::string cakeyfile, std::string certfile,
					  std::string extfile_path);

bool sign_serverCert(std::string csrfile, std::string cafile, std::string cakey, std::string servercert, std::string serverkey);

void remove_passphrase(const std::string& in_keyfile, const std::string& out_keyfile);
#endif