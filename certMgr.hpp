#ifndef __CA_ISSUE_CERTIFICATE_H__
#define __CA_ISSUE_CERTIFICATE_H__

#include "openssl_base.hpp"
#include <iostream>
#include <string>

#define KEY_LENGTH 4096
#define DAYS_VALID 365
#define SERIAL 0x1
#define YEARS 1

typedef struct _server_context
{
	SSL_CTX *ssl_ctx;
	struct event_base *base;
	int port;
	struct evhttp *http;
	struct evhttp_bound_socket *handle;

	std::string cacert_path;
	std::string cakey_path;

	std::string ser_cert_path;
	std::string ser_key_path;
	std::string ser_csr_path;

	std::string client_cert_path;
	std::string client_csr_path;

	std::string extfile_path;
} server_context;

bool validCertExpir(std::string certificate);

int read_file_to_memory(const char *filename, std::string &strData);

// 从内存加载csr
X509_REQ *load_csr_from_memory(const unsigned char *csr_data, size_t csr_len);

// 从文件中加载证书
X509 *load_cert(const char *filename);

bool saveContentToFile(const std::string &content, const std::string &filename);
// 生成自签名
bool generate_ca_certificate(std::string cacert_path, std::string cakey_path);
// 颁发证书
bool sign_clientcert(std::string csrfile, std::string cafile, std::string cakeyfile, std::string certfile,
					  std::string extfile_path);

bool sign_serverCert(server_context serverCertHandle);

void remove_passphrase(const std::string& in_keyfile, const std::string& out_keyfile);
#endif