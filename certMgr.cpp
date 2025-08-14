#include <fstream>
#include <iostream>
#include <memory>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/file.h>
#include <unistd.h>
#include <vector>

#include "certMgr.hpp"
#include "utils.h"

void handle_errors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

// 从内存加载csr
X509_REQ *load_csr_from_memory(const unsigned char *csr_data, size_t csr_len)
{
	BIO *bio = BIO_new_mem_buf(csr_data, csr_len);
	X509_REQ *csr = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return csr;
}

// 从文件中加载证书
X509 *load_cert(const char *filename)
{
	FILE *file = fopen(filename, "r");
	if (!file)
	{
		perror("Unable to open certificate file");
		return NULL;
	}

	X509 *cert = PEM_read_X509(file, NULL, NULL, NULL);
	fclose(file);

	if (!cert)
	{
		fprintf(stderr, "Error loading certificate from file.\n");
		return NULL;
	}

	return cert;
}

// 将证书保存到内存中
char *save_certificate_to_memory(X509 *cert, size_t *cert_len)
{
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio)
		handle_errors();

	if (!PEM_write_bio_X509(bio, cert))
	{
		BIO_free(bio);
		handle_errors();
	}

	BUF_MEM *bptr;
	BIO_get_mem_ptr(bio, &bptr);
	char *cert_data = (char *)malloc(bptr->length + 1);
	if (!cert_data)
		handle_errors();

	memcpy(cert_data, bptr->data, bptr->length);
	cert_data[bptr->length] = '\0'; // 添加字符串结束符
	*cert_len = bptr->length;

	BIO_free(bio);
	return cert_data;
}

bool validCertExpir(std::string certificate)
{
	// Create a memory buffer
	BIO *bio = BIO_new_mem_buf(certificate.c_str(), -1);
	if (!bio)
	{
		printf("[%s %d] Failed to create BIO.", __func__, __LINE__);
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bioPtr(bio, BIO_free);

	// Read the certificate from the memory buffer
	X509 *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
	if (!x509)
	{
		printf("[%s %d] Certificate parsing failed:\"%s\".", __func__, __LINE__,
			   ERR_error_string(ERR_get_error(), nullptr));
		return false;
	}
	std::unique_ptr<X509, decltype(&X509_free)> x509Ptr(x509, X509_free);

	// Verify the certificate validity period
	if (X509_cmp_current_time(X509_get_notBefore(x509)) > 0)
	{
		printf("[%s %d] The certificate's 'notBefore' date is in the future. It is not valid yet.", __func__, __LINE__);
		return false;
	}
	if (X509_cmp_current_time(X509_get_notAfter(x509)) < 0)
	{
		printf("[%s %d] The certificate has expired.", __func__, __LINE__);
		return false;
	}

	printf("[%s %d] The certificate not expired!!!\n\n", __func__, __LINE__);
	return true;
}

int read_file_to_memory(const char *filename, std::string &strData)
{
	FILE *file = fopen(filename, "r");
	if (file == NULL)
	{
		perror("Error opening file");
		return -1;
	}

	// 计算文件大小
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);

	// 分配内存并读取文件内容
	char *buffer = (char *)malloc(size + 1); // +1 for null terminator
	if (buffer)
	{
		fread(buffer, 1, size, file);
		buffer[size] = '\0'; // Null-terminate the string
		strData = buffer;
		free(buffer);
	}

	fclose(file);
	return 0;
}

bool saveContentToFile(const std::string &content, const std::string &filename)
{
	int fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1)
	{
		printf("Failed to open file:%s.", filename.c_str());
		return false;
	}

	if (flock(fd, LOCK_EX) == -1)
	{
		printf("Failed to lock file:%s.", filename.c_str());
		close(fd);
		return false;
	}

	write(fd, content.data(), content.size());
	flock(fd, LOCK_UN);
	close(fd);
	return true;
}

bool generate_ca_certificate(std::string cakey_path, std::string cacert_path)
{
	RSA *rsa = NULL;
	X509 *ca_cert = NULL;
	X509_NAME *name = NULL;
	EVP_PKEY *pkey = NULL;
	FILE *key_file = NULL, *cert_file = NULL;
	int bRet = false;
	do
	{
		// 1. 生成 RSA 私钥
		printf("Generating RSA private key...\n");
		rsa = RSA_generate_key(KEY_LENGTH, RSA_F4, NULL, NULL);
		if (rsa == NULL)
		{
			fprintf(stderr, "Error generating RSA key\n");
			break;
		}

		// 将私钥写入文件
		key_file = fopen(cakey_path.c_str(), "wb");
		if (key_file == NULL)
		{
			fprintf(stderr, "Error opening ca.key for writing\n");
			break;
		}
		if (!PEM_write_RSAPrivateKey(key_file, rsa, NULL, NULL, 0, NULL, NULL))
		{
			fprintf(stderr, "Error writing private key\n");
			break;
		}
		fclose(key_file);
		key_file = NULL;

		// 2. 创建自签名证书
		printf("Creating self-signed certificate...\n");
		ca_cert = X509_new();
		if (ca_cert == NULL)
		{
			fprintf(stderr, "Error creating X509 structure\n");
			break;
		}

		// 设置证书版本
		X509_set_version(ca_cert, 2); // X509v3

		// 设置序列号
		ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);

		// 设置有效期
		X509_gmtime_adj(X509_get_notBefore(ca_cert), 0);
		X509_gmtime_adj(X509_get_notAfter(ca_cert), DAYS_VALID * 24 * 60 * 60);

		// 设置公钥
		pkey = EVP_PKEY_new();
		if (pkey == NULL)
		{
			fprintf(stderr, "Error creating EVP_PKEY\n");
			break;
		}
		EVP_PKEY_set1_RSA(pkey, rsa);
		X509_set_pubkey(ca_cert, pkey); // 设置公钥

		// 设置主题名称
		name = X509_get_subject_name(ca_cert);
		X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"CN", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)"Shanxi", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *)"Xian", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"EXEC", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char *)"DS", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"ca_ip", -1, -1, 0);

		// 设置颁发者名称（自签名，所以与主题相同）
		X509_set_issuer_name(ca_cert, name);

		// 6. 添加扩展
		X509V3_CTX ctx;
		X509V3_set_ctx(&ctx, ca_cert, ca_cert, nullptr, nullptr, 0);

		// 基本约束 - CA证书
		X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "CA:TRUE");
		if (!ex)
		{
			break;
		}
		X509_add_ext(ca_cert, ex, -1);
		X509_EXTENSION_free(ex);

		// 使用者密钥标识符
		ex = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, "hash");
		if (!ex)
		{
			break;
		}
		X509_add_ext(ca_cert, ex, -1);
		X509_EXTENSION_free(ex);

		// 授权密钥标识符
		ex = X509V3_EXT_conf_nid(nullptr, &ctx, NID_authority_key_identifier, "keyid:always");
		if (!ex)
		{
			break;
		}
		X509_add_ext(ca_cert, ex, -1);
		X509_EXTENSION_free(ex);

		// 密钥用途
		ex = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, "keyCertSign, cRLSign");
		if (!ex)
		{
			break;
		}
		X509_add_ext(ca_cert, ex, -1);
		X509_EXTENSION_free(ex);
		// 签名证书
		if (!X509_sign(ca_cert, pkey, EVP_sha256()))
		{
			fprintf(stderr, "Error signing certificate\n");
			break;
		}

		// 将证书写入文件
		cert_file = fopen(cacert_path.c_str(), "wb");
		if (cert_file == NULL)
		{
			fprintf(stderr, "Error opening ca.crt for writing\n");
			break;
		}
		if (!PEM_write_X509(cert_file, ca_cert))
		{
			fprintf(stderr, "Error writing certificate\n");
			break;
		}

		printf("Successfully generated ca.key and ca.crt\n");
		bRet = true;
	} while (0);

	if (key_file)
	{
		fclose(key_file);
	}
	if (cert_file)
	{
		fclose(cert_file);
	}
	if (ca_cert)
	{
		X509_free(ca_cert);
	}
	if (pkey)
	{
		EVP_PKEY_free(pkey);
	}

	return bRet;
}

std::string read_extension_file(const std::string &filename)
{
	std::ifstream file(filename);
	if (!file.is_open())
	{
		throw std::runtime_error("Could not open extension file: " + filename);
	}

	std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	return content;
}

void print_section(const char *name, STACK_OF(CONF_VALUE) * section)
{
	printf("Section [%s]:\n", name);
	if (!section)
	{
		printf("(empty or not found)\n");
		return;
	}

	for (int i = 0; i < sk_CONF_VALUE_num(section); i++)
	{
		CONF_VALUE *val = sk_CONF_VALUE_value(section, i);
		printf("  %s = %s\n", val->name, val->value);
	}
}

bool sign_certificate(std::string csrfile, std::string cafile, std::string cakeyfile, std::string certfile,
					  std::string extfile_path)
{
	bool bRet = false;

	// 初始化OpenSSL配置
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

	// 1. 加载 CA 证书和私钥
	FILE *ca_cert_file = fopen(cafile.c_str(), "r");
	FILE *ca_key_file = fopen(cakeyfile.c_str(), "r");
	if (!ca_cert_file || !ca_key_file)
	{
		perror("Failed to open CA files");
		exit(EXIT_FAILURE);
	}

	X509 *ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
	EVP_PKEY *ca_key = PEM_read_PrivateKey(ca_key_file, NULL, NULL, NULL);
	fclose(ca_cert_file);
	fclose(ca_key_file);

	if (!ca_cert || !ca_key)
	{
		fprintf(stderr, "Failed to read CA cert or key\n");
		handle_errors();
	}

	// 2. 加载客户端 CSR
	FILE *csr_file = fopen(csrfile.c_str(), "r");
	if (!csr_file)
	{
		perror("Failed to open CSR file");
		exit(EXIT_FAILURE);
	}

	X509_REQ *csr = PEM_read_X509_REQ(csr_file, NULL, NULL, NULL);
	fclose(csr_file);

	if (!csr)
	{
		fprintf(stderr, "Failed to read CSR\n");
		handle_errors();
	}

	// 3. 创建新证书
	X509 *new_cert = X509_new();
	if (!new_cert)
	{
		fprintf(stderr, "Failed to create X509 cert\n");
		handle_errors();
	}

	// 4. 设置证书基本信息（从 CSR 复制）
	X509_set_version(new_cert, 2); // X509v3
	X509_set_subject_name(new_cert, X509_REQ_get_subject_name(csr));

	// 5. 设置颁发者（CA）
	X509_set_issuer_name(new_cert, X509_get_subject_name(ca_cert));

	// 6. 设置有效期（3650 天）
	X509_gmtime_adj(X509_get_notBefore(new_cert), 0);				// 现在生效
	X509_gmtime_adj(X509_get_notAfter(new_cert), 3650 * 24 * 3600); // 10 年后过期

	// 7. 设置公钥（从 CSR 复制）
	EVP_PKEY *csr_pubkey = X509_REQ_get_pubkey(csr);
	X509_set_pubkey(new_cert, csr_pubkey);
	EVP_PKEY_free(csr_pubkey);

	// 8. 添加扩展（从 v3.ext 文件读取）
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, ca_cert, new_cert, NULL, NULL, 0);

	FILE *ext_file = fopen(extfile_path.c_str(), "r");
	if (!ext_file)
	{
		perror("Failed to open extfile");
		exit(EXIT_FAILURE);
	}
	// 创建配置对象
	CONF *conf = NCONF_new(NULL);
	// 加载配置文件
	if (NCONF_load(conf, extfile_path.c_str(), NULL) <= 0)
	{
		fprintf(stderr, "Failed to load extfile %s\n", extfile_path.c_str());
		handle_errors();
	}

	printf("All sections in %s:\n", extfile_path.c_str());
	// 读取扩展并添加到证书
	STACK_OF(CONF_VALUE) *sections = NCONF_get_section(conf, "req");
	if (sections)
	{
		printf("sk_CONF_VALUE_num(sections) = %d\n", sk_CONF_VALUE_num(sections));
		for (int i = 0; i < sk_CONF_VALUE_num(sections); i++)
		{
			CONF_VALUE *val = sk_CONF_VALUE_value(sections, i);
			printf("val->name : %s\n", val->name);
			int nid = OBJ_txt2nid(val->name); // 将扩展名转为 NID（如 "basicConstraints" -> NID_basic_constraints）
			if (nid == NID_undef)
			{
				fprintf(stderr, "Warning: Unknown extension %s, skipping\n", val->name);
				continue;
			}

			// 特殊处理 subjectAltName（需引用 alt_names 节）
			if (nid == NID_subject_alt_name && strcmp(val->value, "@alt_names") == 0)
			{
				printf("1. alt_names\n");
				// 直接使用 alt_names 节的内容
				STACK_OF(CONF_VALUE) *alt_names = NCONF_get_section(conf, "alt_names");
				if (!alt_names)
				{
					fprintf(stderr, "Error: [alt_names] section not found\n");
					continue;
				}
				// 生成 subjectAltName 扩展
				X509_EXTENSION *ext = X509V3_EXT_nconf(conf, &ctx, "subjectAltName", "@alt_names");
				if (!ext)
				{
					fprintf(stderr, "Error: Failed to create subjectAltName extension\n");
					continue;
				}
				X509_add_ext(new_cert, ext, -1);
				X509_EXTENSION_free(ext);
			}
			else
			{
				// 普通扩展（如 basicConstraints、keyUsage）
				X509_EXTENSION *ext = X509V3_EXT_nconf(conf, &ctx, val->name, val->value);
				if (!ext)
				{
					fprintf(stderr, "Error: Failed to create extension %s=%s\n", val->name, val->value);
					continue;
				}
				X509_add_ext(new_cert, ext, -1);
				X509_EXTENSION_free(ext);
			}
		}
		
		// 检查各个节
		// print_section("req", NCONF_get_section(conf, "req"));
		// print_section("alt_names", NCONF_get_section(conf, "alt_names"));
		NCONF_free(conf);
	}

	// 9. 使用 CA 私钥签名
	if (!X509_sign(new_cert, ca_key, EVP_sha256()))
	{
		fprintf(stderr, "Failed to sign certificate\n");
		handle_errors();
	}

	// 10. 保存生成的证书
	FILE *out_file = fopen(certfile.c_str(), "w");
	if (!out_file)
	{
		perror("Failed to open output file");
		exit(EXIT_FAILURE);
	}

	PEM_write_X509(out_file, new_cert);
	fclose(out_file);

	// 11. 清理资源
	X509_free(new_cert);
	X509_REQ_free(csr);
	X509_free(ca_cert);
	EVP_PKEY_free(ca_key);

	printf("Certificate generated: client.crt\n");
	return 0;
}

void remove_passphrase(const std::string &in_keyfile, const std::string &out_keyfile)
{
	FILE *in_fp = fopen(in_keyfile.c_str(), "r");
	if (!in_fp)
	{
		printf("Error opening %s", in_keyfile.c_str());
	}

	RSA *rsa = PEM_read_RSAPrivateKey(in_fp, nullptr, nullptr, nullptr);
	fclose(in_fp);
	if (!rsa)
	{
		printf("Error reading private key from %s", in_keyfile.c_str());
	}

	FILE *out_fp = fopen(out_keyfile.c_str(), "wb");
	if (!out_fp)
	{
		RSA_free(rsa);
		printf("Error opening %s for writing", out_keyfile.c_str());
	}

	if (!PEM_write_RSAPrivateKey(out_fp, rsa, nullptr, nullptr, 0, nullptr, nullptr))
	{
		fclose(out_fp);
		RSA_free(rsa);
		printf("Error writing private key to %s", out_keyfile.c_str());
	}

	fclose(out_fp);
	RSA_free(rsa);
}