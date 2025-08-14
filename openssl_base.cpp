#include "openssl_base.hpp"

// 初始化OpenSSL
void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

// 清理OpenSSL
void cleanup_openssl()
{
	EVP_cleanup();
	ERR_free_strings();
}