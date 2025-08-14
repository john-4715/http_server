#ifndef __OPENSSL_BASE_HPP__
#define __OPENSSL_BASE_HPP__

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init_openssl();

void cleanup_openssl();

#endif