#ifndef __HTTP_SERVER_HPP__
#define __HTTP_SERVER_HPP__

#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>

#include <event2/http.h>

#include <event2/http_struct.h>

#include <event2/buffer.h>

#include <event2/event.h>

#include <event2/util.h>

#include <openssl/err.h>

#include <openssl/ssl.h>

#include <openssl/rand.h>

#include <event2/bufferevent_ssl.h>
#include <event2/keyvalq_struct.h>
#include <event2/listener.h>

#include "openssl_base.hpp"
#include "certProtocol.hpp"
#include "certMgr.hpp"

#define SERVER1_PORT 8443
#define SERVER2_PORT 9443

void http_request_handler(struct evhttp_request *req, void *arg);

SSL_CTX *create_ssl_ctx(const char *servercert, const char *serverkey);

SSL_CTX *create_ssl_context(const char* cafile, const char *servercert, const char *serverkey);

int setup_https_server(server_context *ctx);

struct bufferevent *create_ssl_bufferevent(struct event_base *base, void *arg);

void makeResponse(struct evhttp_request *req, std::string body, std::string clientIp,
				  server_context *pServerCertHandle);

void clearResource();


#endif