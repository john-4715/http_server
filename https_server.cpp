#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "https_server.hpp"
#include "ini_wrapper.h"
#include "utils.h"

static std::string csr;
bool m_isRunning = false;
// 创建SSL上下文
SSL_CTX *create_ssl_ctx(const char *servercert, const char *serverkey)
{
	SSL_CTX *ctx;
	// 创建 SSL 上下文
	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx)
	{
		fprintf(stderr, "Failed to create SSL context\n");
		return NULL;
	}
	// 设置 SSL 选项
	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	// 加载服务器证书
	if (SSL_CTX_use_certificate_file(ctx, servercert, SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "Failed to load certificate file\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	// 加载服务器私钥
	if (SSL_CTX_use_PrivateKey_file(ctx, serverkey, SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "Failed to load private key file\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	// 验证私钥是否匹配
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		return NULL;
	}

	return ctx;
}

// 创建SSL上下文
SSL_CTX *create_ssl_context(const char* cafile, const char *servercert, const char *serverkey)
{
	SSL_CTX *ctx;
	// 创建 SSL 上下文
	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx)
	{
		fprintf(stderr, "Failed to create SSL context\n");
		return NULL;
	}
	// 设置 SSL 选项
	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	// 加载服务器证书
	if (SSL_CTX_use_certificate_file(ctx, servercert, SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "Failed to load certificate file\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	// 加载服务器私钥
	if (SSL_CTX_use_PrivateKey_file(ctx, serverkey, SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "Failed to load private key file\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	// 验证私钥是否匹配
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		return NULL;
	}

	// 加载 CA 证书用于验证客户端
	if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1)
	{
		SSL_CTX_free(ctx);
		return NULL;
	}

    // 设置客户端证书验证(双向认证)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify_depth(ctx, 4);

	return ctx;
}

// 设置HTTPS服务器
int setup_https_server(server_context *server_ctx)
{
	// 创建一个HTTP服务器
	server_ctx->http = evhttp_new(server_ctx->base);
	if (!server_ctx->http)
	{
		fprintf(stderr, "Failed to create evhttp\n");
		return -1;
	}

	// 设置HTTP请求处理回调函数
	evhttp_set_gencb(server_ctx->http, http_request_handler, server_ctx);

	// 设置SSL回调
	evhttp_set_bevcb(server_ctx->http, create_ssl_bufferevent, (void*)server_ctx);

	// 绑定到指定端口
	server_ctx->handle = evhttp_bind_socket_with_handle(server_ctx->http, "0.0.0.0", server_ctx->port);
	if (!server_ctx->handle)
	{
		fprintf(stderr, "Failed to bind to port %d\n", server_ctx->port);
		return -1;
	}

	printf("The https server has started successfully, server port : %d.\n\n\n", server_ctx->port);
	return 0;
}

// 自定义bufferevent回调函数
struct bufferevent *create_ssl_bufferevent(struct event_base *base, void *arg)
{
    server_context *pServerCtx = (server_context *)arg;
	SSL *ssl;
	struct bufferevent *bev;

	// 创建一个新的SSL对象
	ssl = SSL_new(pServerCtx->ssl_ctx);
	if (!ssl)
	{
		fprintf(stderr, "Failed to create SSL object\n");
		return NULL;
	}

	// 创建一个SSL bufferevent
	bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	if (!bev)
	{
		fprintf(stderr, "Failed to create SSL bufferevent\n");
		SSL_free(ssl);
		return NULL;
	}

	return bev;
}

void clearResource() {}

void updateExtentFile(std::string extfile_path, std::string clientIp)
{
	// 加载或创建配置文件extfile_path
	ini_config *config = ini_load(extfile_path.c_str());
	if (!config)
	{
		printf("Config file not found, creating new...\n");
		config = dictionary_new(0);
		return;
	}

	ini_set(config, "alt_names", "IP.1", clientIp.c_str());

	// 保存配置
	if (ini_save(config, extfile_path.c_str()))
	{
		printf("Failed to save config file\n");
	}
	else
	{
		printf("Config saved to %s\n", extfile_path.c_str());
	}
	// 清理资源
	ini_free(config);
}

void makeResponse(struct evhttp_request *req, std::string body, std::string clientIp,
				  server_context *server_ctx)
{
	struct evbuffer *evb;

	// 创建一个新的evbuffer来存储响应内容
	evb = evbuffer_new();

	if (evb == NULL)
	{
		fprintf(stderr, "Failed to create response buffer\n");
		return;
	}

	// 添加HTTP headers
	evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/plain");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "close");

	std::string respBody;
	std::string msgInfo;
	if (m_isRunning)
	{
		respBody = BuildRunningRespBody();

		msgInfo = "IsRunning";
		// 添加HTTP body
		evbuffer_add_printf(evb, "%s", respBody.c_str());
		// evbuffer_add_printf(evb, "Hello, HTTPS World!\n");
		fprintf(stdout, "***********************************************\n");
		fprintf(stdout, "http server send %s to client.\n", msgInfo.c_str());
		fprintf(stdout, "***********************************************\n\n\n");
		// 发送HTTP响应
		evhttp_send_reply(req, HTTP_OK, "OK", evb);

		// 释放evbuffer
		evbuffer_free(evb);
		return;
	}

	// 解析url
	ENUM_HTTP_REQ_TYPE reqType = parseUrl(req->uri);

	CSR_REQ_BODY csrReqBody;
	RENEWCERT_REQ_BODY renewReqBody;

	switch (reqType)
	{
	case ENUM_HTTP_REQ_CSR:
	{
		m_isRunning = true;
		char cmd[256];
		sprintf(cmd, "rm -rf ./output/client.*");
		system(cmd);

		parseCSRequest(body, csrReqBody);
		saveContentToFile(csrReqBody.csr, server_ctx->client_csr_path);

		std::string cafile = server_ctx->cacert_path;
		std::string cakeyfile = server_ctx->cakey_path;
		std::string certfile = server_ctx->client_cert_path;
		std::string csrfile = server_ctx->client_csr_path;
		std::string extfile_path = server_ctx->extfile_path;

		updateExtentFile(extfile_path, clientIp);

		sign_clientcert(csrfile, cafile, cakeyfile, certfile, extfile_path);

		respBody = BuildCsrRespBody();
		msgInfo = "csr response";
		m_isRunning = false;
	}
	break;
	case ENUM_HTTP_REQ_CHALLENGE:
	{
		respBody = BuildChallengeCertRespBody();
		msgInfo = "challenge cert response";
	}
	break;
	case ENUM_HTTP_REQ_RENEWCERT:
	{
		m_isRunning = true;
		char cmd[256];
		sprintf(cmd, "rm -rf ./output/client.*");
		system(cmd);
		parseRenewCertRequest(body, renewReqBody);
		saveContentToFile(renewReqBody.csr, server_ctx->client_csr_path);

		std::string cafile = server_ctx->cacert_path;
		std::string cakeyfile = server_ctx->cakey_path;
		std::string certfile = server_ctx->client_cert_path;
		std::string csrfile = server_ctx->client_csr_path;
		std::string extfile_path = server_ctx->extfile_path;

		updateExtentFile(extfile_path, clientIp);

		sign_clientcert(csrfile, cafile, cakeyfile, certfile, extfile_path);

		respBody = BuildRenewCertRespBody();
		msgInfo = "renew cert response";
		m_isRunning = false;
	}
	break;
	default:
		break;
	}

	fprintf(stdout, "reponse body:[%s]\n", respBody.c_str());

	// 添加HTTP body
	evbuffer_add_printf(evb, "%s", respBody.c_str());
	// evbuffer_add_printf(evb, "Hello, HTTPS World!\n");
	fprintf(stdout, "***********************************************\n");
	fprintf(stdout, "http server send %s to client.\n", msgInfo.c_str());
	fprintf(stdout, "***********************************************\n\n\n");
	// 发送HTTP响应
	evhttp_send_reply(req, HTTP_OK, "OK", evb);

	// 释放evbuffer
	evbuffer_free(evb);
}

// 回调函数，处理HTTP请求
void http_request_handler(struct evhttp_request *req, void *arg)
{
	if (req == NULL)
	{
		fprintf(stderr, "req == NULL\n");
		return;
	}

	server_context *server_ctx = (server_context *)arg;
	fprintf(stdout, "-----------------------------------------------\n");
	fprintf(stdout, "http server get message from client.\n");
	fprintf(stdout, "-----------------------------------------------\n");
	// 获取客户端IP和端口
	struct evhttp_connection *conn = evhttp_request_get_connection(req);
	char *client_ip = NULL;
	ev_uint16_t client_port = 0;
	evhttp_connection_get_peer(conn, &client_ip, &client_port);

	fprintf(stdout, "Client IP: %s, Port: %d\n", client_ip, client_port);
	fprintf(stdout, "Request URI: %s\n", evhttp_request_get_uri(req));

	std::string clientIp = client_ip;
	// 获取post body长度
	size_t body_size = evbuffer_get_length(req->input_buffer);

	if (req->type == EVHTTP_REQ_GET)
	{
		fprintf(stdout, "Client sent a GET request for %s\n", req->uri);

		// 获取请求头部
		struct evkeyvalq *headers = evhttp_request_get_input_headers(req);
		printf("Request Headers:\n");
		for (struct evkeyval *header = headers->tqh_first; header; header = header->next.tqe_next)
		{
			printf("%s: %s\n", header->key, header->value);
		}
		std::string body = "";
		makeResponse(req, body, clientIp, server_ctx);
	}
	else if (req->type == EVHTTP_REQ_POST)
	{
		fprintf(stdout, "Client sent a POST request.\n");

		// 获取请求头部
		struct evkeyvalq *headers = evhttp_request_get_input_headers(req);
		printf("Request Headers:\n");
		for (struct evkeyval *header = headers->tqh_first; header; header = header->next.tqe_next)
		{
			printf("%s: %s\n", header->key, header->value);
		}

		fprintf(stdout, "POST Body len(%ld)\n", body_size);

		std::string buff = (char *)evbuffer_pullup(req->input_buffer, -1);
		std::string body = buff.substr(0, body_size);
		fprintf(stdout, "Body:[%s]\n", body.c_str());
		makeResponse(req, body, clientIp, server_ctx);
	}
}
