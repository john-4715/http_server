#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "certMgr.hpp"
#include "certProtocol.hpp"
#include "https_server.hpp"
#include "ini_wrapper.h"
#include "utils.h"

static std::string csr;

// 创建SSL上下文
SSL_CTX *create_ssl_ctx(const char *cert_file, const char *key_file)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx)
	{
		fprintf(stderr, "Failed to create SSL context\n");
		return NULL;
	}

	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "Failed to load certificate file\n");
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "Failed to load private key file\n");
		SSL_CTX_free(ctx);
		return NULL;
	}

	return ctx;
}

// 自定义bufferevent回调函数
struct bufferevent *create_ssl_bufferevent(struct event_base *base, void *arg)
{
	SSL_CTX *ssl_ctx = (SSL_CTX *)arg;
	SSL *ssl;
	struct bufferevent *bev;

	// 创建一个新的SSL对象
	ssl = SSL_new(ssl_ctx);
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

	ini_set(config, "alt_names", "ip.1", clientIp.c_str());

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

void makeResponse(struct evhttp_request *req, std::string body, std::string clientIp)
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
	// 解析url
	ENUM_HTTP_REQ_TYPE reqType = parseUrl(req->uri);
	std::string respBody;
	std::string msgInfo;
	CSR_REQ_BODY csrReqBody;
	RENEWCERT_REQ_BODY renewReqBody;

	switch (reqType)
	{
	case ENUM_HTTP_REQ_CSR:
	{
		char cmd[256];
		sprintf(cmd, "rm -rf ./output/*.key ./output/*.crt ./output/*.csr");
		system(cmd);

		parseCSRequest(body, csrReqBody);
		saveContentToFile(csrReqBody.csr, "./output/client.csr");

		std::string cakey_path = "./output/ca.key";
		std::string cacert_path = "./output/ca.crt";
		generate_ca_certificate(cakey_path, cacert_path);

		std::string csrfile = "./output/client.csr";
		std::string cafile = "./output/ca.crt";
		std::string cakeyfile = "./output/ca.key";
		std::string certfile = "./output/client.crt";
		std::string extfile_path = "./output/v3.ext";

		updateExtentFile(extfile_path, clientIp);

		sign_certificate(csrfile, cafile, cakeyfile, certfile, extfile_path);

		respBody = BuildCsrRespBody();
		msgInfo = "csr response";
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
		parseRenewCertRequest(body, renewReqBody);
		respBody = BuildRenewCertRespBody();
		msgInfo = "renew cert response";
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
		makeResponse(req, body, clientIp);
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
		makeResponse(req, body, clientIp);
	}
}