#include <pthread.h>

#include "certMgr.hpp"
#include "certProtocol.hpp"
#include "https_server.hpp"

int start_https_server(server_context *pServerCtx)
{
	// 创建SSL上下文
	pServerCtx->ssl_ctx = create_ssl_ctx(pServerCtx->ser_cert_path.c_str(), pServerCtx->ser_key_path.c_str());
	if (!pServerCtx->ssl_ctx)
	{
		return -1;
	}

	// 启动HTTPS服务器
	if (setup_https_server(pServerCtx) != 0)
	{
		SSL_CTX_free(pServerCtx->ssl_ctx);
		return -1;
	}

	return 0;
}

int start_https_server2(server_context *pServerCtx)
{
	// 创建SSL上下文
	pServerCtx->ssl_ctx = create_ssl_context(pServerCtx->cacert_path.c_str(), pServerCtx->ser_cert_path.c_str(),
											 pServerCtx->ser_key_path.c_str());
	if (!pServerCtx->ssl_ctx)
	{
		return -1;
	}

	// 启动HTTPS服务器
	if (setup_https_server(pServerCtx) != 0)
	{
		SSL_CTX_free(pServerCtx->ssl_ctx);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct event_base *base;

	// 初始化OpenSSL
	init_openssl();

	server_context server1_ctx;
	server1_ctx.cacert_path = "./output/ca.crt";
	server1_ctx.cakey_path = "./output/ca.key";

	generate_ca_certificate(server1_ctx.cacert_path, server1_ctx.cakey_path);

	server1_ctx.ser_csr_path = "./output/server.csr";
	server1_ctx.ser_cert_path = "./output/server.crt";
	server1_ctx.ser_key_path = "./output/server.key";

	sign_serverCert(server1_ctx);

	server1_ctx.client_cert_path = "output/client.crt";
	server1_ctx.client_csr_path = "output/client.csr";
	server1_ctx.extfile_path = "output/v3.ext";
	// 初始化libevent
	base = event_base_new();
	if (!base)
	{
		fprintf(stderr, "Failed to create event base\n");
		return -1;
	}
	server1_ctx.base = base;
	server1_ctx.port = SERVER1_PORT;

	if(start_https_server(&server1_ctx)< 0)
    {
        event_base_free(base);
        return -1;
    }

    server_context server2_ctx;

	server2_ctx.cacert_path = "./output/ca.crt";
	server2_ctx.cakey_path = "./output/ca.key";

	server2_ctx.ser_csr_path = "./renewcert/server.csr";
	server2_ctx.ser_cert_path = "./renewcert/server.crt";
	server2_ctx.ser_key_path = "./renewcert/server.key";

	sign_serverCert(server2_ctx);

	server2_ctx.client_cert_path = "renewcert/client.crt";
	server2_ctx.client_csr_path = "renewcert/client.csr";
	server2_ctx.extfile_path = "renewcert/v3.ext";

    server2_ctx.base = base;
	server2_ctx.port = SERVER2_PORT;

	if(start_https_server2(&server2_ctx)< 0)
    {
        event_base_free(base);
        return -1;
    }

	// 进入事件循环
	event_base_dispatch(base);

	// 清理
	clearResource();

	evhttp_free(server1_ctx.http);
	SSL_CTX_free(server1_ctx.ssl_ctx);

    evhttp_free(server2_ctx.http);
	SSL_CTX_free(server2_ctx.ssl_ctx);
	event_base_free(base);
	cleanup_openssl();

	return 0;
}