

#include "certProtocol.hpp"
#include "https_server.hpp"
#include "certMgr.hpp"

int main(int argc, char **argv)
{
	struct event_base *base;
	struct evhttp *http;
	struct evhttp_bound_socket *handle;
	SSL_CTX *ssl_ctx;

    // 初始化OpenSSL
	init_openssl();

    std::string cacert_path = "./output/ca.crt";
	std::string cakey_path = "./output/ca.key";
	generate_ca_certificate(cakey_path, cacert_path);

	std::string csrfile = "./output/server.csr";
	std::string serverCert = "./output/server.crt";
    std::string serverKey = "./output/server.key";

	sign_serverCert(csrfile, cacert_path, cakey_path, serverCert, serverKey);

	// 创建SSL上下文
	ssl_ctx = create_ssl_ctx(cacert_path.c_str(), serverCert.c_str(), serverKey.c_str());
	if (!ssl_ctx)
	{
		return 1;
	}

	// 初始化libevent
	base = event_base_new();
	if (!base)
	{
		fprintf(stderr, "Failed to create event base\n");
		return 1;
	}

	// 创建一个HTTP服务器
	http = evhttp_new(base);
	if (!http)
	{
		fprintf(stderr, "Failed to create evhttp\n");
		return 1;
	}

	// 设置HTTP请求处理回调函数
	evhttp_set_gencb(http, http_request_handler, NULL);

	// 设置自定义bufferevent回调函数
	evhttp_set_bevcb(http, create_ssl_bufferevent, ssl_ctx);

	// 绑定到指定端口
	handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", 8443);
	if (!handle)
	{
		fprintf(stderr, "Failed to bind to port %s\n", argv[3]);
		return 1;
	}

	// 进入事件循环
	event_base_dispatch(base);

	// 清理
	clearResource();
	evhttp_free(http);
	event_base_free(base);
	SSL_CTX_free(ssl_ctx);
	cleanup_openssl();

	return 0;
}