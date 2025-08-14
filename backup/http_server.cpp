#include "http_server.hpp"
/*
	服务端
	------------------------------------------------------------------------------------
*/

bool evHttpServer::serverConnect()
{
	base = event_base_new();
	if (!base)
	{
		fprintf(stderr, "Create event_base failed.\n");
		return false;
	}
	http_server = evhttp_new(base);
	if (http_server == NULL)
	{
		fprintf(stderr, "Create evhttp failed.\n");
		return false;
	}
	if (evhttp_bind_socket(http_server, ip.c_str(), port) != 0)
	{
		fprintf(stderr, "bind socket<%s:%d> failed.\n", ip.c_str(), port);
		return false;
	}
	return true;
}

void evHttpServer::setHttpTimeout(int timeout)
{
	if (http_server)
	{
		evhttp_set_timeout(http_server, timeout);
	}
}

void evHttpServer::interfaceRegister(const char *path, void (*cb)(evhttp_request *, void *), void *cb_arg)
{
	if (http_server)
	{
		evhttp_set_cb(http_server, path, cb, cb_arg);
	}
}

void evHttpServer::loopListen()
{
	if (base)
	{
		event_base_dispatch(base);
	}
}

evHttpServer::~evHttpServer()
{
	if (http_server)
	{
		evhttp_free(http_server);
	}
}

void evHttpServer::cbGETSample(evhttp_request *request, void *arg)
{
	if (request == NULL)
	{
		return;
	}

	struct evkeyvalq params = {0};
	char *param1_value = findGetParam(request, &params, "param1");
	char *param2_value = findGetParam(request, &params, "param2");
	if (param1_value == NULL || param2_value == NULL)
	{
		evhttp_send_error(request, HTTP_BADREQUEST, NULL); // reason为NULL时会发送默认的error描述
	}
	else
	{
		cout << "param1:" << param1_value << endl;
		cout << "param2:" << param2_value << endl;
		/*
			对value做处理
		*/
		// 响应体
		reply(request, HTTP_OK, "Success", "this is body");
	}
}

char *evHttpServer::findGetParam(struct evhttp_request *request, struct evkeyvalq *params, const char *query_char)
{
	if (request == NULL || params == NULL || query_char == NULL)
	{
		return NULL;
	}
	// 返回uri(request->uri) (/getparam?param1=hello) / 往后的部分
	// const char *uri = evhttp_request_get_uri(request);
	// 解析参数部分
	struct evhttp_uri *ev_uri = evhttp_uri_parse(request->uri); // 需要evhttp_uri_free释放
	if (!ev_uri)
	{
		fprintf(stderr, "evhttp_uri_parse uri failed!\n");
		return NULL;
	}

	// 返回(ev_uri->query) URI中的查询参数部分 ? 往后的部分 param1=hello
	const char *query_param = evhttp_uri_get_query(ev_uri);
	if (query_param == NULL)
	{
		fprintf(stderr, "evhttp_uri_parse uri failed!\n");
		evhttp_uri_free(ev_uri);
		return NULL;
	}

	// 查询指定参数的值 应该是将query_param 赋给 params
	evhttp_parse_query_str(query_param, params);
	// (params是传入的结构) query_result应该是params的一部分 否则无法正常返回
	char *query_result = (char *)evhttp_find_header(params, query_char);

	evhttp_uri_free(ev_uri);
	return query_result;
}

void evHttpServer::cbPOSTSample(evhttp_request *request, void *arg)
{
	if (request == NULL)
	{
		return;
	}
    

	// 获取post body长度
	size_t body_size = evbuffer_get_length(request->input_buffer);
	if (body_size <= 0)
	{
		fprintf(stderr, "POST Body is null\n");
		evhttp_send_error(request, HTTP_BADMETHOD, "POST Body is null");
	}
	else
	{
		fprintf(stdout, "POST Body len(%ld)\n", body_size);
		// evbuffer_pullup函数是移动指定字节数的数据到huan缓冲区的起始位置
		//  所以取body的时候需要取指定的大小
		string buff = (char *)evbuffer_pullup(request->input_buffer, -1);
		string body = buff.substr(0, body_size);
		fprintf(stdout, "Body:[%s]\n", body.c_str());
		/*
			处理post请求
		*/
		reply(request, HTTP_OK, NULL, NULL);
	}
}

void evHttpServer::reply(evhttp_request *request, int code, const char *reason, const char *body)
{
	struct evbuffer *retbuff = NULL;
	if (body)
	{
		retbuff = evbuffer_new();
		evbuffer_add_printf(retbuff, "%s", body);
	}
	evhttp_send_reply(request, code, reason, retbuff); // reason为NULL 发送code默认reason
	if (body)
		evbuffer_free(retbuff);
}
