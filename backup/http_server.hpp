#ifndef __HTTP_SERVER_HPP__
#define __HTTP_SERVER_HPP__

#include <iostream>
#include <sstream>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include "event.h"
#include "evhttp.h"

using namespace std;

// ev http server
class evHttpServer
{
private:
	string ip;
	int port;
	struct evhttp *http_server = NULL;
	struct event_base *base = NULL;

public:
	evHttpServer(string ip, int port) : ip(ip), port(port) {};
	// 创建http 绑ip端口
	bool serverConnect();
	// 设置服务超时时间
	void setHttpTimeout(int timeout);
	/*
		接口注册
		@param path 接口路径 如"/get_task"
		@param cb 处理该接口的回调
		@param cb_arg 回调的参数
	*/
	void interfaceRegister(const char *path, void (*cb)(struct evhttp_request *, void *), void *cb_arg = NULL);
	// 循环监听
	void loopListen();
	~evHttpServer();

public:
	/*
		http响应
		@param code - 响应码
		@param reason - 响应码对应的说明, 为NULL,使用默认的响应码说明
		@param body - body, 为NULL, 没有body
	*/
	static void reply(evhttp_request *request, int code, const char *reason, const char *body);
	// Get回调函数例子
	static void cbGETSample(struct evhttp_request *request, void *arg);
	// 解析request获取GET请求参数
	static char *findGetParam(struct evhttp_request *request, struct evkeyvalq *params, const char *query_char);
	// Post回调函数例子
	static void cbPOSTSample(struct evhttp_request *request, void *arg);
};

#endif