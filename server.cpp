#include <fcntl.h>		//设置非阻塞
#include <iostream>		//控制台输出
#include <netinet/in.h> //socket addr
#include <string.h>
#include <sys/epoll.h>	//epoll
#include <sys/socket.h> //创建socket
#include <unistd.h>		//close函数

using namespace std;

#define PORT 8080
#define BUFFER_SIZE 1024

char *get_header_value(char *header, char *key)
{
	// 查找key
	char *key_pos = strstr(header, key);
	if (key_pos == NULL)
	{
		return NULL;
	}
	// 查找value
	char *value_pos = strchr(key_pos, ':');
	if (value_pos == NULL)
	{
		return NULL;
	}
	value_pos++;

	// 跳过前面的空格
	while (*value_pos == ' ')
	{
		value_pos++;
	}

	// 查找结尾的\r\n
	char *end_pos = strstr(value_pos, "\r\n");
	if (end_pos == NULL)
	{
		return NULL;
	}

	// 截取value
	*end_pos = '\0';

	return value_pos;
}

void handle_request(char *request, int client_socket)
{
	char method[BUFFER_SIZE], uri[BUFFER_SIZE], http_version[BUFFER_SIZE];
	char *header, *body;

	// 解析HTTP请求
	sscanf(request, "%s %s %s", method, uri, http_version);

	// 处理GET请求
	if (strcmp(method, "GET") == 0)
	{
		// 构造响应消息
		char *response = "HTTP/1.1 200 OK\r\n"
						 "Content-Type: text/html\r\n"
						 "\r\n"
						 "<html><body><h1>Hello, World!</h1></body></html>";

		// 发送响应
		send(client_socket, response, strlen(response), 0);

	} // 处理POST请求
	else if (strcmp(method, "POST") == 0)
	{
		// 查找Content-Length头部
		header = strstr(request, "Content-Length");
		if (header == NULL)
		{
			// 没有Content-Length头部，不处理POST请求体
			return;
		}

		// 解析Content-Length头部的值
		int content_length = atoi(get_header_value(header, "Content-Length"));

		// 查找请求体
		body = strstr(request, "\r\n\r\n") + 4;
		if (body == NULL)
		{
			// 没有请求体
			return;
		}

		// 处理POST请求体
		printf("POST request body: %.*s\n", content_length, body);

		// 构造响应消息
		char *response = "HTTP/1.1 200 OK\r\n"
						 "Content-Type: text/plain\r\n"
						 "\r\n"
						 "Hello, World!";

		// 发送响应
		send(client_socket, response, strlen(response), 0);
	}
	else
	{
		// 不支持的HTTP方法，返回405 Method Not Allowed
		char *response = "HTTP/1.1 405 Method Not Allowed\r\n"
						 "Content-Length: 0\r\n"
						 "\r\n";
		send(client_socket, response, strlen(response), 0);
	}
}

int main()
{
	const int EVENTS_SIZE = 20;
	// 读socket的数组
	char buff[1024];

	// 创建一个tcp socket
	int socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// 设置socket监听的地址和端口
	sockaddr_in sockAddr{};
	sockAddr.sin_port = htons(8088);
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_addr.s_addr = htons(INADDR_ANY);

	// 将socket和地址绑定
	if (bind(socketFd, (sockaddr *)&sockAddr, sizeof(sockAddr)) == -1)
	{
		cout << "bind error" << endl;
		return -1;
	}

	// 开始监听socket,当调用listen之后,
	// 进程就可以调用accept来接受一个外来的请求
	// 第二个参数,请求队列的长度
	if (listen(socketFd, 10) == -1)
	{
		cout << "listen error" << endl;
		return -1;
	}

	// 创建一个epoll,size已经不起作用了,一般填1就好了
	int eFd = epoll_create(1);

	// 把socket包装成一个epoll_event对象并添加到epoll中
	epoll_event epev{};
	epev.events = EPOLLIN;							// 可以响应的事件,这里只响应可读就可以了
	epev.data.fd = socketFd;						// socket的文件描述符
	epoll_ctl(eFd, EPOLL_CTL_ADD, socketFd, &epev); // 添加到epoll中

	// 回调事件的数组,当epoll中有响应事件时,通过这个数组返回
	epoll_event events[EVENTS_SIZE];

	// 整个epoll_wait 处理都要在一个死循环中处理
	while (true)
	{
		// 这个函数会阻塞,直到超时或者有响应事件发生
		int eNum = epoll_wait(eFd, events, EVENTS_SIZE, -1);

		if (eNum == -1)
		{
			cout << "epoll_wait" << endl;
			return -1;
		}
		// 遍历所有的事件
		for (int i = 0; i < eNum; i++)
		{
			// 判断这次是不是socket可读(是不是有新的连接)
			if (events[i].data.fd == socketFd)
			{
				if (events[i].events & EPOLLIN)
				{
					sockaddr_in cli_addr{};
					socklen_t length = sizeof(cli_addr);
					// 接受来自socket连接
					int fd = accept(socketFd, (sockaddr *)&cli_addr, &length);
					if (fd > 0)
					{
						// 设置响应事件,设置可读和边缘(ET)模式
						// 很多人会把可写事件(EPOLLOUT)也注册了,后面会解释
						epev.events = EPOLLIN | EPOLLET;
						epev.data.fd = fd;
						// 设置连接为非阻塞模式
						int flags = fcntl(fd, F_GETFL, 0);
						if (flags < 0)
						{
							cout << "set no block error, fd:" << fd << endl;
							continue;
						}
						if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
						{
							cout << "set no block error, fd:" << fd << endl;
							continue;
						}
						// 将新的连接添加到epoll中
						epoll_ctl(eFd, EPOLL_CTL_ADD, fd, &epev);
						cout << "client on line fd:" << fd << endl;
					}
				}
			}
			else
			{ // 不是socket的响应事件

				// 判断是不是断开和连接出错
				// 因为连接断开和出错时,也会响应`EPOLLIN`事件
				if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
				{
					// 出错时,从epoll中删除对应的连接
					// 第一个是要操作的epoll的描述符
					// 因为是删除,所有event参数天null就可以了
					epoll_ctl(eFd, EPOLL_CTL_DEL, events[i].data.fd, nullptr);
					cout << "client out fd:" << events[i].data.fd << endl;
					close(events[i].data.fd);
				}
				else if (events[i].events & EPOLLIN) // 如果是可读事件
				{ 
                    int client_socket = events[i].data.fd;
					int len = recv(client_socket, buff, BUFFER_SIZE, 0);
					// 如果读取数据出错,关闭并从epoll中删除连接
					if (len == -1)
					{
						epoll_ctl(eFd, EPOLL_CTL_DEL, events[i].data.fd, nullptr);
						cout << "client out fd:" << events[i].data.fd << endl;
						close(events[i].data.fd);
					}
					else
					{
						
						// 正常读取,打印读到的数据
						cout << buff << endl;

						buff[len] = '\0';
						// 处理HTTP请求
						handle_request(buff, client_socket);
					}
				}
			}
		}
	}
}