#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>

typedef struct _METHOD_REQ_
{
	uint8_t ver;
	uint8_t methods;
	uint8_t method[255];
}socks5_method_req_t;

typedef struct _METHOD_REP_
{
	uint8_t ver;
	uint8_t method;   // 0: 无用户名密码 2: 有用户名密码
}socks5_method_rep_t;


typedef struct _AUTH_REQ_
{
	char version;		// 版本，此处恒定为0x01
	char name_len;		// 第三个字段用户名的长度，一个字节，最长为0xff
	char name[255];		// 用户名
	char pwd_len;		// 第四个字段密码的长度，一个字节，最长为0xff
	char pwd[255];		// 密码

}socks5_auth_req_t;

typedef struct _AUTH_REP_
{
	char version;		// 版本，此处恒定为0x01
	char result;		// 服务端认证结果，0x00为成功，其他均为失败
}socks5_auth_rep_t;

typedef struct _COMMEND_
{
	char version; // 客户端支持的Socks版本，0x04或者0x05
	char cmd; // 客户端命令，CONNECT为0x01，BIND为0x02，UDP为0x03，一般为0x01
	char reserved; // 保留位，恒定位0x00
	char address_type; // 客户端请求的真实主机的地址类型，IP V4为0x01  
}socks5_commend_t;


typedef struct _REP_
{
	char version; // 服务器支持的Socks版本，0x04或者0x05
	char reply; // 代理服务器连接真实主机的结果，0x00成功
	char reserved; // 保留位，恒定位0x00
	char address_type; // Socks代理服务器绑定的地址类型，IP V4为0x01 
}socks5_rep_t;

// 代理服务器信息
typedef struct _PROXY_SERVER_
{
	uint32_t ip;
	uint16_t port;
	char uname[32];
	char upswd[32];
}proxy_info_t;


typedef struct _HANDLE_
{
	int32_t		 tcp_fd;
	int32_t		 udp_fd;
	uint16_t	 udp_port;  
	uint32_t	 dest_ip;   // 目标服务器ip
	uint16_t	 dest_port; // 目标服务器端口
	proxy_info_t proxy_info;
	uint8_t      protocol;
}socks5_handle_t;


socks5_handle_t socks5_handle;

int32_t create_socks5_tcp_fd(uint32_t proxy_ip, uint32_t proxy_port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
	{
		printf("create tcp fd error!\n");
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(proxy_port);
	addr.sin_addr.s_addr = proxy_ip;

	if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		printf("connect proxy server failed! [%d][%s]\n", errno, strerror(errno));
		return -1;
	}
	return fd;
}


int socks5_method_request(int32_t fd)
{
	socks5_method_req_t socks5_method_req;
	memset(&socks5_method_req, 0, sizeof(socks5_method_req));

	socks5_method_req.ver = 0x05;
	socks5_method_req.methods = 0x02;
	socks5_method_req.method[0] = 0;
	socks5_method_req.method[1] = 2;

	if(4 != write(fd, &socks5_method_req, 4))
	{
		printf("send method request failed![%s]\n", strerror(errno));
		return;
	}
	return;
}


int socks5_auth_request(int32_t fd, char *uname, char *upswd)
{
	char out[512] = {0};
	char *cur = out;
	size_t c= 0;
	uint32_t ulen = strlen(uname);
	uint32_t plen = strlen(upswd);

	*cur++ = 0x01; //ver;
	c = ulen & 0xff;
	*cur++ = c;
	memcpy(cur, uname, c);
	*cur += c;
	c = plen & 0xff;
	*cur += c;
	memcpy(cur, upswd, c);
	cur += c;
	if((cur - out) != write(fd, out, cur - out))
	{
		printf("send auth request failed! [%s]\n", strerror(errno));
		return -1;
	}
	return 0;
}

int socks5_auth_response(int32_t fd)
{
	char in[4] = {0};
	if(2 != read(fd, in, 2))
	{
		printf("recv auth response failed! [%s]\n", strerror(errno));
		return -1;
	}

	if(in[0] == 0x01 && in[1] == 0x00)
	{
		return 0;
	}

	printf("recv auth response failed ver: %d status: %d\n", in[0], in[1]);
	return -1;
}


int socks5_method_response(int32_t fd, proxy_info_t* proxy_info)
{
	socks5_method_rep_t socks5_method_rep;
	memset(&socks5_method_rep, 0, sizeof(socks5_method_rep));
	if(2 != read(fd, &socks5_method_rep, 2))
	{
		printf("recv method response failed![%s]\n", strerror(errno));
		return -1;
	}

	if(socks5_method_rep.ver == 0x05 && socks5_method_rep.method == 0x00)
	{
		return 0;
	}
	else if(socks5_method_rep.ver == 0x05 && socks5_method_rep.method == 0x02)
	{
		// 需要用户名密码验证
		if(socks5_auth_request(fd,proxy_info->uname, proxy_info->upswd) < 0)
			return -1;
		if(socks5_auth_response(fd) < 0)
			return -1;
	}
	else
	{
		printf("客户端验证方式不正确！[%s] [%d]\n ", __FILE__, __LINE__);
		return -1;
	}
	return 1;
}


int socks5_dest_request(int32_t fd, uint32_t dest_ip, uint16_t dest_port)
{
	char buff[32] = {0};
	int buff_iter = 0;

	buff[buff_iter++] = 0x05;

	if(socks5_handle.protocol == 6)
	{
		buff[buff_iter++] = 0x01;  // tcp connect
	}
	else
	{
		buff[buff_iter++] = 0x03; // udp associate
	}

	buff[buff_iter++] = 0;    // reserved
	buff[buff_iter++] = 1;    // ipv4
	memcpy(buff + buff_iter, &dest_ip, 4);
	buff_iter += 4;
	memcpy(buff + buff_iter, &dest_port, 2);
	buff_iter += 2;

	if(buff_iter != write(fd, buff, buff_iter))
	{
		printf("send dest request failed! [%s]\n", strerror(errno));
		return -1;
	}

	return 0;
}

int32_t create_socks5_udp_fd()
{
	struct sockaddr_in addr;
	int32_t fd = 0;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		printf("create udp fd failed!\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = INADDR_ANY;

	if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		printf("binf local udp fd failed!\n");
		return -1;
	}

	return fd;
}


int read_n_bytes(int32_t fd, char *buf, int len)
{
	int rlen = 0;
	size_t r_tol_len = 0;
	while(1)
	{
		rlen = read(fd, buf, len - r_tol_len);
		if(rlen <= 0)
			return rlen;
		r_tol_len += rlen;
		if(r_tol_len == len)
			return r_tol_len;
	}
	return 0;
}



int socks5_dest_response(int32_t fd, proxy_info_t* server_info)
{
	char buff[512] = {0};
	int len = 0;
	uint16_t udp_port = 0;
	char ip_str[16] = {0};
	uint32_t ip;

	if(4 != read_n_bytes(fd, buff, 4))
	{
		if(buff[1] == 0x07)
		{
			printf("proxy server not support udp!\n");
			return -1;
		}
		printf("read dest response failed![%d] [%s]\n",errno ,strerror(errno));
		return -1;
	}

	if(buff[1] == 0x05)
	{
		printf("proxy refuse!!!\n");
		return -1;
	}

	if(6 != read_n_bytes(fd, buff, 6))
	{
		printf("read dest response port failed! [%s]\n", strerror(errno));
		return -1;
	}
	ip = *((uint32_t*)(buff));
	inet_ntop(AF_INET, &ip, ip_str);
	//printf("ip:%s\n", ip_str);

	if(socks5_handle.protocol == 6)
		return 0;

	// udp 会重新创建udp_fd
	udp_port = *((uint16_t*)(buff+4));

	socks5_handle.udp_port = udp_port;
	socks5_handle.udp_fd = create_socks5_udp_fd();
	if(socks5_handle.udp_fd < 0)
	{
		return -1;	
	}
}

int getstr(char* str, char *start_str, char *end_str)
{
	char *p = str;
	char *q = NULL;
	char *m = str;
	if(!str)
		return -1;
	
	q = strstr(str, ":");
	if(!q)
		return -1;
	memcpy(start_str, p, q-p);
	memcpy(end_str, q + 1, strlen(str) - (q-p) - 1);

}

int check_option(int argc, char **argv)
{
	int		opt = 0;
	char	ip[16] = {0};
	char	port[16] = {0};
	char	name[32] = {0};
	char	pswd[32] = {0}; 
	int		flag = 0;
	struct option opts[]=
	{
		{"proxy",required_argument, NULL, 1},
		{"auth", required_argument, NULL, 2},
		{"remotehost", required_argument, NULL, 3},
		{"protocol", required_argument, NULL, 4},
		{"help", no_argument, NULL, 5},
		{0,0,0,0}
	};

	socks5_handle.protocol = 6; // default tcp 

	while((opt = getopt_long(argc, argv, "p:u:d:P:h", opts, NULL)) != -1)
	{
		memset(ip, 0, sizeof(ip));
		switch(opt)
		{
			case 1:
			case 'p':
				getstr(optarg, ip, port);
				socks5_handle.proxy_info.ip = inet_addr(ip);
				socks5_handle.proxy_info.port = atoi(port);
				printf("proxy: %s:%u\n",ip, socks5_handle.proxy_info.port);
				flag++;
				break;
			case 2:
			case 'u':
				getstr(optarg, name, pswd);
				memcpy(socks5_handle.proxy_info.uname, name, sizeof(name));
				memcpy(socks5_handle.proxy_info.upswd, pswd, sizeof(pswd));
				flag++;
				break;
			case 3:
			case 'd':
				getstr(optarg, ip, port);
				socks5_handle.dest_ip = inet_addr(ip);
				socks5_handle.dest_port = htons(atoi(port));
				printf("remote: %s:%u\n",ip, socks5_handle.dest_port);
				flag++;
				break;
				break;
			case 4:
			case 'P':
				if(strcmp(optarg, "tcp") == 0)
					socks5_handle.protocol = 6;
				else if(strcmp(optarg, "udp") == 0)
					socks5_handle.protocol = 17;
				else
				{
					printf("协议不正确\n");
					return -1;
				}
				flag++;
				break;
			case 5:
			case 'h':
				return -1;
		}
	}

	if(flag < 2)
	{
		return -1;
	}
	return 0;
}


int tcp_proc()
{

	printf("tcp start---------------\n");
	pid_t pid;
	pid = fork();

	if(pid == 0)
	{
		int ret = 0;
		char send_buf[1024] = {0};
		int len = 0;
		char buf[128] = {0};
		struct sockaddr_in addr;

		while(1)
		{
			memset(send_buf, 0, sizeof(send_buf));
			memset(buf,0, sizeof(buf));
			len = 0;
			printf("input:");
			scanf("%s", buf);
			buf[strlen(buf) - 1] = '\n';
			memcpy(send_buf, buf, strlen(buf));
			len = strlen(buf);
			ret = sendto(socks5_handle.tcp_fd, send_buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
			if(ret < 0)
			{
				printf("send msg error! [%s] [%s] [%d]\n", strerror(errno), __FILE__, __LINE__);
				close(socks5_handle.tcp_fd);
				return -1;
			}
			printf("send msg:%s\n", send_buf);
		}
	}
	else if(pid > 0)
	{

		 char buf[1024] = {0};
		 struct sockaddr_in addr;
		 int ret = 0;
		 socklen_t sin_size = sizeof(addr);
		while(1)
		{
			ret = recvfrom(socks5_handle.tcp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr,&sin_size);
			if(ret < 0)
			{
				printf("recv msg failed! [%s] [%s] [%d]\n", strerror(errno), __FILE__, __LINE__);
				close(socks5_handle.tcp_fd);
				return -1;
			}
			printf("recv_msg: %s\n", buf);
			memset(buf, 0, sizeof(buf));
		}
	}
	else
	{
		printf(" fork failed!\n");
		return -1;
	}

	return 0;
}

int udp_proc()
{

	printf("udp start---------------\n");
	pid_t pid;
	pid = fork();

	if(pid == 0)
	{
		int ret = 0;
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		char ip_str[16] = {0};
		addr.sin_port = socks5_handle.udp_port;
		addr.sin_addr.s_addr = socks5_handle.proxy_info.ip;
		char send_buf[1024] = {0};
		int len = 0;
		char buf[128] = {0};

		send_buf[0] = 0;
		send_buf[1] = 0;
		send_buf[2] = 0;
		send_buf[3] = 1;
		memcpy(send_buf + 4, &socks5_handle.dest_ip, sizeof(uint32_t));
		memcpy(send_buf + 8, &socks5_handle.dest_port, sizeof(uint16_t));
		inet_ntop(AF_INET,&socks5_handle.dest_ip, ip_str, 16);
		printf("udp_port: %u dest_ip: %s dest_port: %u udp_fd: %d\n", socks5_handle.udp_port,ip_str, ntohs(socks5_handle.dest_port), socks5_handle.udp_fd);

		while(1)
		{
			memset(send_buf+10, 0, sizeof(send_buf));
			memset(buf,0, sizeof(buf));
			printf("input:");
			scanf("%s", buf);
			buf[strlen(buf) - 1] = '\n';
			memcpy(send_buf + 10, buf, strlen(buf));
			len = 10 + strlen(buf);
			ret = sendto(socks5_handle.udp_fd, send_buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
			if(ret < 0)
			{
				printf("send msg error! [%s] [%s] [%d]\n", strerror(errno), __FILE__, __LINE__);
				return -1;
			}
			printf("send msg:%s\n", send_buf+10);
		}
	}
	else if(pid > 0)
	{

		 char buf[1024] = {0};
		 struct sockaddr_in addr;
		 int ret = 0;
		 socklen_t sin_size = sizeof(addr);
		while(1)
		{
			ret = recvfrom(socks5_handle.udp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr,&sin_size);
			if(ret < 0)
			{
				printf("recv msg failed! [%s] [%s] [%d]\n", strerror(errno), __FILE__, __LINE__);
				return -1;
			}
			printf("recv_msg: %s\n", buf + 10);
			memset(buf, 0, sizeof(buf));
		}
	}
	else
	{
		printf(" fork failed!\n");
		return -1;
	}

	return 0;
}


void usage()
{
	printf("usage: ./socks5 [option] ... [-p proxy -u auth -d remote -P protocol]\n");
	printf("options and arguments:\n");
	printf("-p, --proxy host:port Use socks5 proxy on given port\n");
	printf("-u, --auth username:passwd Use proxy username and passwd\n");\
	printf("-d, --remote remoteip:remoteport Use remote ip and port\n");
	printf("-P, --protocol tcp or udp\n");
	printf("-h, --help\n");
	return;
}

int main(int argc, char *argv[])
{	

	if(check_option(argc, argv) < 0)
	{
		usage();
		return -1;
	}

	socks5_handle.tcp_fd = create_socks5_tcp_fd(socks5_handle.proxy_info.ip, socks5_handle.proxy_info.port);
	// 客户端请求验证方式
	if(socks5_method_request(socks5_handle.tcp_fd) < 0)
	{
		 goto err;
	}
	
	printf("create fd success!\n");
	// 服务器回复验证请求
	if(socks5_method_response(socks5_handle.tcp_fd, &socks5_handle.proxy_info) < 0)  //有用户名 则需要验证
	{
		goto err;
	}

	printf("auth success! \n");
	// 客户端请求连接目标服务器
	if(socks5_dest_request(socks5_handle.tcp_fd, socks5_handle.dest_ip, socks5_handle.dest_port))
	{
		goto err;
	}

	// 服务器回复连接目标服务器结果
	if(socks5_dest_response(socks5_handle.tcp_fd, &socks5_handle.proxy_info) < 0)   // 若是udp则需要重新创建udp连接
	{
		goto err;
	}

	printf("connect success! \n");

	switch(socks5_handle.protocol)
	{
		case 6:
			tcp_proc();
			goto err;
		case 17:
			udp_proc();
			goto err;
	}
err:
	close(socks5_handle.tcp_fd);
	if(socks5_handle.protocol == 17)
	{
		 close(socks5_handle.udp_fd);
	}
	return 0;
}

