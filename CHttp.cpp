#include "CHttp.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <string>
#include <time.h>
#include <fstream>
#include <iostream>
#include <unistd.h>

using namespace std;

char m_strRootDir[]="/home/liuhangzhuo/Desktop/HttpsServer/mySites";
char HTTP_STATUS_OK[]="200 OK";

string GetContentType(string fileExt){
	if (fileExt == ".doc")
		return "application/msword";
	else if (fileExt == ".docx")
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
	else if (fileExt == ".rtf")
		return "application/rtf";
	else if (fileExt == ".xls")
		return "application/vnd.ms-excel";
	else if (fileExt == ".xlsx")
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
	else if (fileExt == ".ppt")
		return "application/vnd.ms-powerpoint";
	else if (fileExt == ".pptx")
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
	else if (fileExt == ".pdf")
		return "application/pdf";
	else if (fileExt == ".swf")
		return "application/x-shockwave-flash";
	else if (fileExt == ".rar")
		return "application/octet-stream";
	else if (fileExt == ".zip")
		return "application/x-zip-compressed";
	else if (fileExt == ".mp3")
		return "audio/mpeg";
	else if (fileExt == ".gif")
		return "image/gif";
	else if (fileExt == ".png")
		return "image/png";
	else if (fileExt == ".jpeg")
		return "image/jpeg";
	else if (fileExt == ".jpg")
		return "image/jpeg";
	else if (fileExt == ".jpe")
		return "image/jpeg";
	else if (fileExt == ".txt")
		return "text/plain";
	else if (fileExt == ".bmp")
		return "image/jpeg";
	else if (fileExt == ".exe")
		return "application/octet-stream";
	else if (fileExt == ".html" || fileExt == ".htm")
		return "text/html";
	else
		return "application/octet-stream";
}

int password_cb(char *buf, int size, int rwflag, void *password){
	strncpy(buf, (char *)(password), size);
  	buf[size - 1] = '\0';
  	return(strlen(buf));
}

CHttpProtocol::CHttpProtocol(){
	SSL_library_init();			// 加载OpenSSL将会用到的算法
    SSL_load_error_strings();	// 加载错误字符串
    OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();

	const SSL_METHOD *meth;

    meth = SSLv23_method();	// 相应的SSL结构能理解SL2.0、3.0以及TSL1.0
    ctx = SSL_CTX_new(meth);	// 创建一个上下文环境
    if(SSL_CTX_use_certificate_chain_file(ctx, "./my_service/service.pem") != 1){ // 指定所使用的证书文件
		perror("SSL_CTX_use_certificate_file failed!\n");
        exit(errno);
	}

    
	if(SSL_CTX_use_PrivateKey_file(ctx, "./my_service/service.key", SSL_FILETYPE_PEM) != 1){ // 加载私钥文件
		perror("SSL_CTX_use_PrivateKey_file failed!\n");
		exit(errno);
	}

	if(!SSL_CTX_check_private_key(ctx)){
		perror("cert error");
		exit(errno);
	}

    SSL_CTX_set_default_passwd_cb(ctx, password_cb);	// 设置密码回调函数

    SSL_CTX_load_verify_locations(ctx, "./my_service/demoCA/newcerts/ca.pem", 0);		// 加载受信任的CA证书

    /*当使用RSA算法鉴别的时候，会有一个临时的DH密钥磋商发生。这样会话数据将用
    这个临时的密钥加密，而证书中的密钥作为签名*/
    load_dh_params(ctx, "./dh1024.pem");

	if ((m_listenSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("Socket");
        exit(errno);
    }

	int one=1;
    if(setsockopt(m_listenSocket,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))<0){
        perror("Socket opt set");
        exit(errno);
    }

	char strIpAddr[]="127.0.0.1";
	struct sockaddr_in sLocalAddr;
	sLocalAddr.sin_family = AF_INET;
	sLocalAddr.sin_port = htons(SERVERPORT);
    sLocalAddr.sin_addr.s_addr = inet_addr(strIpAddr);

	if (bind(m_listenSocket, (struct sockaddr *) &sLocalAddr, sizeof(struct sockaddr))== -1)
    {
        perror("bind");
        exit(1);
    }
	printf("1\n");
	pthread_t listen_tid;
	pthread_create(&listen_tid,NULL,&ListenThread,this);
}

void CHttpProtocol::load_dh_params(SSL_CTX *ctx, char *file){
	DH *ret=0;
	BIO *bio;

	if((bio=BIO_new_file(file,"r"))==NULL){
		perror("failed to open dh file\n");
	}

	ret=PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
	BIO_free(bio);

	if(SSL_CTX_set_tmp_dh(ctx,ret)<0){
		perror("failed to set dh params\n");
	}
}


void * CHttpProtocol::ListenThread(LPVOID param)
{
	printf("-----------------server-------------------\n");
	CHttpProtocol *pHttpProtocol = (CHttpProtocol *)param;

	int ret=listen(pHttpProtocol->m_listenSocket,4);		//server_fd设置为监听套接字
	if(ret==-1)
	{
		perror("listen:");
	}
	while(1)	// 循环等待,如有客户连接请求,则接受客户机连接要求
	{	
		struct sockaddr_in SockAddr;
		socklen_t nLen = sizeof(SockAddr);		
		// 套接字等待链接,返回对应已接受的客户机连接的套接字
		int socketClient = accept(pHttpProtocol->m_listenSocket, (LPSOCKADDR)&SockAddr, &nLen);
		if (socketClient == INVALID_SOCKET)
			break;
		
		printf("IP:%s connecting to socket:%d\n",inet_ntoa(SockAddr.sin_addr),socketClient);
		// 创建client进程，处理request
		pthread_t client_tid;
		
		PREQUEST pReq=new REQUEST;
		pReq->pHttpProtocol=pHttpProtocol;
		pReq->Socket=socketClient;
		pReq->ssl_ctx=pHttpProtocol->ctx;

		pthread_create(&client_tid,NULL,&ClientThread,pReq);

	} //while

}

void * CHttpProtocol::ClientThread(LPVOID param)
{
	PREQUEST pReq = (PREQUEST)param;
	CHttpProtocol *pHttpProtocol = (CHttpProtocol *)pReq->pHttpProtocol;
	SOCKET s = pReq->Socket;
	BIO* sbio = BIO_new_socket(s, BIO_NOCLOSE);	// 创建一个socket类型的BIO对象
	SSL* ssl=SSL_new(pReq->ssl_ctx);				// 创建一个SSL对象
    SSL_set_bio(ssl, sbio, sbio);			// 把SSL对象绑定到socket类型的BIO上

	//连接客户端，在SSL_accept过程中，将会占用很大的cpu
    int nRet = SSL_accept(ssl);
	//printf("%d\n",nRet);
	//nRet<=0时发生错误
    if(nRet <= 0){
		//handle erro
		perror("wrong in ssl accept");
		exit(errno);
	}
	
	BIO* io = BIO_new(BIO_f_buffer());      //封装了缓冲区操作的BIO
    
	//封装了SSL协议的BIO类型，也就是为SSL协议增加了一些BIO操作方法
	BIO* ssl_bio = BIO_new(BIO_f_ssl());		
	
	// 把ssl(SSL对象)封装在ssl_bio(SSL_BIO对象)中
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);	
	
	// 把ssl_bio封装在一个缓冲的BIO对象中，实现对SSL连接的缓冲读和写
    BIO_push(io, ssl_bio);

	//printf("accept done\n");

	BYTE buf[BUFSIZZ];
	//做好上述IO绑定之后，开始接受客户端请求
	if (!pHttpProtocol->SSLRecvRequest(ssl,io,buf,sizeof(buf)))   
	{
		// 处理错误
		perror("recv request");
		exit(errno);
	}

	//printf("recv done\n");

	//HTTPS协议分析
	nRet = pHttpProtocol->Analyze(pReq, buf);  
	if (nRet)
	{	
		// 处理错误
		perror("analyze");
		exit(errno);
	}
	
	//printf("analyse done\n");

	// 生成并返回头部
	if(!pHttpProtocol->SSLSendHeader(pReq,io))
	{
		// 处理错误
		perror("send header");
		exit(errno);
	}

	//printf("send done\n");

	BIO_flush(io);
	// 向client传送数据
	if(pReq->nMethod == METHOD_GET)
	{
		if(!pHttpProtocol->SSLSendFile(pReq,io))
		{
			// 处理错误
			perror("send file");
			exit(errno);
		}
	}

	//printf("sendfile done\n");
	//sleep(50000000);
	//析构操作
	printf("Closing socket: %d\n",pReq->Socket);
	close(pReq->Socket);
}	


bool CHttpProtocol::SSLRecvRequest(SSL *ssl,BIO *io, LPBYTE pBuf, DWORD dwBufSize)
{
	char buf[BUFSIZZ];
	memset(buf, 0, BUFSIZZ);	//初始化缓冲区
	int length = 0;
	while(1)
	{
		int r = BIO_gets(io, buf, BUFSIZZ-1);
		//printf("got some data\n");
		//printf("%s",buf);
		//printf("%d\n",r);
		switch(SSL_get_error(ssl, r))
		{
			case SSL_ERROR_NONE:
				memcpy(&pBuf[length], buf, r);
				length += r;
				//printf("no error\n");
				break;
			default:
				break;
		}
		// 直到读到代表HTTP头部结束的空行
		if(!strcmp(buf,"\r\n") || !strcmp(buf,"\n"))
			break;
   }
	// 添加结束符
	pBuf[length] = '\0';
	//printf("done\n");
	return true;
}


int  CHttpProtocol::Analyze(PREQUEST pReq, LPBYTE pBuf)
{
	// 分析接收到的信息
	char szSeps[] = " \n";
	char *cpToken;
	// 判断request的method	
	cpToken = strtok((char *)pBuf, szSeps);	// 缓存中字符串分解为一组标记串。
	//printf("%s\n",cpToken);	
	if (!strcmp(cpToken, "GET"))			// GET命令
	{
		pReq->nMethod = METHOD_GET;
	}
	cpToken=strtok(NULL, szSeps);
	strcpy(pReq->szFileName, m_strRootDir);
	if (strlen(cpToken) > 1)
	{
		strcat(pReq->szFileName, cpToken);	// 把该文件名添加到结尾处形成路径
		printf("%s\n",cpToken);
	}
	else
	{
		strcat(pReq->szFileName, "/index.html"); //若无文件名，则默认为index.html
		printf("index.html\n");
	}
	return 0;
}


bool CHttpProtocol::SSLSendHeader(PREQUEST pReq, BIO *io)
{
	char Header[200]={0};

	char curTime[50];
	time_t rawTime;
	struct tm* timeInfo;
	time(&rawTime);
	timeInfo = gmtime(&rawTime);
    strftime(curTime,sizeof(curTime),"%a, %d %b %Y %H:%M:%S GMT",timeInfo);

	// 取得文件的last-modified时间
	//char last_modified[60] = " ";
	//GetLastModified(pReq->hFile, (char*)last_modified);


	// 取得文件的类型
	string filename(pReq->szFileName);
	string fileExt = filename.substr(filename.find_last_of('.'));
	string ContentType=GetContentType(fileExt);

	ifstream fin(filename);
	int length=0;
	if(fin.is_open())
	{
		fin.seekg( 0, ios::end );
		length = fin.tellg();
		fin.close();
	}

	pReq->dwSend=length;
	
	//组成完整的服务器响应
	sprintf((char*)Header, "HTTP/1.1 %s\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
	        HTTP_STATUS_OK, 
	        curTime,				// Date
			"Villa Server 127.0.0.1",      // Server"My Https Server"
			ContentType,				// Content-Type
			length);					// Content-length
	BIO_puts(io, Header);
	BIO_flush(io);   //一次性清空缓冲区，全部写入io
	return true;
}


bool CHttpProtocol::SSLSendFile(PREQUEST pReq, BIO *io){
	ifstream in(pReq->szFileName,ios::in|ios::binary);
	char *buf=new char[pReq->dwSend];
	
	memset(buf,0,sizeof(buf));
	if(!in.read(buf,pReq->dwSend)){
		perror("error when read file");
		exit(errno);
	}
	//printf("%s\n",buf);

	BIO_write(io,buf,pReq->dwSend);
	
	BIO_flush(io);
	return true;
}