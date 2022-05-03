#include<openssl/ssl.h>

typedef u_char* LPBYTE;
typedef u_char BYTE;
typedef u_int32_t DWORD;
typedef void* LPVOID;
typedef int SOCKET;
typedef struct sockaddr* LPSOCKADDR;

#define INVALID_SOCKET -1
#define METHOD_GET 1
#define BUFSIZZ 1024
#define SERVERPORT 22222

typedef struct REQUEST
{
	SOCKET		Socket;                // 请求的socket
	int			nMethod;               // 请求的使用方法：GET或HEAD
	DWORD		dwRecv;                // 收到的字节数
	DWORD		dwSend;                // 发送的字节数
	int 		hFile;                 // 请求连接的文件
	char		szFileName[256];       // 文件的相对路径
	char		postfix[10];           // 存储扩展名
	SSL_CTX *	ssl_ctx;           //SSL上下文
	void* pHttpProtocol;			   // 指向类CHttpProtocol的指针
}REQUEST, *PREQUEST;


class CHttpProtocol
{
public:
	CHttpProtocol(void);
	~CHttpProtocol(void){
	}
	SSL_CTX *ctx;       //SSL上下文
	int m_listenSocket;

	char * initialize_ctx();			//初始化CTX
	void load_dh_params(SSL_CTX *ctx, char *file);		//加载CTX参数
	//int TcpListen(); 	//TCP监听函数
	void StopHttpSrv();		//停止HTTP服务
	bool StartHttpSrv();		//开始HTTP服务
	static void * ListenThread(LPVOID param);		//监听线程
	static void * ClientThread(LPVOID param);		//客户线程	
	
	//接收HTTPS请求
	bool SSLRecvRequest(SSL *ssl,BIO *io, LPBYTE pBuf, DWORD dwBufSize); 
	
	int Analyze(PREQUEST pReq, LPBYTE pBuf);		//分析HTTP请求
	bool SSLSendHeader(PREQUEST pReq, BIO *io);		//发送HTTPS头
	bool SSLSendFile(PREQUEST pReq, BIO *io);	   	    //由SSL通道发送文件
	bool SSLSendBuffer(PREQUEST pReq, LPBYTE pBuf, DWORD dwBufSize);
};