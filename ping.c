#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define PING_DATA_LEN 56

//ICMP消息头部
typedef struct ICMPHeader
{
    unsigned char type;//消息类型
    unsigned char code;//消息代码
    unsigned short checksum;//校验和
    union{
        struct{
            unsigned short id;
            unsigned short sequence;
        }echo;

        unsigned int gateway;

        struct{
            unsigned short unsed;
            unsigned short nextmtu;
        }frag; //pmtu实现
    }un;

    unsigned char data[0]; //ICMP数据占位符
}ICMPHeader;

typedef struct IPHeader
{
    unsigned char   headerLen:4;
    unsigned char   version:4;
    unsigned char   tos;        //服务类型
    unsigned short  totalLen;   //总长度
    unsigned short  id;         //标识
    unsigned short  flagOffset; //3位标志+13位片偏移
    unsigned char   ttl;        //TTL
    unsigned char   protocol;   //协议
    unsigned short  checksum;   //首部检验和
    unsigned int    srcIP;      //源IP地址
    unsigned int    dstIP;      //目的IP地址
}IPHeader;


//This function calculates the 16-bit one's complement sum
//of the supplied buffer (ICMP) header
unsigned short checksum(unsigned short* buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(unsigned char*)buffer;
    }
    cksum = (cksum>>16) + (cksum & 0xffff);
    cksum += (cksum>>16);
    return (unsigned short)(~cksum);
}

//校验和算法
unsigned short cal_chksum(unsigned short *addr,int len)
{
    int nleft=len;
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;

    //把ICMP报头二进制数据以2字节为单位累加起来
    while(nleft>1)
    {
        sum+=*w++;
        nleft-=2;
    }

    //若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加
    if( nleft==1)
    {
        *(unsigned char *)(&answer)=*(unsigned char *)w;
        sum+=answer;
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return answer;
}

//ip数字转字符串
void ip_ll_to_str(long long ip_num,char* ip_str)
{
    unsigned int iptok1 = (ip_num & 0xFF000000) >> 24;
    unsigned int iptok2 = (ip_num & 0x00FF0000) >> 16;
    unsigned int iptok3 = (ip_num & 0x0000FF00) >> 8;
    unsigned int iptok4 = ip_num & 0x000000FF;
    char ip[32];
    bzero(ip,sizeof(ip));
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d", iptok1,iptok2,iptok3,iptok4);
    strcpy(ip_str, ip);
}

//发送ICMP报文
int send_icmp_packet(int sockfd, struct sockaddr_in* dst_addr, int pid, char is_build_ip_protocl)
{
    char sendBuf[1024] = "";
    int totalLen = sizeof(IPHeader) + sizeof(ICMPHeader) + PING_DATA_LEN;
    int pos = 0;
    if(is_build_ip_protocl)
    {
        IPHeader* ipHeader = (IPHeader *)sendBuf;
        ipHeader->headerLen = sizeof(IPHeader)>>2;
        ipHeader->version = IPVERSION;
        //服务类型
        ipHeader->tos = 0;
        ipHeader->totalLen = htons(totalLen);
        ipHeader->id=0;
        //设置flag标记为0
        ipHeader->flagOffset=0;
        //运用的协议为ICMP协议
        ipHeader->protocol=IPPROTO_ICMP;
        //一个封包在网络上可以存活的时间
        ipHeader->ttl = 255;
        //目的地址
        ipHeader->dstIP = dst_addr->sin_addr.s_addr;
        pos = sizeof(IPHeader);
    }

    ICMPHeader *icmpHeader = (ICMPHeader*)(sendBuf+pos);
    icmpHeader->type = ICMP_ECHO;
    icmpHeader->code = 0;
    icmpHeader->un.echo.id = pid;

    //计算校验和
    icmpHeader->checksum = cal_chksum( (unsigned short *)icmpHeader,totalLen);

    IPHeader* ipHeader = (IPHeader *)sendBuf;

    char srcIPStr[64] = "",dstIPStr[64]="";
    ip_ll_to_str(ipHeader->srcIP,srcIPStr);
    ip_ll_to_str(ipHeader->dstIP,dstIPStr);

//    char ipHeaderStr[256] = "";
//    snprintf(ipHeaderStr, sizeof(ipHeaderStr),
//             "request ip header info: version:%d,tos:%d,protocol:%d,ttl:%d,srcIP:%s,dstIP:%s",
//             ipHeader->version,ipHeader->tos,ipHeader->protocol,ipHeader->ttl,srcIPStr,dstIPStr);
//    printf("%s\n", ipHeaderStr);

    if(sendto(sockfd,sendBuf,totalLen,0,(struct sockaddr *)dst_addr,sizeof(*dst_addr))<0){
        perror("sendto error");
        return -1;
    }
    return 0;
}

//接收解析ICMP报文
int parse_icmp_packet(int sockfd,int pid)
{
    struct sockaddr_in cliaddr;
    bzero(&cliaddr,sizeof(cliaddr));
    socklen_t cliLen = sizeof(cliaddr);
    char recvBuf[256] = "";
    int recvLen = recvfrom(sockfd,recvBuf,sizeof(recvBuf),0,(struct sockaddr*)&cliaddr,&cliLen);
    if( recvLen < 0)
    {
        if(errno==EINTR)
        {
            return -101;
        }
        return -102;
    }

#if 01
    IPHeader *ipHeader = (IPHeader*)recvBuf;

    char srcIPStr[64] = "",dstIPStr[64]="";
    ip_ll_to_str(ntohl(ipHeader->srcIP),srcIPStr);
    ip_ll_to_str(ntohl(ipHeader->dstIP),dstIPStr);

    int ipHeaderLen = sizeof(IPHeader);
    int icmpLen = recvLen - ipHeaderLen;
    //小于ICMP报头长度则不合理
    if( icmpLen < 8)
    {
        return -103;
    }

    ICMPHeader *icmpHeader = (ICMPHeader *)(recvBuf+sizeof(IPHeader));  //越过ip报头,指向ICMP报头
    //确保所接收的是我所发的的ICMP的回应
    if(icmpHeader->type != ICMP_ECHOREPLY || icmpHeader->un.echo.id != pid)
    {
        return -104;
    }

//    char ipHeaderStr[256] = "";
//    snprintf(ipHeaderStr,sizeof(ipHeaderStr),
//             "response ip header info: version:%d,tos:%d,protocol:%d,ttl:%d,srcIP:%s,dstIP:%s",
//             ipHeader->version,ipHeader->tos,ipHeader->protocol,ipHeader->ttl,srcIPStr,dstIPStr);

//    char icmpStr[256] = "";
//    snprintf(icmpStr,sizeof(icmpStr),"%d byte from %s: icmp_seq=%d,ttl=%dms",icmpLen,inet_ntoa(cliaddr.sin_addr),icmpHeader->un.echo.sequence,ipHeader->ttl);
//    printf("%s\n", icmpStr);
#endif
    return 0;
}

int ping(const char *ip, int timeout_ms)
{
    //用主机名或ip地址都可以
    int ret = -1;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if( sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    struct timeval timeout = {1, 0};
    if(timeout_ms > 0)
    {
        timeout.tv_sec = timeout_ms/1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
    }
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ret = setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    //扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答
    int bufSize = 50*1024;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufSize, sizeof(bufSize) );
    if(ret != 0) { ret = -2; goto ERR; }

    //构造自己的ip协议头
    int on = 1;
    ret = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    if(ret != 0) { ret = -3; goto ERR; }

    struct sockaddr_in dst_addr;
    bzero(&dst_addr,sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(ip);

    if( dst_addr.sin_addr.s_addr == INADDR_NONE)
    {
        struct hostent *host = gethostbyname(ip);
        if(host == NULL) { ret = -4; goto ERR; }
        memcpy( (char *)&dst_addr.sin_addr,host->h_addr,host->h_length);
    }

    //获取main的进程id,用于设置ICMP的标志符
    int pid = getpid();

    int try_times = 3;
    do
    {
        //发送ICMP报文
        ret = send_icmp_packet(sockfd, &dst_addr, pid, 1);

        //解析所有ICMP报文
        ret = parse_icmp_packet(sockfd, pid);
//        printf("parse_icmp_packet %s %d\n", ip, ret);
        if(ret == 0)
        {
            break;
        }
    }while(--try_times);

    if(ret != 0) { goto ERR; }

    close(sockfd);
    return 0;

ERR:
    close(sockfd);
    return ret;
}

/**
 * @brief ping检测网络是否通畅
 * @param ip 目的主机,IP 或 域名
 * @return 成功返回0，否则失败
 */
int network_ping(const char *ip, int timeout_ms)
{
#if 01
    char cmd[128] = "";
    snprintf(cmd, sizeof(cmd), "ping -i 0.2 -c 1 %s > /dev/null 2>&1", ip); //-s 1

    int try_times = 2;
    int ret = -1;
    do
    {
        ret = system(cmd);
        if(ret == 0)
            return 0;
    }while(--try_times);
    return -1;
#else
    return ping(ip, timeout_ms); //need root running
#endif
}
