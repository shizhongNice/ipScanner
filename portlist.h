#ifndef PORTLIST_H
#define PORTLIST_H

#include <stdlib.h>

#define ARRAY_SIZE(arr)  (sizeof(arr)/sizeof(arr[0]))

#define USING_THREAD_NUM  (40)

typedef enum _scan_type_e
{
    SCANNER_TCP,
    SCANNER_UDP,
}scan_type_e;

typedef struct PortInfo
{
    int     port;     //端口
    int     isOpen;   //检测结果
    char    desc[64]; //端口描述
}PortInfo, *PortInfoList;

typedef struct HostInfo
{
    char    ip[32];   //端口
    int     isalive;  //检测结果
    char    desc[64]; //端口描述
}HostInfo, *HostInfoList;

//! TCP
PortInfoList new_tcpportlist();

int get_tcpportlist_count();

void delete_tcpportlist(PortInfoList lst);

//! UDP
PortInfoList new_udpportlist();

int get_udpportlist_count();

void delete_udpportlist(PortInfoList lst);

int scanner_port(const char *ip, PortInfoList lst, int count, scan_type_e scantype, int timeout_ms);

//! show
void show_port_result(const char *tittle, PortInfoList lst, int count);


int scanner_host(HostInfoList lst, int count, int timeout_ms);

void show_host_result(const char *tittle, HostInfoList lst, int count);

#endif // PORTLIST_H
