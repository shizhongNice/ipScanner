#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "ping.h"
#include "scanner.h"
#include "portlist.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    if (geteuid())
    {
        fprintf(stderr, "Please run this program as root user. You may use sudo!\n");
        return 1;
    }

    int timeout_ms = 100;
    int host_count = 0;

#define IPPOOL_MAXNUM 1024

    char prefix_ip[32] = "192.168.1.";

    HostInfoList hostlst = (HostInfoList)malloc( IPPOOL_MAXNUM * sizeof(HostInfo) );

    for(int i = 1; i < 255; i++)
    {
        sprintf(hostlst[i-1].ip, "%s%d", prefix_ip, i);
    }

    scanner_host(hostlst, 254, timeout_ms);
    show_host_result("Host", hostlst, 254 );

    for(int i=0; i < 254; i++)
    {
        if(hostlst[i].isalive == 1)
        {
            host_count++;
            char *ip = hostlst[i].ip;

            PortInfoList tcplst = new_tcpportlist();
            scanner_port(ip, tcplst, get_tcpportlist_count(), SCANNER_TCP , timeout_ms);
            show_port_result( ip, tcplst, get_tcpportlist_count() );
            delete_tcpportlist(tcplst);

//            PortInfoList udplst = new_udpportlist();
//            scanner_port(ip, udplst, get_udpportlist_count(), SCANNER_UDP , timeout_ms);
//            show_port_result(ip, udplst, get_udpportlist_count() );
//            delete_udpportlist(udplst);
        }
    }

    printf("scan lan host total count %d\n", host_count);



    getchar();
    return 0;
}
