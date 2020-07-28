#include "scanner.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

/**
 * @brief 扫描远程主机的TCP端口是否开启
 * @param ip: 远程主机IP
 * @param port: 端口号
 * @return 成功返回0，失败返回1，错误返回负数
 */
int network_port_scan_tcp(const char *ip, const short port, int timeout_ms)
{
    int		conn_fd;
    int		ret;
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof (struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn_fd < 0) {
        return -1;
    }
    struct timeval timeout = {1, 0};
    if(timeout_ms > 0)
    {
        timeout.tv_sec = timeout_ms/1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
    }
    ret = setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ret = setsockopt(conn_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    ret = connect(conn_fd, (struct sockaddr *)&serv_addr, sizeof (struct sockaddr));
    if(ret == 0)
    {
        close(conn_fd);
        return 0;
    }

    if (errno == ECONNREFUSED) {
        close(conn_fd);
        return 1;
    } else {	// 其他错误
        close(conn_fd);
        return -1;
    }
}

/**
 * @brief 扫描远程主机的UDP端口是否打开
 * @param ip: 远程主机IP
 * @param port: 端口号
 * @return
 */
int network_port_scan_udp(const char *ip, const short port, int timeout_ms)
{
#if 01
    char cmd[128] = "";
    snprintf(cmd, sizeof(cmd), "nc -vuz %s %d > /dev/null 2>&1", ip, port);
    return system(cmd);
#else

#define UDP_BUFFER_SIZE 512

    int ret = 0;
    int len = 0;
    int i;

    struct timeval timeout = {1, 0};
    struct sockaddr_in remoteaddr;
    char txmessage[UDP_BUFFER_SIZE+1],rxmessage[UDP_BUFFER_SIZE+1];

    unsigned char localmacaddr[6];
    memset( localmacaddr, 0, sizeof(localmacaddr));
    localmacaddr[5] = 0x01;

    memset(&remoteaddr, 0, sizeof(remoteaddr));
    memset(&txmessage, 0, sizeof(txmessage));
    memset(&rxmessage, 0, sizeof(rxmessage));
    if(timeout_ms > 0)
    {
        timeout.tv_sec = timeout_ms/1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
    }

    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_addr.s_addr = inet_addr(ip);
    remoteaddr.sin_port = htons(port);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return -1;

    ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    ret = connect( fd, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr) );
    if (ret < 0) return -2;

    switch (port)
    {
        // DNS query
    case 53:
    {
        // Host name to query
        char dnsquery1[] = "www6";
        char dnsquery2[] = "chappell-family";
        char dnsquery3[] = "co";
        char dnsquery4[] = "uk";

        len = 12;
        memcpy(txmessage, "\x21\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", len);

        txmessage[len++] = (char)strlen(dnsquery1);
        ret = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", dnsquery1);
        if (ret < 0 || ret >=( UDP_BUFFER_SIZE-len )) return -1;

        txmessage[len++]= (char)strlen(dnsquery2);
        ret = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", dnsquery2);
        if (ret < 0 || ret >= ( UDP_BUFFER_SIZE-len )) return -1;

        txmessage[len++]= (char)strlen(dnsquery3);
        ret = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", dnsquery3);
        if (ret < 0 || ret >= ( UDP_BUFFER_SIZE-len )) return -1;

        txmessage[len++]= (char)strlen(dnsquery4);
        ret = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len), "%s", dnsquery4);
        if (ret < 0 || ret >= ( UDP_BUFFER_SIZE-len )) return -1;

        // End of name
        txmessage[len++]= 0;
        txmessage[len++] = 0;
        txmessage[len++] = 255;
        txmessage[len++] = 0;
        txmessage[len++] = 1;
        break;
    }

    case 69:
    {
        len = snprintf(&txmessage[0], UDP_BUFFER_SIZE, "%c%c%s%d%coctet%c",0,1,"/filename_tjc_",getpid(),0,0);
        if (len < 0) return -1;
        break;
    }

    case 123:
    {
        txmessage[0] = ((0 << 5) + (4 << 3) + ( 3 ));
        txmessage[1] = 16;
        txmessage[2] = 8;
        txmessage[3] = 2;
        len = 48;
        break;
    }

    case 161:
    {
        len = 0;
        // SNMPv3 engine discovery
        txmessage[len++] = 0x30;
        txmessage[len++] = 0x38;

        // SNMP version 3
        txmessage[len++] = 0x02; // int
        txmessage[len++] = 0x01; // length of 1
        txmessage[len++] = 0x03; // SNMP v3

        // msgGlobalData
        txmessage[len++] = 0x30;
        txmessage[len++] = 0x0e;

        txmessage[len++] = 0x02;
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x02; // msgID

        txmessage[len++] = 0x02; //
        txmessage[len++] = 0x03; //
        txmessage[len++] = 0x00; // Max message size (less than 64K)
        txmessage[len++] = 0xff; //
        txmessage[len++] = 0xe3; //

        txmessage[len++] = 0x04;
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x04; // flags (reportable, not encrypted, not authenticated)

        txmessage[len++] = 0x02;
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x03; // msgSecurityModel is USM (3)

        // end of GlobalData
        txmessage[len++] = 0x04;
        txmessage[len++] = 0x10; //

        txmessage[len++] = 0x30; //
        txmessage[len++] = 0x0e; // length to end of this varbind

        txmessage[len++] = 0x04; //
        txmessage[len++] = 0x00; // EngineID

        txmessage[len++] = 0x02;
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x00; // EngineBoots

        txmessage[len++] = 0x02;
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x00; // EngineTime

        txmessage[len++] = 0x04; // UserName
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x04; // Authentication Parameters
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x04; // Privacy Parameters
        txmessage[len++] = 0x00;

        // msgData
        txmessage[len++] = 0x30; //
        txmessage[len++] = 0x11; //

        txmessage[len++] = 0x04; //  Context Engine ID (missing)
        txmessage[len++] = 0x00; //

        txmessage[len++] = 0x04; //  Context Name (missing)
        txmessage[len++] = 0x00; //

        txmessage[len++] = 0xa0; //  Get Request
        txmessage[len++] = 0x0b; //

        txmessage[len++] = 0x02; // Request ID (is 0x14)
        txmessage[len++] = 0x01; //
        txmessage[len++] = 0x14; //

        // Error status (0=noError)
        txmessage[len++] = 0x02; //int
        txmessage[len++] = 0x01; //length of 1
        txmessage[len++] = 0x00; // SNMP error status
        // Error index (0)
        txmessage[len++] = 0x02; //int
        txmessage[len++] = 0x01; //length of 1
        txmessage[len++] = 0x00; // SNMP error index
        // Variable bindings (none)
        txmessage[len++] = 0x30; //var-bind sequence
        txmessage[len++] = 0x00;

        break;
    }

    // IKEv2
    case 500:
    case 4500:
    {
        // ISAKMP
        len = 0;
        // Initiator cookie (8 bytes)
        txmessage[len++] = 0xde;
        txmessage[len++] = 0xad;
        txmessage[len++] = 0xfa;
        txmessage[len++] = 0xce;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 1;
        // Responder cookie (8 bytes)
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        // Next payload 0=None, 2=proposal, 4=key exchange, 33=SA
        txmessage[len++] = 33;
        // Version Major/Minor 2.0
        txmessage[len++] = 32;
        // Exchange type 4=aggressive, 34=IKE_SA_INIT
        txmessage[len++] = 34;
        // Flags 8=initiator
        txmessage[len++] = 8;

        // Message ID (4 bytes)
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        // Length (4 bytes)
        txmessage[len++] = 0;
        txmessage[len++] = 0;
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x2c; // includes key exchange payload

        // SA=33
        // Next payload 0=None, 2=proposal, 4=key exchange, 33=SA, 34=KeyEx
        txmessage[len++] = 34;
        txmessage[len++] = 0; // Not critical
        txmessage[len++] = 0; // Length 44
        txmessage[len++] = 44;

        txmessage[len++] = 0x00; // No next payload
        txmessage[len++] = 0x00; // Not critical
        txmessage[len++] = 0x00; // Length 40
        txmessage[len++] = 0x28;
        txmessage[len++] = 0x01; // Proposal 1
        txmessage[len++] = 0x01; // IKE
        txmessage[len++] = 0x00; // SPI size 0
        txmessage[len++] = 0x04; // Number of transforms
        txmessage[len++] = 0x03; // Payload type is transform
        txmessage[len++] = 0x00; // Not critical
        txmessage[len++] = 0x00; // Length 8
        txmessage[len++] = 0x08;
        txmessage[len++] = 0x01; // ENCRYPTION Algorithm
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // 3=3DES
        txmessage[len++] = 0x03;
        txmessage[len++] = 0x03; // Payload type is transform
        txmessage[len++] = 0x00; // Not critical
        txmessage[len++] = 0x00; // Length 8
        txmessage[len++] = 0x08;
        txmessage[len++] = 0x03; // INTEGRITY Algorithm
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // 2=AUTH_HMAC_SHA1_96
        txmessage[len++] = 0x02;
        txmessage[len++] = 0x03; // Payload type is transform
        txmessage[len++] = 0x00; // Not critical
        txmessage[len++] = 0x00; // Length 8
        txmessage[len++] = 0x08;
        txmessage[len++] = 0x02; // PRF Algorithm
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // 2=PRF_HMAC_SHA1
        txmessage[len++] = 0x02;
        txmessage[len++] = 0x00; // Next Payload type is NONE
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // Length 8
        txmessage[len++] = 0x08;
        txmessage[len++] = 0x04; // 4=Diffie-Hellman Group
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // 1024-bit MODP group
        txmessage[len++] = 0x02;

        txmessage[len++] = 0x28; // Next Payload type is None (40)
        txmessage[len++] = 0x00; // Not critical
        txmessage[len++] = 0x00; // Length 136
        txmessage[len++] = 0x88;
        txmessage[len++] = 0x00; // DH group 1024-bit MODP (2)
        txmessage[len++] = 0x02;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x2d; // Key Exchange data (128 octets)
        txmessage[len++] = 0x54;
        txmessage[len++] = 0x91;
        txmessage[len++] = 0xfa;
        txmessage[len++] = 0x0c;
        txmessage[len++] = 0xd4;
        txmessage[len++] = 0xd4;
        txmessage[len++] = 0xcc;
        txmessage[len++] = 0x77;
        txmessage[len++] = 0xf8;
        txmessage[len++] = 0xce;
        txmessage[len++] = 0x08;
        txmessage[len++] = 0x98;
        txmessage[len++] = 0x45;
        txmessage[len++] = 0x40;
        txmessage[len++] = 0xb7;
        txmessage[len++] = 0xc6;
        txmessage[len++] = 0x8c;
        txmessage[len++] = 0x08;
        txmessage[len++] = 0x93;
        txmessage[len++] = 0x2c;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0xf7;
        txmessage[len++] = 0xc1;
        txmessage[len++] = 0x5b;
        txmessage[len++] = 0xf1;
        txmessage[len++] = 0x04;
        txmessage[len++] = 0xb0;
        txmessage[len++] = 0x94;
        txmessage[len++] = 0x02;
        txmessage[len++] = 0x1a;
        txmessage[len++] = 0xf9;
        txmessage[len++] = 0x95;
        txmessage[len++] = 0x29;
        txmessage[len++] = 0x6c;
        txmessage[len++] = 0x4a;
        txmessage[len++] = 0x26;
        txmessage[len++] = 0x12;
        txmessage[len++] = 0x18;
        txmessage[len++] = 0x75;
        txmessage[len++] = 0x21;
        txmessage[len++] = 0x0e;
        txmessage[len++] = 0x02;
        txmessage[len++] = 0x06;
        txmessage[len++] = 0x11;
        txmessage[len++] = 0x49;
        txmessage[len++] = 0xc1;
        txmessage[len++] = 0xa0;
        txmessage[len++] = 0xc5;
        txmessage[len++] = 0x82;
        txmessage[len++] = 0xe1;
        txmessage[len++] = 0x11;
        txmessage[len++] = 0x30;
        txmessage[len++] = 0xab;
        txmessage[len++] = 0xc4;
        txmessage[len++] = 0x31;
        txmessage[len++] = 0xde;
        txmessage[len++] = 0x49;
        txmessage[len++] = 0x7d;
        txmessage[len++] = 0xd3;
        txmessage[len++] = 0xe6;
        txmessage[len++] = 0xfb;
        txmessage[len++] = 0x42;
        txmessage[len++] = 0x08;
        txmessage[len++] = 0xfd;
        txmessage[len++] = 0x72;
        txmessage[len++] = 0x74;
        txmessage[len++] = 0xbf;
        txmessage[len++] = 0x34;
        txmessage[len++] = 0x60;
        txmessage[len++] = 0xdc;
        txmessage[len++] = 0x98;
        txmessage[len++] = 0x97;
        txmessage[len++] = 0xd3;
        txmessage[len++] = 0xb5;
        txmessage[len++] = 0x5b;
        txmessage[len++] = 0x82;
        txmessage[len++] = 0xec;
        txmessage[len++] = 0x77;
        txmessage[len++] = 0x0d;
        txmessage[len++] = 0xae;
        txmessage[len++] = 0xca;
        txmessage[len++] = 0x39;
        txmessage[len++] = 0xfd;
        txmessage[len++] = 0x9a;
        txmessage[len++] = 0x08;
        txmessage[len++] = 0x8f;
        txmessage[len++] = 0x5a;
        txmessage[len++] = 0x73;
        txmessage[len++] = 0xa1;
        txmessage[len++] = 0xfd;
        txmessage[len++] = 0x60;
        txmessage[len++] = 0x98;
        txmessage[len++] = 0xa8;
        txmessage[len++] = 0xc8;
        txmessage[len++] = 0xdf;
        txmessage[len++] = 0x16;
        txmessage[len++] = 0x3d;
        txmessage[len++] = 0x55;
        txmessage[len++] = 0xff;
        txmessage[len++] = 0x6d;
        txmessage[len++] = 0xe0;
        txmessage[len++] = 0x94;
        txmessage[len++] = 0xd7;
        txmessage[len++] = 0x93;
        txmessage[len++] = 0xa6;
        txmessage[len++] = 0x82;
        txmessage[len++] = 0x1f;
        txmessage[len++] = 0xce;
        txmessage[len++] = 0x07;
        txmessage[len++] = 0x0a;
        txmessage[len++] = 0x17;
        txmessage[len++] = 0xf4;
        txmessage[len++] = 0x87;
        txmessage[len++] = 0x0b;
        txmessage[len++] = 0xc7;
        txmessage[len++] = 0x90;
        txmessage[len++] = 0xa2;
        txmessage[len++] = 0x47;
        txmessage[len++] = 0x51;
        txmessage[len++] = 0xca;
        txmessage[len++] = 0x2c;
        txmessage[len++] = 0xe8;
        txmessage[len++] = 0x33;
        txmessage[len++] = 0x3a;
        txmessage[len++] = 0x4d;
        txmessage[len++] = 0x5f;
        txmessage[len++] = 0xae;

        // Payload is Nonce
        txmessage[len++] = 0x29; // Next payload is Notify (41)
        txmessage[len++] = 0x00; // Not critical
        txmessage[len++] = 0x00; // Length 36
        txmessage[len++] = 0x24; // Nonce data
        txmessage[len++] = 0xfb;
        txmessage[len++] = 0xe5;
        txmessage[len++] = 0x90;
        txmessage[len++] = 0x3f;
        txmessage[len++] = 0xc9;
        txmessage[len++] = 0xdf;
        txmessage[len++] = 0x47;
        txmessage[len++] = 0x09;
        txmessage[len++] = 0xe5;
        txmessage[len++] = 0xd4;
        txmessage[len++] = 0xab;
        txmessage[len++] = 0x0a;
        txmessage[len++] = 0xa6;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0xb3;
        txmessage[len++] = 0xbe;
        txmessage[len++] = 0x36;
        txmessage[len++] = 0xeb;
        txmessage[len++] = 0x35;
        txmessage[len++] = 0xa6;
        txmessage[len++] = 0xf5;
        txmessage[len++] = 0x54;
        txmessage[len++] = 0x47;
        txmessage[len++] = 0xfe;
        txmessage[len++] = 0xda;
        txmessage[len++] = 0xb9;
        txmessage[len++] = 0x0d;
        txmessage[len++] = 0x67;
        txmessage[len++] = 0x66;
        txmessage[len++] = 0x9f;
        txmessage[len++] = 0xab;
        txmessage[len++] = 0x96;

        // Payload is Notify
        txmessage[len++] = 0x29; // Next payload is also notify
        txmessage[len++] = 0x00; // Not critical
        txmessage[len++] = 0x00; // Length 28
        txmessage[len++] = 0x1c;
        txmessage[len++] = 0x00; // Protocol ID is RESERVED (0)
        txmessage[len++] = 0x00; // SPI size is 0
        txmessage[len++] = 0x40; // NAT_DETECTION_SOURCE_IP (16388)
        txmessage[len++] = 0x04;
        // data is SHA1(SPIs, source IP address, source port)
        // however, we're just looking for a response, not a valid
        // packet
        txmessage[len++] = 0xc6; // Notification data
        txmessage[len++] = 0x93;
        txmessage[len++] = 0x14;
        txmessage[len++] = 0x61;
        txmessage[len++] = 0x31;
        txmessage[len++] = 0xa7;
        txmessage[len++] = 0x7f;
        txmessage[len++] = 0xe9;
        txmessage[len++] = 0x93;
        txmessage[len++] = 0x47;
        txmessage[len++] = 0x26;
        txmessage[len++] = 0xe5;
        txmessage[len++] = 0x23;
        txmessage[len++] = 0x17;
        txmessage[len++] = 0xd4;
        txmessage[len++] = 0xec;
        txmessage[len++] = 0x5f;
        txmessage[len++] = 0x64;
        txmessage[len++] = 0x45;
        txmessage[len++] = 0xf1;

        // Payload is Notify
        txmessage[len++] = 0x00; // Next payload is NONE
        txmessage[len++] = 0x00; // Not critical
        txmessage[len++] = 0x00; // :ength 28
        txmessage[len++] = 0x1c;
        txmessage[len++] = 0x00; // Protocol ID is RESERVED(0)
        txmessage[len++] = 0x00; // SPI size = 0
        txmessage[len++] = 0x40; // NAT_DETECTION_DESTIANTION_IP (16389)
        txmessage[len++] = 0x05;
        // data is SHA1(SPIs, source IP address, source port)
        // however, we're just looking for a response, not a valid
        // packet
        txmessage[len++] = 0xf9; // Notification data
        txmessage[len++] = 0x33;
        txmessage[len++] = 0xa1;
        txmessage[len++] = 0x9a;
        txmessage[len++] = 0x65;
        txmessage[len++] = 0x1a;
        txmessage[len++] = 0xc3;
        txmessage[len++] = 0x73;
        txmessage[len++] = 0x8b;
        txmessage[len++] = 0xb7;
        txmessage[len++] = 0xf6;
        txmessage[len++] = 0x04;
        txmessage[len++] = 0x43;
        txmessage[len++] = 0x6f;
        txmessage[len++] = 0x80;
        txmessage[len++] = 0x12;
        txmessage[len++] = 0x69;
        txmessage[len++] = 0x3e;
        txmessage[len++] = 0x6a;
        txmessage[len++] = 0x2a;

        break;
    }

    // RIPng
    case 521:
    {
        len = 0;
        txmessage[len++] = 0x01; // Command is REQUEST
        txmessage[len++] = 0x01; // Version 1
        txmessage[len++] = 0x00; // Reserved
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // ::
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // Route Tag
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // Prefix length
        txmessage[len++] = 0x10; // Metric
        break;
    }

    case 547:
    {
        len = 0;
        txmessage[len++] = 0x01; // msg-type = 0x01 (Solicit)
        txmessage[len++] = 0xde; // transaction-id
        txmessage[len++] = 0xad;
        txmessage[len++] = 0xfa;

        txmessage[len++] = 0x00; // Option 1 is Client Identifier
        txmessage[len++] = 0x01;

        txmessage[len++] = 0x00; // Length field
        txmessage[len++] = 0x0e;

        txmessage[len++] = 0x00; // DUID-LLT
        txmessage[len++] = 0x01;

        txmessage[len++] = 0x00; // Hardware type: Ethernet
        txmessage[len++] = 0x01;

        txmessage[len++] = 0x00; // Time
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x01;

        // Copy in the local MAC address as the Link-layer address
        for (i = 0; i < 6 ; i++) txmessage[len++] = localmacaddr[i];

        txmessage[len++] = 0x00; // Reconfigure Accept option
        txmessage[len++] = 0x14;

        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x00; // Identity Association for Non-temporary Address (IA_NA) option
        txmessage[len++] = 0x03;

        txmessage[len++] = 0x00; // Length (options length = 0)
        txmessage[len++] = 0x0c;

        txmessage[len++] = 0x00; // IAID
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x00; // T1
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x00; // T2
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x00; // Elapsed Time Option
        txmessage[len++] = 0x08;

        txmessage[len++] = 0x00; // Length
        txmessage[len++] = 0x02;

        txmessage[len++] = 0x00; // We just started ..
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x00; // Option Request Option Option
        txmessage[len++] = 0x06;

        txmessage[len++] = 0x00; // Option length
        txmessage[len++] = 0x04;

        txmessage[len++] = 0x00; // Recursive DNS server
        txmessage[len++] = 0x17;

        txmessage[len++] = 0x00; // Domain Search List
        txmessage[len++] = 0x18;

        txmessage[len++] = 0x00; // IA_PD Option
        txmessage[len++] = 0x19;

        txmessage[len++] = 0x00; // Length
        txmessage[len++] = 0x29;

        txmessage[len++] = 0x00; // IAID
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x00; // T1
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x00; // T2
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x00; // IA Prefix option
        txmessage[len++] = 0x1a;

        txmessage[len++] = 0x00; // Length (no additional options)
        txmessage[len++] = 0x19;

        txmessage[len++] = 0x00; // Preferred lifetime - 21600 seconds (6 hours)
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x54;
        txmessage[len++] = 0x60;

        txmessage[len++] = 0x00; // Valid lifetime - 86400 seconds (24 hours)
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x51;
        txmessage[len++] = 0x80;

        txmessage[len++] = 0x40; // 64-bit prefix length

        txmessage[len++] = 0x00; // Prefix ::
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00;
        break;
    }

    case 1900:
    {
        len = snprintf(&txmessage[0], UDP_BUFFER_SIZE,
                "M-SEARCH * HTTP/1.1\r\n"
                "Host:[%s]:1900\r\n"
                "Man: \"ssdp:discover\"\r\n"
                "MX:1\r\nST: \"ssdp:all\"\r\n"
                "USER-AGENT: linux/2.6 UPnP/1.1 TimsTester/1.0\r\n\r\n",
                ip);
        if (len < 0 || len >= UDP_BUFFER_SIZE) return -1;
        break;
    }

    case 11211: // memcache
    {
        txmessage[len++] = 0x00; // Request ID
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x00; // Sequence ID
        txmessage[len++] = 0x00;
        txmessage[len++] = 0x00; // Number of datagrams
        txmessage[len++] = 0x01;
        txmessage[len++] = 0x00; // Reserved for future use
        txmessage[len++] = 0x00;

        txmessage[len++] = 0x80; //	request
        txmessage[len++] = 0x0b; //	opcode - Version
        txmessage[len++] = 0; //	keylength
        txmessage[len++] = 0; //	keylength
        txmessage[len++] = 0; //	extras length -must be 0, else "multipart not supported"
        txmessage[len++] = 1; //	data type    - must be 1, else "multipart not supported"
        txmessage[len++] = 0; //	reserved
        txmessage[len++] = 0; //	reserved
        txmessage[len++] = 0; //	total body length
        txmessage[len++] = 0; //	total body length
        txmessage[len++] = 0; //	total body length
        txmessage[len++] = 0; //	total body length
        txmessage[len++] = 0x21; //	opaque
        txmessage[len++] = 0x03; //	opaque
        txmessage[len++] = 0x14; //	opaque
        txmessage[len++] = 0x08; //	opaque
        txmessage[len++] = 0; //	cas
        txmessage[len++] = 0; //	cas
        txmessage[len++] = 0; //	cas
        txmessage[len++] = 0; //	cas
        txmessage[len++] = 0; //	cas
        txmessage[len++] = 0; //	cas
        txmessage[len++] = 0; //	cas
        txmessage[len++] = 0; //	cas

        break;
    }

    default:
    {
        len = 0;
        // Generate an unspecified message
        txmessage[len++] = 0x0A;
        txmessage[len++] = 0x0A;
        txmessage[len++] = 0x0D;
        txmessage[len++] = 0x0;
        ret = snprintf(&txmessage[len], (size_t)(UDP_BUFFER_SIZE-len),
                       "IPscan (c) 2011-2019 Tim Chappell. "
                       "This message is destined for UDP port %d\n", port);
        if (ret < 0 || ret >= (UDP_BUFFER_SIZE-len)) return -1;

        break;
    }
    }

    ret = write(fd, &txmessage, (size_t)len);
    if (ret < 0) return -3;

    ret = read(fd, &rxmessage, UDP_BUFFER_SIZE);
    if (ret < 0) return -4;

    close(fd);
    return ret;
#endif
}
