#ifndef HOSTPORTSCANNER_H
#define HOSTPORTSCANNER_H

#ifdef __cplusplus
extern "C"{
#endif

int network_port_scan_tcp(const char *ip, const short port, int timeout_ms);

int network_port_scan_udp(const char *ip, const short port, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif // HOSTPORTSCANNER_H
