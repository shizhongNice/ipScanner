#ifndef NETWORKPING_H
#define NETWORKPING_H

#ifdef __cplusplus
extern "C"{
#endif

int network_ping(const char *ip, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif // NETWORKPING_H
