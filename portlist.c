#include "portlist.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "ping.h"
#include "scanner.h"

static const PortInfo tcpportlist[] =
{
    {   1 , 0, "tcpmux"          }, //TCP 端口服务多路复用
    {   5 , 0, "rje"             }, //远程作业入口
    {   7 , 0, "echo"            }, //Echo 服务
    {   9 , 0, "discard"         }, //用于连接测试的空服务
    {   11, 0, "systat"          }, //用于列举连接了的端口的系统状态
    {   13, 0, "daytime"         }, //给请求主机发送日期和时间
    {   17, 0, "qotd"            }, //给连接了的主机发送每日格言
    {   18, 0, "msp"             }, //消息发送协议
    {   19, 0, "chargen"         }, //字符生成服务；发送无止境的字符流
    {   20, 0, "ftp-data"        }, //FTP 数据端口
    {   21, 0, "ftp"             }, //文件传输协议（FTP）端口；有时被文件服务协议（FSP）使用
    {   22, 0, "ssh"             }, //安全 Shell（SSH）服务
    {   23, 0, "telnet"          }, //Telnet 服务
    {   25, 0, "smtp"            }, //简单邮件传输协议（SMTP）
    {   37, 0, "time"            }, //时间协议
    {   39, 0, "rlp"             }, //资源定位协议
    {   42, 0, "nameserver"      }, //互联网名称服务
    {   43, 0, "nicname"         }, //WHOIS 目录服务
    {   49, 0, "tacacs"          }, //用于基于 TCP/IP 验证和访问的终端访问控制器访问控制系统
    {   50, 0, "re-mail-ck"      }, //远程邮件检查协议
    {   53, 0, "DNS"             }, //域名服务（如 BIND）
    {   63, 0, "whois++"         }, //WHOIS++，被扩展了的 WHOIS 服务
    {   67, 0, "bootps"          }, //引导协议（BOOTP）服务；还被动态主机配置协议（DHCP）服务使用
    {   68, 0, "bootpc"          }, //Bootstrap（BOOTP）客户；还被动态主机配置协议（DHCP）客户使用
    {   69, 0, "tftp"            }, //小文件传输协议（TFTP）
    {   70, 0, "gopher"          }, //Gopher 互联网文档搜寻和检索
    {   71, 0, "netrjs-1"        }, //远程作业服务
    {   72, 0, "netrjs-2"        }, //远程作业服务
    {   73, 0, "netrjs-3"        }, //远程作业服务
    {   73, 0, "netrjs-4"        }, //远程作业服务
    {   79, 0, "finger"          }, //用于用户联系信息的 Finger 服务
    {   80, 0, "http"            }, //用于万维网（WWW）服务的超文本传输协议（HTTP）
    {   88, 0, "kerberos"        }, //Kerberos 网络验证系统
    {   95, 0, "supdup"          }, //Telnet 协议扩展
    {  101, 0, "hostname"        }, //SRI-NIC 机器上的主机名服务
    {  102, 0, "iso-tsap"        }, //ISO 开发环境（ISODE）网络应用
    {  105, 0, "csnet-ns"        }, //邮箱名称服务器；也被 CSO 名称服务器使用
    {  107, 0, "rtelnet"         }, //远程 Telnet
    {  109, 0, "pop2"            }, //邮局协议版本2
    {  110, 0, "pop3"            }, //邮局协议版本3
    {  111, 0, "sunrpc"          }, //用于远程命令执行的远程过程调用（RPC）协议，被网络文件系统（NFS）使用
    {  113, 0, "auth"            }, //验证和身份识别协议
    {  115, 0, "sftp"            }, //安全文件传输协议（SFTP）服务
    {  117, 0, "uucp-path"       }, //Unix 到 Unix 复制协议（UUCP）路径服务
    {  119, 0, "nntp"            }, //用于 USENET 讨论系统的网络新闻传输协议（NNTP）
    {  123, 0, "ntp"             }, //网络时间协议（NTP）
    {  137, 0, "netbios-ns"      }, //在红帽企业 Linux 中被 Samba 使用的 NETBIOS 名称服务
    {  138, 0, "netbios-dgm"     }, //在红帽企业 Linux 中被 Samba 使用的 NETBIOS 数据报服务
    {  139, 0, "netbios-ssn"     }, //在红帽企业 Linux 中被 Samba 使用的NET BIOS 会话服务
    {  143, 0, "imap"            }, //互联网消息存取协议（IMAP）
    {  161, 0, "snmp"            }, //简单网络管理协议（SNMP）
    {  162, 0, "snmptrap"        }, //SNMP 的陷阱
    {  163, 0, "cmip-man"        }, //通用管理信息协议（CMIP）
    {  164, 0, "cmip-agent"      }, //通用管理信息协议（CMIP）
    {  174, 0, "mailq"           }, //MAILQ
    {  177, 0, "xdmcp"           }, //X 显示管理器控制协议
    {  178, 0, "nextstep"        }, //NeXTStep 窗口服务器
    {  179, 0, "bgp"             }, //边界网络协议
    {  191, 0, "prospero"        }, //Cliffod Neuman 的 Prospero 服务
    {  194, 0, "irc"             }, //互联网中继聊天（IRC）
    {  199, 0, "smux"            }, //SNMP UNIX 多路复用
    {  201, 0, "at-rtmp"         }, //AppleTalk 选路
    {  202, 0, "at-nbp"          }, //AppleTalk 名称绑定
    {  204, 0, "at-echo"         }, //AppleTalk echo 服务
    {  206, 0, "at-zis"          }, //AppleTalk 区块信息
    {  209, 0, "qmtp"            }, //快速邮件传输协议（QMTP）
    {  210, 0, "z39.50"          }, //NISO Z39.50 数据库
    {  213, 0, "ipx"             }, //互联网络分组交换协议（IPX），被 Novell Netware 环境常用的数据报协议
    {  220, 0, "imap3"           }, //互联网消息存取协议版本3
    {  245, 0, "link"            }, //LINK
    {  347, 0, "fatserv"         }, //Fatmen 服务器
    {  363, 0, "rsvp_tunnel"     }, //RSVP 隧道
    {  369, 0, "rpc2portmap"     }, //Coda 文件系统端口映射器
    {  370, 0, "codaauth2"       }, //Coda 文件系统验证服务
    {  372, 0, "ulistproc"       }, //UNIX Listserv
    {  389, 0, "ldap"            }, //轻型目录存取协议（LDAP）
    {  427, 0, "svrloc"          }, //服务位置协议（SLP）
    {  434, 0, "mobileip-agent"  }, //可移互联网协议（IP）代理
    {  435, 0, "mobilip-mn"      }, //可移互联网协议（IP）管理器
    {  443, 0, "https"           }, //安全超文本传输协议（HTTP）
    {  444, 0, "snpp"            }, //小型网络分页协议
    {  445, 0, "ms_samba"        },  //通过 TCP/IP 的服务器消息块（SMB）
    {  464, 0, "kpasswd"         }, //Kerberos 口令和钥匙改换服务
    {  468, 0, "photuris"        }, //Photuris 会话钥匙管理协议
    {  487, 0, "saft"            }, //简单不对称文件传输（SAFT）协议
    {  488, 0, "gss-http"        }, //用于 HTTP 的通用安全服务（GSS）
    {  496, 0, "pim-rp-disc"     }, //用于协议独立的多址传播（PIM）服务的会合点发现（RP-DISC）
    {  500, 0, "isakmp"          }, //互联网安全关联和钥匙管理协议（ISAKMP）
    {  535, 0, "iiop"            }, //互联网内部对象请求代理协议（IIOP）
    {  538, 0, "gdomap"          }, //GNUstep 分布式对象映射器（GDOMAP）
    {  546, 0, "dhcpv6-client"   }, //动态主机配置协议（DHCP）版本6客户
    {  547, 0, "dhcpv6-server"   }, //动态主机配置协议（DHCP）版本6服务
    {  554, 0, "rtsp"            }, //实时流播协议（RTSP）
    {  563, 0, "nntps"           }, //通过安全套接字层的网络新闻传输协议（NNTPS）
    {  565, 0, "whoami"          }, //whoami
    {  587, 0, "submission"      }, //邮件消息提交代理（MSA）
    {  610, 0, "npmp-local"      }, //网络外设管理协议（NPMP）本地 / 分布式排队系统（DQS）
    {  611, 0, "npmp-gui"        }, //网络外设管理协议（NPMP）GUI / 分布式排队系统（DQS）
    {  612, 0, "hmmp-ind"        }, //HMMP 指示 / DQS
    {  631, 0, "ipp"             }, //互联网打印协议（IPP）
    {  636, 0, "ldaps"           }, //通过安全套接字层的轻型目录访问协议（LDAPS）
    {  674, 0, "acap"            }, //应用程序配置存取协议（ACAP）
    {  694, 0, "ha-cluster"      }, //用于带有高可用性的群集的心跳服务
    {  749, 0, "kerberos-adm"    }, //Kerberos 版本5（v5）的“kadmin”数据库管理
    {  750, 0, "kerberos-iv"     }, //Kerberos 版本4（v4）服务
    {  765, 0, "webster"         }, //网络词典
    {  767, 0, "phonebook"       }, //网络电话簿
    {  873, 0, "rsync"           }, //rsync 文件传输服务
    {  992, 0, "telnets"         }, //通过安全套接字层的 Telnet（TelnetS）
    {  993, 0, "imaps"           }, //通过安全套接字层的互联网消息存取协议（IMAPS）
    {  994, 0, "ircs"            }, //通过安全套接字层的互联网中继聊天（IRCS）
    {  995, 0, "pop3s"           }, //通过安全套接字层的邮局协议版本3（POPS3）
    { 1025, 0, "Blackjack, NFS, IIS or RFS"     },
    { 1026, 0, "CAP, Microsoft DCOM"            },
    { 1029, 0, "Microsoft DCOM"                 },
    { 1030, 0, "BBN IAD"                        },
    { 1080, 0, "Socks"                          },
    { 1433, 0, "SQLServer"                      },
    { 1720, 0, "H323, Microsoft Netmeeting"     },
    { 1723, 0, "PPTP"                           },
    { 1801, 0, "MSMQ"                           },
    { 2049, 0, "NFS"                            },
    { 2103, 0, "MSMQ-RPC"                       },
    { 2105, 0, "MSMQ-RPC"                       },
    { 2107, 0, "MSMQ-Mgmt"                      },
    { 2869, 0, "SSDP Event Notification"        },
    { 3128, 0, "Active API, or Squid Proxy"     },
    { 3260, 0, "iscsi"                          },
    { 3306, 0, "MySQL"                          },
    { 3389, 0, "Microsoft RDP"                  },
    { 3689, 0, "DAAP, iTunes"                   },
    { 5000, 0, "UPNP"                           },
    { 5060, 0, "SIP"                            },
    { 5100, 0, "Service Mux, Yahoo Messenger"   },
    { 5357, 0, "WSDAPI_HTTP"                    },
    { 5900, 0, "VNC"                            },
    { 8080, 0, "HTTP alternate"                 },
    { 9090, 0, "WebSM"                          },
    {10243, 0, "Microsoft WMP HTTP"             },
    {11211, 0, "memcache"                       },
    {16992, 0, "Intel AMT SOAP/HTTP"            },
    {16993, 0, "Intel AMT SOAP/HTTPS"           },
    {16994, 0, "Intel AMT Redir/TCP"            },
    {16995, 0, "Intel AMT Redir/TLS"            },
    {32764, 0, "Router Backdoor"                },
};

static const PortInfo udpportlist[] =
{
    {   53, 0, "DNS"                },
    {   67, 0, "DHCP_TX"            },
    {   68, 0, "DHCP_RX"            },
    {   69, 0, "TFTP"               },
    {  123, 0, "NTP"                },
//    {  161, 0, "SNMPv3"             },
//    {  500, 0, "IKEv2 SA_INIT"      },
//    {  521, 0, "RIPng"              },
    {  547, 0, "DHCPv6"             },
//    { 1900, 0, "UPnP SSDP"          },
//    { 3503, 0, "MPLS LSP Ping"      },
//    { 4500, 0, "IKEv2 NAT-T SA_INIT"},
//    {11211, 0, "memcache ASCII"     },

//    {512,  0, "biff"      },        //[comsat]	异步邮件客户（biff）和服务（comsat）
//    {513,  0, "who"       },        //[whod]	登录的用户列表
    {514,  0, "syslog"    },        //UNIX 系统日志服务
//    {517,  0, "talk"      },        //远程对话服务和客户
//    {518,  0, "ntalk"     },        //网络交谈（ntalk），远程对话服务和客户
//    {520,  0, "router"    },        //[route, routed]	选路信息协议（RIP）
//    {533,  0, "netwall"   },        //用于紧急广播的 Netwall
//    {2430, 0, "venus"     },        //用于 Coda 文件系统（callback/wbc interface 界面）的 Venus 缓存管理器
//    {2431, 0, "venus-se"  },        //Venus 用户数据报协议（UDP）的副作用
//    {2432, 0, "codasrv"   },        //Coda 文件系统服务器端口
//    {2433, 0, "codasrv-se"},        //Coda 文件系统 UDP SFTP 副作用

};


PortInfoList new_tcpportlist()
{
    PortInfoList lst = (PortInfoList)malloc( (sizeof(tcpportlist) ) );
    if(lst != NULL)
    {
        memcpy(lst, tcpportlist, sizeof(tcpportlist) );
    }
    return lst;
}

int get_tcpportlist_count()
{
    return (sizeof(tcpportlist)/sizeof(tcpportlist[0]));
}

void delete_tcpportlist(PortInfoList lst)
{
    if(lst != NULL)
    {
        free(lst);
        lst = NULL;
    }
}


PortInfoList new_udpportlist()
{
    PortInfoList lst = (PortInfoList)malloc( (sizeof(udpportlist) ) );
    if(lst != NULL)
    {
        memcpy(lst, udpportlist, sizeof(udpportlist) );
    }
    return lst;
}

int get_udpportlist_count()
{
    return (sizeof(udpportlist)/sizeof(udpportlist[0]));
}

void delete_udpportlist(PortInfoList lst)
{
    if(lst != NULL)
    {
        free(lst);
        lst = NULL;
    }
}

typedef struct _port_segment
{
    char		        ip[32];         // 目标IP
    int                 type;           // 扫描类型TCP UDP
    int                 timeout_ms;     // 扫描超时时间
    PortInfoList        lst;            // 要扫描的端口集合
    unsigned int        count;          // 端口集合长度
    unsigned short      min_index;      // 起始索引
    unsigned short      max_index;      // 最大索引
} port_segment;

// 执行扫描的线程，扫描某一区间的端口
static void *do_scan_port(void *arg)
{
    port_segment *segment = (port_segment *)arg;
    unsigned int	i;
    int ret;
    for (i=segment->min_index; i<=segment->max_index; i++)
    {
        if(segment->type == SCANNER_TCP)
        {
            ret = network_port_scan_tcp(segment->ip, segment->lst[i].port, segment->timeout_ms);
        }
        else if(segment->type == SCANNER_UDP)
        {
            ret = network_port_scan_udp(segment->ip, segment->lst[i].port, segment->timeout_ms);
        }
        else continue;

        if(ret == 0){
            segment->lst[i].isOpen = 1; //端口开放
        }
        else
        {
            segment->lst[i].isOpen = 0;
        }
    }
    return NULL;
}

int scanner_port(const char *ip, PortInfoList lst, int count, scan_type_e scantype, int timeout_ms)
{
    if(lst == NULL) return;
    const int default_thread_count = USING_THREAD_NUM;
    int		seg_len;

    int thread_num = count < default_thread_count ? count : default_thread_count;

    seg_len = count / thread_num;
    if ( (count%thread_num) != 0 ) {
        seg_len += 1;
    }

//    pthread_t    thread[USING_THREAD_NUM];
//    port_segment segment[USING_THREAD_NUM];

    pthread_t    *thread  = (pthread_t*)malloc( thread_num * sizeof(pthread_t) );
    port_segment *segment = (port_segment*)malloc( thread_num * sizeof(port_segment) );

    memset(thread, 0, thread_num*sizeof(pthread_t) );
    memset(segment, 0, thread_num*sizeof(port_segment) );

    int		i;
    for (i=0; i<thread_num; i++)
    {
        strcpy(segment[i].ip, ip);
        segment[i].type = scantype;
        segment[i].timeout_ms = timeout_ms;
        segment[i].lst = lst;
        segment[i].count = count;

        segment[i].min_index = i*seg_len;

        if (i == thread_num-1)
        {
            segment[i].max_index = count - 1; //最后一个线程
        }
        else
        {
            segment[i].max_index = segment[i].min_index + seg_len - 1;
        }

        pthread_create(&thread[i], NULL, do_scan_port, (void *)&segment[i]);
        usleep(1000);
    }

    for(i=0; i<thread_num; i++)
    {
        if( thread[i] != 0)
            pthread_join(thread[i], NULL); // 主线程等待子线程结束
    }
    usleep(1000);
//    free(thread);
//    free(segment);
    return 0;
}

void show_port_result(const char *tittle, PortInfoList lst, int count)
{
    if(lst == NULL) return;
    printf("%s", tittle);
    for(int i=0; i < count; i++)
    {
        if(lst[i].isOpen == 1)
        {
            printf("\t(%s)", lst[i].desc);
        }
    }
    printf("\n");
    fflush(stdout);
}




typedef struct _host_segment
{
    HostInfoList        lst;            // 要扫描的ip集合
    unsigned int        count;          // ip集合长度
    int                 timeout_ms;     // 扫描超时时间
    unsigned short      min_index;      // 起始索引
    unsigned short      max_index;      // 最大索引
} host_segment;

static void *do_scan_host(void *arg)
{
    host_segment *segment = (host_segment *)arg;
    unsigned int	i;
    int ret;
    for (i=segment->min_index; i<=segment->max_index; i++)
    {
        ret = network_ping(segment->lst[i].ip, segment->timeout_ms);
//        printf("network_ping %s, %d\n", segment->lst[i].ip, ret);
        if(ret == 0){
            segment->lst[i].isalive = 1;
        }
        else{
            segment->lst[i].isalive = 0;
        }
    }
    return NULL;
}

int scanner_host(HostInfoList lst, int count, int timeout_ms)
{
    if(lst == NULL) return;

    const int default_thread_count = USING_THREAD_NUM;
    int		seg_len;

    int thread_num = count < default_thread_count ? count : default_thread_count;

    seg_len = count / thread_num;
    if ( (count%thread_num) != 0 ) {
        seg_len += 1;
    }

    pthread_t    *thread  = (pthread_t*)malloc(thread_num*sizeof(pthread_t));
    host_segment *segment = (host_segment*)malloc(thread_num*sizeof(host_segment));
    memset(thread, 0, thread_num*sizeof(pthread_t));
    memset(segment, 0, thread_num*sizeof(host_segment));

    int		i;
    for (i=0; i<thread_num; i++)
    {
        segment[i].timeout_ms = timeout_ms;
        segment[i].lst = lst;
        segment[i].count = count;
        segment[i].min_index = i*seg_len;
        if (i == thread_num-1)
        {
            segment[i].max_index = count - 1; //最后一个线程
        }
        else
        {
            segment[i].max_index = segment[i].min_index + seg_len - 1;
        }
        pthread_create(&thread[i], NULL, do_scan_host, (void *)&segment[i]);
        usleep(1000);
    }

    for(i=0; i<thread_num; i++)
    {
        if( thread[i] != 0)
            pthread_join(thread[i], NULL); // 主线程等待子线程结束
    }

    usleep(1000);
    free(thread);
    free(segment);
    return 0;
}

void show_host_result(const char *tittle, HostInfoList lst, int count)
{
    if(lst == NULL) return;
    printf("=========== scanner %s begin =============\n", tittle);
    for(int i=0; i < count; i++)
    {
        if(lst[i].isalive == 1)
        {
            printf("%s %s\n", lst[i].ip, lst[i].desc);
        }
    }
    printf("=========== scanner %s end =============\n", tittle);
    fflush(stdout);
}
