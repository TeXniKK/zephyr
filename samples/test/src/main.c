/*
 * main.c
 *
 *  Created on: Oct 17, 2021
 *      Author: pavelgamov
 */


#include <zephyr.h>
#include <sys/printk.h>
#include <time.h>
#include <net/socket.h>
#include <net/net_ip.h>
#include <net/mqtt.h>
#include <net/socket.h>
#include <net/http_client.h>
#include <stdio.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

#define SERVER_ADDR "https://qadevices.com:9765/"

static const unsigned char ca_certificate[] = {
    #include "certs/ca.der.hex"
};
static const unsigned char public_key[] = {
    #include "certs/publicKey.der.hex"
};
static const unsigned char private_key[] = {
    #include "certs/privateKey.der.hex"
};
#define APP_CA_CERT_TAG 2

static bool dhcpAcquired = false;

static int tlsInit(void) {
    int rv = tls_credential_add(APP_CA_CERT_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, ca_certificate, sizeof(ca_certificate));
    if (rv < 0) {
        LOG_ERR("Failed to register public certificate: %d", rv);
        return rv;
    }

    rv = tls_credential_add(APP_CA_CERT_TAG, TLS_CREDENTIAL_SERVER_CERTIFICATE, public_key, sizeof(public_key));
    if (rv < 0) {
        LOG_ERR("Failed to register public key: %d", rv);
        return rv;
    }

    rv = tls_credential_add(APP_CA_CERT_TAG, TLS_CREDENTIAL_PRIVATE_KEY, private_key, sizeof(private_key));
    if (rv < 0) {
        LOG_ERR("Failed to register private key: %d", rv);
        return rv;
    }

    return rv;
}

static int setup_socket(int family, const char *name, const char *srvAdr, int port, int *sock, struct sockaddr *addr, int addr_len) {
    int ret = 0;

    memset(addr, 0, addr_len);

    if (family == AF_INET) {
        net_sin(addr)->sin_family = AF_INET;
        net_sin(addr)->sin_port = htons(port);
        inet_pton(family, srvAdr, &net_sin(addr)->sin_addr);
    } else {
        net_sin6(addr)->sin6_family = AF_INET6;
        net_sin6(addr)->sin6_port = htons(port);
        inet_pton(family, srvAdr, &net_sin6(addr)->sin6_addr);
    }

    if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS)) {
        sec_tag_t sec_tag_list[] = {
                APP_CA_CERT_TAG,
        };

        *sock = socket(family, SOCK_STREAM, IPPROTO_TLS_1_2);
        if (*sock >= 0) {
            do {
                int peer_verify = TLS_PEER_VERIFY_REQUIRED;
                ret = setsockopt(*sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify, sizeof(peer_verify));
                if (ret < 0) {
                    LOG_ERR("Failed to set TLS_PEER_VERIFY (%d)", -errno);
                    ret = -errno;
                    break;
                }

                ret = setsockopt(*sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
                if (ret < 0) {
                    LOG_ERR("Failed to set TLS_SEC_TAG_LIST (%d)", -errno);
                    ret = -errno;
                    break;
                }

                ret = setsockopt(*sock, SOL_TLS, TLS_HOSTNAME, name, strlen(name));
                if (ret < 0) {
                    LOG_ERR("Failed to set TLS_HOSTNAME option (%d)", -errno);
                    ret = -errno;
                    break;
                }
            } while (0);
            if (ret) {
                close(*sock);
                *sock = -1;
            }
        }
    } else {
        *sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    }

    if (*sock < 0) {
        LOG_ERR("Failed to create HTTP socket (%d)", -errno);
    }

    return ret;
}

static int connect_socket(int family, const char *name, const char *server, int port, int *sock, struct sockaddr *addr, int addr_len) {
    int ret = setup_socket(family, name, server, port, sock, addr, addr_len);
    if (ret < 0 || *sock < 0) {
        return -1;
    }
    ret = connect(*sock, addr, addr_len);
    if (ret < 0) {
        LOG_ERR("Cannot connect to %s remote (%d) %s %s", family == AF_INET ? "IPv4" : "IPv6", -errno, log_strdup(name), log_strdup(server));
        ret = -errno;
        close(*sock);
        *sock = -1;
    }

    return ret;
}

static int getAddrinfo(struct zsock_addrinfo **haddr, const char *srv, int sPort) {
    struct zsock_addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = 0,
    };
    char port[6] = {0};
    snprintf(port, sizeof(port), "%u", sPort);

    int rc = -EINVAL;
    int retries = 5;
    while (retries--) {
        rc = zsock_getaddrinfo(srv, port, &hints, haddr);
        if (!rc)
            return 0;
        k_sleep(K_SECONDS(1));
    }
    return rc;
}

static void response_cb(struct http_response *rsp, enum http_final_call final_data, void *user_data) {
    if (final_data == HTTP_DATA_MORE) {
        LOG_INF("Partial data received (%zd bytes)", rsp->data_len);
    } else if (final_data == HTTP_DATA_FINAL) {
        LOG_INF("All the data received (%zd bytes)", rsp->data_len);
    }
    LOG_INF("Response status %s", log_strdup(rsp->http_status));
}


static int rqFeed(const char *path, time_t *timestamp, char *out, size_t outSize) {
    const char *http = strstr(path, "http://");
    const char *https = strstr(path, "https://");
    const char *sSrv = path + (7 + !!https);
    const char *sPort = strchr(sSrv, ':');
    const char *feed = strchr(sSrv, '/');

    if (!feed || (!http && !https)) {
        LOG_ERR("malformed rq %s", log_strdup(path));
        return -EINVAL;
    }

    char srv[257] = { 0 };
    char portStr[17] = { 0 };
    int port = https ? 443 : 80;
    if (sPort && sPort < feed) {
        memcpy(portStr, sPort + 1, feed - sPort);
        char *end;
        port = strtol(portStr, &end, 0);
        if (end == portStr) {
            LOG_ERR("Invalid port %s", log_strdup(portStr));
            return -EINVAL;
        }
        memcpy(srv, sSrv, sPort - sSrv);
    } else {
        memcpy(srv, sSrv, feed - sSrv);
        snprintf(portStr, sizeof(portStr), "%u", port);
    }

    LOG_INF("%s %s %d %s", https ? "sec" : "open", log_strdup(srv), port, log_strdup(feed));

    struct zsock_addrinfo *haddr = NULL;
    int rc = getAddrinfo(&haddr, srv, port);
    if (rc) {
        LOG_INF("Hostname is not resolved %s:%d, %d", log_strdup(srv), port, rc);
        return rc;
    }

    char addr[17] = { 0 };
    snprintf(addr, sizeof(addr), "%u.%u.%u.%u",
                    net_sin((haddr)->ai_addr)->sin_addr.s4_addr[0],
                    net_sin((haddr)->ai_addr)->sin_addr.s4_addr[1],
                    net_sin((haddr)->ai_addr)->sin_addr.s4_addr[2],
                    net_sin((haddr)->ai_addr)->sin_addr.s4_addr[3]);
    zsock_freeaddrinfo(haddr);

    struct sockaddr_in addr4;
    int sock4 = -1;
    rc = connect_socket(AF_INET, srv, addr, port, &sock4, (struct sockaddr *)&addr4, sizeof(addr4));
    if (rc)
        return rc;

    uint8_t recv_buf_ipv4[512] = {0};
    struct http_request req = {0};
    req.method = HTTP_GET;
    req.url = feed;
    req.content_type_value = "application/json; charset=utf-8";
    req.host = srv;
    req.port = portStr;
    req.protocol = "HTTP/1.1";
    req.response = response_cb;
    req.recv_buf = recv_buf_ipv4;
    req.recv_buf_len = sizeof(recv_buf_ipv4);

    LOG_DBG("inited");

    rc = http_client_req(sock4, &req, 13 * MSEC_PER_SEC, "IPv4 GET");
    close(sock4);
    if (rc < 0) {
        LOG_ERR("No answer form OTA %d", rc);
        return rc;
    }

    return 0;
}

#ifdef CONFIG_NET_L2_ETHERNET
#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_context.h>
#include <net/net_mgmt.h>
static struct net_mgmt_event_callback dhcp_cb;
static void handler_cb(struct net_mgmt_event_callback *cb, uint32_t mgmt_event, struct net_if *iface) {
    if (mgmt_event != NET_EVENT_IPV4_DHCP_BOUND) {
        return;
    }

    char buf[NET_IPV4_ADDR_LEN];
    LOG_INF("Your address: %s", log_strdup(net_addr_ntop(AF_INET, &iface->config.dhcpv4.requested_ip, buf, sizeof(buf))));
    LOG_INF("Lease time: %u seconds", iface->config.dhcpv4.lease_time);
    LOG_INF("Subnet: %s", log_strdup(net_addr_ntop(AF_INET, &iface->config.ip.ipv4->netmask, buf, sizeof(buf))));
    LOG_INF("Router: %s", log_strdup(net_addr_ntop(AF_INET, &iface->config.ip.ipv4->gw, buf, sizeof(buf))));

    dhcpAcquired = true;
}
#endif

void main() {

#ifdef CONFIG_NET_L2_ETHERNET
    net_mgmt_init_event_callback(&dhcp_cb, handler_cb, NET_EVENT_IPV4_DHCP_BOUND);
    net_mgmt_add_event_callback(&dhcp_cb);

    struct net_if *iface = net_if_get_default();
    if (iface) {
        net_dhcpv4_start(iface);
    } else
        LOG_ERR("wifi interface not available");
#endif

    int rv = tlsInit();
    if (rv) {
        LOG_ERR("TLS err");
        return;
    }
    while (1) {
        k_sleep(K_MSEC(100));
        if (!dhcpAcquired)
            continue;

        static const char *feed = SERVER_ADDR;
        char buf[384];
        time_t ts;
        rv = rqFeed(feed, &ts, buf, sizeof(buf));
        if (rv) {
            LOG_ERR("reqest problem");
        } else {
            LOG_INF("request ok");
        }
    }
}
