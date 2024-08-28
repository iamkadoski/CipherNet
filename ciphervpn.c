//ciphernet
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <openssl/evp.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <poll.h>

#define PORT 54345
#define MTU 1400
#define BIND_HOST "0.0.0.0"
#define AES_KEYLEN 256
#define AES_BLOCK_SIZE 16
#define MAX_CLIENTS 100

static int max(int a, int b) {
    return a > b ? a : b;
}

void handle_error(const char *msg) {
    syslog(LOG_ERR, "%s: %s", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

int tun_alloc() {
    struct ifreq ifr;
    int fd, e;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        handle_error("Cannot open /dev/net/tun");
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if ((e = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        handle_error("ioctl[TUNSETIFF] failed");
        close(fd);
    }

    return fd;
}

static void run(char *cmd) {
    syslog(LOG_INFO, "Executing `%s`", cmd);
    if (system(cmd)) {
        handle_error(cmd);
    }
}

void ifconfig(int as_client) {
    char cmd[1024];

    if (as_client) {
        snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.2/16 mtu %d up", MTU);
    } else {
        snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.1/16 mtu %d up", MTU);
    }
    run(cmd);
}

void setup_route_table(int as_client, const char *server_host) {
    run("sysctl -w net.ipv4.ip_forward=1");

    if (as_client) {
        run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
        run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
        run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "ip route add %s via $(ip route show 0/0 | sed -e 's/.* via \\([^ ]*\\).*/\\1/')", server_host);
        run(cmd);
        run("ip route add 0/1 dev tun0");
        run("ip route add 128/1 dev tun0");
    } else {
        run("iptables -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
        run("iptables -A FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
        run("iptables -A FORWARD -d 10.8.0.0/16 -j ACCEPT");
    }
}

void cleanup_route_table(int as_client, const char *server_host) {
    if (as_client) {
        run("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE");
        run("iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
        run("iptables -D FORWARD -o tun0 -j ACCEPT");
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "ip route del %s", server_host);
        run(cmd);
        run("ip route del 0/1");
        run("ip route del 128/1");
    } else {
        run("iptables -t nat -D POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
        run("iptables -D FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
        run("iptables -D FORWARD -d 10.8.0.0/16 -j ACCEPT");
    }
}

int udp_bind(struct sockaddr *addr, socklen_t *addrlen, int as_client, const char *server_host) {
    struct addrinfo hints;
    struct addrinfo *result;
    int sock, flags;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    const char *host = as_client ? server_host : BIND_HOST;

    if (0 != getaddrinfo(host, NULL, &hints, &result)) {
        handle_error("getaddrinfo error");
    }

    if (result->ai_family == AF_INET)
        ((struct sockaddr_in *)result->ai_addr)->sin_port = htons(PORT);
    else if (result->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)result->ai_addr)->sin6_port = htons(PORT);
    else {
        syslog(LOG_ERR, "unknown ai_family %d", result->ai_family);
        freeaddrinfo(result);
        return -1;
    }
    memcpy(addr, result->ai_addr, result->ai_addrlen);
    *addrlen = result->ai_addrlen;

    if (-1 == (sock = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP))) {
        handle_error("Cannot create socket");
    }

    if (!as_client) {
        if (0 != bind(sock, result->ai_addr, result->ai_addrlen)) {
            handle_error("Cannot bind");
        }
    }

    freeaddrinfo(result);

    flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1) {
        if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK))
            return sock;
    }
    handle_error("fcntl error");

    close(sock);
    return -1;
}

// Function to encrypt or decrypt data using AES with EVP API
void aes_encrypt_decrypt(const unsigned char *input, unsigned char *output, int len, int enc, const unsigned char *aes_key) {
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char iv[AES_BLOCK_SIZE] = "initialvector123";

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handle_error("EVP_CIPHER_CTX_new failed");
    }

    // Initialize the encryption or decryption operation
    if(1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cfb128(), NULL, aes_key, iv, enc)) {
        handle_error("EVP_CipherInit_ex failed");
    }

    // Provide the message to be encrypted or decrypted, and obtain the output
    if(1 != EVP_CipherUpdate(ctx, output, &outlen, input, len)) {
        handle_error("EVP_CipherUpdate failed");
    }

    // Finalize the encryption or decryption
    if(1 != EVP_CipherFinal_ex(ctx, output + outlen, &tmplen)) {
        handle_error("EVP_CipherFinal_ex failed");
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void cleanup(int signo) {
    syslog(LOG_INFO, "Goodbye, cruel world....");
    if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
        exit(0);
    }
}

void cleanup_when_sig_exit() {
    struct sigaction sa;
    sa.sa_handler = &cleanup;
    sa.sa_flags = SA_RESTART;
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        handle_error("Cannot handle SIGHUP");
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        handle_error("Cannot handle SIGINT");
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        handle_error("Cannot handle SIGTERM");
    }
}

int main(int argc, char **argv) {
    openlog("vpn_demo", LOG_PID | LOG_CONS, LOG_USER);

    if (argc < 3) {
        syslog(LOG_ERR, "Usage: %s <SERVER|CLIENT> <AES_KEY> [SERVER_HOST]", argv[0]);
        exit(EXIT_FAILURE);
    }

    int as_client = 0;
    const char *server_host = NULL;
    unsigned char aes_key[AES_KEYLEN / 8];

    strncpy((char *)aes_key, argv[2], AES_KEYLEN / 8);

    if (strcmp(argv[1], "CLIENT") == 0) {
        if (argc != 4) {
            syslog(LOG_ERR, "Usage: %s CLIENT <AES_KEY> <SERVER_HOST>", argv[0]);
            exit(EXIT_FAILURE);
        }
        as_client = 1;
        server_host = argv[3];
    } else if (strcmp(argv[1], "SERVER") != 0) {
        syslog(LOG_ERR, "Invalid argument. Use 'SERVER' or 'CLIENT'.");
        exit(EXIT_FAILURE);
    }

    int tun_fd;
    if ((tun_fd = tun_alloc()) < 0) {
        return 1;
    }

    ifconfig(as_client);
    setup_route_table(as_client, server_host);
    cleanup_when_sig_exit();

    int udp_fd;
    struct sockaddr_storage client_addrs[MAX_CLIENTS];
    socklen_t client_addrlens[MAX_CLIENTS];
    struct pollfd pfds[MAX_CLIENTS + 1];
    int num_clients = 0;

    if ((udp_fd = udp_bind((struct sockaddr *)&client_addrs[0], &client_addrlens[0], as_client, server_host)) < 0) {
        return 1;
    }

    pfds[0].fd = udp_fd;
    pfds[0].events = POLLIN;

    unsigned char tun_buf[MTU], udp_buf[MTU];
    bzero(tun_buf, MTU);
    bzero(udp_buf, MTU);

    while (1) {
        fd_set readset;
        FD_ZERO(&readset);
        FD_SET(tun_fd, &readset);
        FD_SET(udp_fd, &readset);
        int max_fd = max(tun_fd, udp_fd) + 1;

        if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
            syslog(LOG_ERR, "select error");
            break;
        }

        int r;
        if (FD_ISSET(tun_fd, &readset)) {
            r = read(tun_fd, tun_buf, MTU);
            if (r < 0) {
                syslog(LOG_ERR, "read from tun_fd error");
                break;
            }

            aes_encrypt_decrypt(tun_buf, udp_buf, r, 1, aes_key); // Encrypt

            for (int i = 0; i < num_clients; i++) {
                r = sendto(udp_fd, udp_buf, r, 0, (const struct sockaddr *)&client_addrs[i], client_addrlens[i]);
                if (r < 0) {
                    syslog(LOG_ERR, "sendto udp_fd error");
                    break;
                }
            }
        }

        if (FD_ISSET(udp_fd, &readset)) {
            struct sockaddr_storage new_client_addr;
            socklen_t new_client_addrlen = sizeof(new_client_addr);
            r = recvfrom(udp_fd, udp_buf, MTU, 0, (struct sockaddr *)&new_client_addr, &new_client_addrlen);
            if (r < 0) {
                syslog(LOG_ERR, "recvfrom udp_fd error");
                break;
            }

            // Check if it's a new client
            int client_known = 0;
            for (int i = 0; i < num_clients; i++) {
                if (memcmp(&client_addrs[i], &new_client_addr, sizeof(new_client_addr)) == 0) {
                    client_known = 1;
                    break;
                }
            }

            if (!client_known && num_clients < MAX_CLIENTS) {
                client_addrs[num_clients] = new_client_addr;
                client_addrlens[num_clients] = new_client_addrlen;
                num_clients++;

                char client_ip[INET6_ADDRSTRLEN];
                inet_ntop(new_client_addr.ss_family,
                          (void *)&((struct sockaddr_in *)&new_client_addr)->sin_addr,
                          client_ip, sizeof(client_ip));

                syslog(LOG_INFO, "New client connected: %s", client_ip);
            }

            aes_encrypt_decrypt(udp_buf, tun_buf, r, 0, aes_key); // Decrypt
            syslog(LOG_INFO, "Writing to tun %d bytes ...", r);

            r = write(tun_fd, tun_buf, r);
            if (r < 0) {
                syslog(LOG_ERR, "write tun_fd error");
                break;
            }
        }
    }

    close(tun_fd);
    close(udp_fd);

    cleanup_route_table(as_client, server_host);
    closelog();

    return 0;
}
