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
#include <openssl/aes.h>
#include <syslog.h>

#include <openssl/evp.h>

// Configuration macros
#define PORT 54345
#define MTU 1400
#define BIND_HOST "0.0.0.0"
#define AES_KEYLEN 256
#define AES_BLOCK_SIZE 16

static int max(int a, int b) {
  return a > b ? a : b;
}

void handle_error(const char *msg) {
  syslog(LOG_ERR, "%s: %s", msg, strerror(errno));
  exit(EXIT_FAILURE);
}

/*
 * Create VPN interface /dev/tun0 and return a fd
 */
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

/*
 * Execute commands
 */
static void run(char *cmd) {
	syslog(LOG_INFO, "Executing `%s`", cmd);
  if (system(cmd)) {
    handle_error(cmd);
  }
}

/*
 * Configure IP address and MTU of VPN interface /dev/tun0
 */
void ifconfig(int as_client) {
  char cmd[1024];

  if (as_client) {
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.2/16 mtu %d up", MTU);
  } else {
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.1/16 mtu %d up", MTU);
  }
  run(cmd);
}

/*
 * Setup route table via `iptables` & `ip route`
 */
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

/*
 * Cleanup route table
 */
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

/*
 * Bind UDP port
 */
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

/*
 * AES encryption/decryption
 */
void aes_encrypt_decrypt(const unsigned char *input, unsigned char *output, int len, int enc) {
    static const unsigned char aes_key[AES_KEYLEN / 8] = "12345678901234567890123456789012";
    unsigned char iv[AES_BLOCK_SIZE] = "initialvector123";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_error("Failed to create EVP_CIPHER_CTX");
    }

    const EVP_CIPHER *cipher = EVP_aes_256_cfb128();
    if (enc) {
        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, aes_key, iv)) {
            handle_error("EVP_EncryptInit_ex failed");
        }

        int outlen;
        if (1 != EVP_EncryptUpdate(ctx, output, &outlen, input, len)) {
            handle_error("EVP_EncryptUpdate failed");
        }

        if (1 != EVP_EncryptFinal_ex(ctx, output + outlen, &outlen)) {
            handle_error("EVP_EncryptFinal_ex failed");
        }
    } else {
        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, aes_key, iv)) {
            handle_error("EVP_DecryptInit_ex failed");
        }

        int outlen;
        if (1 != EVP_DecryptUpdate(ctx, output, &outlen, input, len)) {
            handle_error("EVP_DecryptUpdate failed");
        }

        if (1 != EVP_DecryptFinal_ex(ctx, output + outlen, &outlen)) {
            handle_error("EVP_DecryptFinal_ex failed");
        }
    }

    EVP_CIPHER_CTX_free(ctx);
}
/*
 * Catch Ctrl-C and `kill`s, make sure route table gets cleaned before this process exit
 */
void cleanup(int signo) {
  syslog(LOG_INFO, "Goodbye, cruel world....");
  if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
    // Assuming we have access to global variables or a structure holding the state
    // cleanup_route_table(global_as_client, global_server_host);
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

  if (argc < 2) {
    syslog(LOG_ERR, "Usage: %s <SERVER|CLIENT> [SERVER_HOST]", argv[0]);
    exit(EXIT_FAILURE);
  }

  int as_client = 0;
  const char *server_host = NULL;

  if (strcmp(argv[1], "CLIENT") == 0) {
    if (argc != 3) {
      syslog(LOG_ERR, "Usage: %s CLIENT <SERVER_HOST>", argv[0]);
      exit(EXIT_FAILURE);
    }
    as_client = 1;
    server_host = argv[2];
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
  struct sockaddr_storage client_addr;
  socklen_t client_addrlen = sizeof(client_addr);

  if ((udp_fd = udp_bind((struct sockaddr *)&client_addr, &client_addrlen, as_client, server_host)) < 0) {
    return 1;
  }

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

      aes_encrypt_decrypt(tun_buf, udp_buf, r, 1); // Encrypt
      syslog(LOG_INFO, "Writing to UDP %d bytes ...", r);

      r = sendto(udp_fd, udp_buf, r, 0, (const struct sockaddr *)&client_addr, client_addrlen);
      if (r < 0) {
        syslog(LOG_ERR, "sendto udp_fd error");
        break;
      }
    }

    if (FD_ISSET(udp_fd, &readset)) {
      r = recvfrom(udp_fd, udp_buf, MTU, 0, (struct sockaddr *)&client_addr, &client_addrlen);
      if (r < 0) {
        syslog(LOG_ERR, "recvfrom udp_fd error");
        break;
      }

      aes_encrypt_decrypt(udp_buf, tun_buf, r, 0); // Decrypt
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

