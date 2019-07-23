#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSIZE 4096
#define IP_HDRLEN 20
#define ICMP_HDRLEN 8

#define USAGE "Usage: p1ng [OPTIONS] <DSTIP>\n\n" \
              "Options:\n" \
              "  -d  DATA     Payload data to send\n" \
              "  -h           Display this usage information\n" \
              "  -m           Set the More Fragments (MF) flag in the IP header\n" \
              "  -s  SRCIP    Spoof the source IP address\n" \
              "  -w  SECONDS  Seconds to wait for a reply, only relevant when source address isn't spoofed (default=5)\n"

unsigned short checksum(char* buf, int left) {
  long sum = 0;
  unsigned short* words = (unsigned short*)buf;

  while (left > 1) {
    sum += *words++;
    left -= 2;
  }

  if (left) {
    sum += *(char*)words;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return ~sum & 0xffff;
}

int rawsock(int waitsecs) {
  int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
  setuid(getuid());

  if (sockfd == -1) {
    perror("socket");
    return -1;
  }

  if (waitsecs > 0) {
    struct timeval tv;
    tv.tv_sec = waitsecs;
    tv.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval))) {
      close(sockfd);
      perror("setsockopt(SO_RCVTIMEO)");
      return -1;
    }
  }

  int on = 1;

  if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) {
    close(sockfd);
    perror("setsockopt(IP_HDRINCL)");
    return 1;
  }

  return sockfd;
}

int ping(int sockfd, struct sockaddr_in* dstaddr, struct ip* ip, struct icmp* icmp, int wait) {
  int left = ip->ip_len;
  char* ptr = (char*)ip;
  int sent;

  while (left) {
    sent = sendto(sockfd, ptr, left, 0, (struct sockaddr*)dstaddr, sizeof(struct sockaddr));

    if (sent == -1) {
      perror("sendto");
      return -1;
    }

    ptr += sent;
    left -= sent;
  }

  if (!wait) return 0;

  int rcvd;

  while (1) {
    left = ip->ip_len;
    ptr = (char*) ip;

    while (left) {
      rcvd = recv(sockfd, ptr, left, 0);

      if (rcvd == -1) {
        perror("recv");
        return -1;
      }

      ptr += rcvd;
      left -= rcvd;
    }

    if (
      ip->ip_p == IPPROTO_ICMP &&
      icmp->icmp_type == ICMP_ECHOREPLY &&
      icmp->icmp_id == htons(54321)
    ) return 0;
  }
}

int main(int argc, char** argv) {
  int opt, help = 0, mf = 0, waitsecs = 5;
  char* data = NULL;
  char* srcip = NULL;

  while ((opt = getopt(argc, argv, "d:hms:w:")) != -1) {
    switch (opt) {
      case 'd':
        data = optarg;
        break;

      case 'h':
        help = 1;
        break;

      case 'm':
        mf = 1;
        break;

      case 's':
        srcip = optarg;
        break;

      case 'w':
        waitsecs = atoi(optarg);
        break;

      default:
        break;
    }
  }

  if (srcip != NULL || waitsecs <= 0) {
    waitsecs = 0;
  }

  if (help) {
    printf("%s\n", USAGE);
    return 0;
  }

  char* dstip = argv[optind];

  if (dstip == NULL) {
    fprintf(stderr, "Expected IP address\n");
    return -1;
  }

  // Check the destination IP addresses
  struct sockaddr_in dstaddr, srcaddr;

  if (!inet_pton(AF_INET, dstip, &(dstaddr.sin_addr))) {
    fprintf(stderr, "Invalid destination IP address \"%s\"\n", dstip);
    return -1;
  }

  if (srcip != NULL) {
    if (!inet_pton(AF_INET, srcip, &(srcaddr.sin_addr))) {
      fprintf(stderr, "Invalid source IP address \"%s\"\n", srcip);
      return -1;
    }
  }

  // Create the raw socket
  int sockfd = rawsock(waitsecs);

  if (sockfd == -1) {
    return -1;
  }

  char buf[BUFSIZE];
  int dlen = 0;

  if (data != NULL) {
    dlen = strlen(data);
  }

  // Construct the IP packet
  struct ip* ip = (struct ip*)buf;

  ip->ip_v = 4;
  ip->ip_hl = IP_HDRLEN / 4;
  ip->ip_tos = 0;
  ip->ip_len = IP_HDRLEN + ICMP_HDRLEN + dlen;
  ip->ip_id  = 0;
  ip->ip_off = htons(mf ? IP_MF : IP_DF);
  ip->ip_ttl = 255;
  ip->ip_p = IPPROTO_ICMP;
  ip->ip_sum = 0;
  ip->ip_src = srcaddr.sin_addr;
  ip->ip_dst = dstaddr.sin_addr;

  // Construct the ICMP packet
  struct icmp* icmp = (struct icmp*)(ip + 1);

  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_cksum = 0;
  icmp->icmp_id = htons(54321);
  icmp->icmp_seq = 0;

  char* dptr = buf + IP_HDRLEN + ICMP_HDRLEN;

  // Copy the data and calculate checksums for ICMP then IP
  memcpy(dptr, data, dlen);
  icmp->icmp_cksum = checksum((char*)icmp, ICMP_HDRLEN + dlen);
  ip->ip_sum = checksum((char*)ip, ip->ip_len);

  // Send echo request and receive reply
  if (ping(sockfd, &dstaddr, ip, icmp, waitsecs)) {
    return -1;
  }

  close(sockfd);

  if (waitsecs) {
    printf("Got reply!\n");

    if (dlen) {
      printf("'%s'\n", data);
    }
  }

  return 0;
}
