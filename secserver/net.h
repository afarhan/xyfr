#define MAX_PACKET_LEN 1200
int udp_socket_open(char *strAddress, uint16_t port);
int udp_read(int sock, uint8_t *data, int max_length, uint32_t *ip, uint16_t *port);
int udp_write(int sock, void *data, int length, uint32_t ip, uint16_t port);
const char *ip2string(uint32_t address);
uint32_t string2ip(const char *host);
