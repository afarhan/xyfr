// Standalone activation tester: builds a msg_type=5 activation msg1 exactly like
// the firmware (build_msg1 -> peer_handshake_request_generate + code in mac2),
// sends it to the relay's :5004, and reports the routed-back reply. Test-only.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include "wg.h"

// platform symbols wg.o references (initiator path here never calls the
// responder-side validate_public_key, but the linker still needs both):
time_t get_current_time_seconds(void){ return time(NULL); }
int validate_public_key(const uint8_t *pk, void *ctx){ (void)pk;(void)ctx; return 1; }

static void hex2bin(const char *hex, uint8_t *out, int n){
  int i; for(i=0;i<n;i++){ char b[3]={hex[2*i],hex[2*i+1],0}; out[i]=(uint8_t)strtol(b,0,16); }
}

int main(int argc, char **argv){
  if(argc<5){ fprintf(stderr,"usage: %s <relay_ip> <server_pub_hex64> <my_priv_hex64> <code16>\n",argv[0]); return 2; }
  uint8_t server_pub[32], my_priv[32];
  hex2bin(argv[2],server_pub,32);
  hex2bin(argv[3],my_priv,32);
  const char *code=argv[4];
  if(strlen(code)!=16){ fprintf(stderr,"code must be 16 chars, got %zu\n",strlen(code)); return 2; }

  wireguard_init(my_priv);
  struct peer p; peer_init(&p);
  struct msg1 m;
  uint64_t sid = get_fresh_sessionid();
  peer_handshake_request_generate(&p, MSG_REQUEST_ACTIVATE, server_pub, sid, &m);
  memcpy(m.mac2, code, 16);

  int s=socket(AF_INET,SOCK_DGRAM,0);
  struct sockaddr_in dst; memset(&dst,0,sizeof dst);
  dst.sin_family=AF_INET; dst.sin_port=htons(5004);
  inet_pton(AF_INET,argv[1],&dst.sin_addr);
  struct timeval tv={5,0}; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);

  if(sendto(s,&m,sizeof(m),0,(struct sockaddr*)&dst,sizeof dst)<0){ perror("sendto"); return 1; }
  printf("sent: sid=%016llx code=%s sender_index=%08x server_partkey=%08x\n",
         (unsigned long long)sid, code, m.sender_index, get_part_key(server_pub));

  uint8_t buf[512];
  int r=recvfrom(s,buf,sizeof buf,0,NULL,NULL);
  if(r<=0){ printf("RESULT: NO REPLY (timeout)\n"); return 1; }
  if(buf[0]==MSG_RESPONSE_CONNECT){
    printf("RESULT: SUCCESS  (msg2, %d bytes)\n", r);
  } else if(buf[0]==MSG_ACTIVATION_FAILED){
    unsigned rn=buf[1];
    const char *nm = rn==1?"UNKNOWN_CODE":rn==2?"CODE_USED":rn==3?"USER_EXISTS":rn==4?"INTERNAL":"?";
    printf("RESULT: FAILED   reason=%u (%s)\n", rn, nm);
  } else {
    printf("RESULT: unexpected reply type=%u (%d bytes)\n", buf[0], r);
  }
  return 0;
}
