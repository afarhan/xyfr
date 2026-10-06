#ifndef MD5_H
#define MD5_H 

struct MD5Context {
		uint32_t buf[4];
		uint32_t bits[2];
		unsigned char in[64];
};
//typedef struct MD5Context MD5_CTX;

extern void MD5Init(struct MD5Context *ctx);
extern void MD5Update(struct MD5Context *ctx, unsigned char const *buf, unsigned len);
extern void MD5Final(unsigned char *digest, struct MD5Context *ctx);
extern void MD5Transform(uint32_t *buf, uint32_t *in);


#endif /* !MD5_H */
