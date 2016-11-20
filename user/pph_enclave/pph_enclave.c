#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>
#include <sgx-lib.h>
#include "libgfshare.h"
#include "config.h"
#include "libgfshare_tables.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#define RB_MODE_RD 0
#define RB_MODE_WR 1
#define MAX_NUMBER_OF_SHARES 255
#define SHARE_LENGTH 256/8 
#define DIGEST_LENGTH SHARE_LENGTH

/*INCLUDE SGX-MALLOC Insted of stdlib malloc*/
#define XMALLOC malloc
#define XFREE free
/*INCLUDE SGX-MALLOC Insted of stdlib malloc*/

char TMP_DIRECTORY_CONF[] = "/tmp/ipc_conf";
char TMP_DIRECTORY_RUN[] = "/tmp/ipc_run";
char TMP_FILE_NUMBER_FMT[] =  "/pipe_";
int NAME_BUF_SIZE = 256;

struct _gfshare_ctx {
  unsigned int sharecount;
  unsigned int threshold;
  unsigned int size;
  unsigned char* sharenrs;
  unsigned char* buffer;
  unsigned int buffersize;
};

static int pipe_init(int flag_dir)
{
	int ret;

	if(flag_dir == 0)
		ret = mkdir(TMP_DIRECTORY_CONF, 0770);
	else if(flag_dir == 1)
		ret = mkdir(TMP_DIRECTORY_RUN, 0770);

	if(ret == -1)
	{
		if(errno != EEXIST) {
                puts("Fail to mkdir");
                return -1;
        }
	}
	return 0;
}

static int pipe_open(char *unique_id, int is_write, int flag_dir)
{
	char name_buf[NAME_BUF_SIZE];

    if (flag_dir == 0) {
        strcpy(name_buf, TMP_DIRECTORY_CONF);
        strcpy(name_buf+strlen(name_buf), TMP_FILE_NUMBER_FMT);
        strcpy(name_buf+strlen(name_buf), unique_id);
    }
    else if (flag_dir == 1) {
        strcpy(name_buf, TMP_DIRECTORY_RUN);
        strcpy(name_buf+strlen(name_buf), TMP_FILE_NUMBER_FMT);
        strcpy(name_buf+strlen(name_buf), unique_id);
    }

	int ret = mknod(name_buf, S_IFIFO | 0770, 0);
	if(ret == -1)
	{
        if(errno != EEXIST) {
            puts("Fail to mknod");
            return -1;
        }
	}

	int flag = O_ASYNC;
	if(is_write)
		flag |= O_WRONLY;
	else
		flag |= O_RDONLY;

	int fd = open(name_buf, flag);

    if(fd == -1)
    {
        puts("Fail to open");
        return -1;
    }

    return fd;
}

// For simplicity, this function do simple operation.
// In the realistic scenario, key creation, signature generation and etc will be
// the possible example.
void do_secret(char *buf) 
{
    for(int i=0; i<strlen(buf); i++)
        buf[i]++;
}

/* main operation. communicate with tor-gencert & tor process */
void enclave_main(int argc, char **argv)
{
    int fd_ea = -1;
    int fd_ae = -1;
	int i;
	EVP_PKEY identity_key_set;
	unsigned char share_numbers[MAX_NUMBER_OF_SHARES];

	for(i=0;i<MAX_NUMBER_OF_SHARES;i++) {
    	share_numbers[i] = (short)i+1;
  	}
	
	//this is just for test to see if ported gfshare compiles 
	gfshare_ctx_init_enc( share_numbers,
                         MAX_NUMBER_OF_SHARES-1,
                         0,
                         SHARE_LENGTH);

    char port_enc_to_app[NAME_BUF_SIZE];
    char port_app_to_enc[NAME_BUF_SIZE];
	printf("[%d] \n",argc);
	
    if(argc != 5) {
        printf("Usage: [PORT_ENCLAVE_TO_APP] [PORT_APP_TO_ENCLAVE]\n");
        sgx_exit(NULL);
    }
    
    strcpy(port_enc_to_app, argv[3]);
    strcpy(port_app_to_enc, argv[4]);

	printf("HI PIPE 1 [%s] PIPE 2 [%s] \n",port_enc_to_app,port_app_to_enc);
    if(pipe_init(0) < 0) {
            puts("Error in pipe_init");
            sgx_exit(NULL);
    }

    if((fd_ea = pipe_open(port_enc_to_app, RB_MODE_WR, 0)) < 0) {
            puts("Error in pipe_open");
            sgx_exit(NULL);
    }

    if((fd_ae = pipe_open(port_app_to_enc, RB_MODE_RD, 0)) < 0) {
            puts("Error in pipe_open");
            sgx_exit(NULL);
    }

    // Read the request operations
    int len;
    char msg[20]={0};
   
    
    read(fd_ae, msg, 15);
	puts(msg);
    printf("ENCLAVE: message from host [%s] \n",msg);
    // Send the result
    write(fd_ea, "Hi Santiago !!!", 15);       
	while(1);
    close(fd_ea);
    close(fd_ae);
}


/*AL GFSHARE FUNCTIONS ARE AVAILABLE FROM HERE - (Porting to OpenSGX)*/
static void
_gfshare_fill_rand_using_random( unsigned char* buffer,
                                 unsigned int count )
{
  unsigned int i;
  for( i = 0; i < count; ++i )
    buffer[i] = 1<<i; // this is a really big patch, but why should we have 
                      // a random initialization
}

gfshare_rand_func_t gfshare_fill_rand = _gfshare_fill_rand_using_random;

/* ------------------------------------------------------[ Preparation ]---- */

static gfshare_ctx *
_gfshare_ctx_init_core( unsigned char *sharenrs,
                        unsigned int sharecount,
                        unsigned char threshold,
                        unsigned int size )
{
  gfshare_ctx *ctx;
  
  ctx = XMALLOC( sizeof(struct _gfshare_ctx) );
  if( ctx == NULL )
    return NULL; /* errno should still be set from XMALLOC() */
  
  ctx->sharecount = sharecount;
  ctx->threshold = threshold;
  ctx->size = size;
  ctx->sharenrs = XMALLOC( sharecount );
  
  if( ctx->sharenrs == NULL ) {
    int saved_errno = errno;
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  memcpy( ctx->sharenrs, sharenrs, sharecount );
  ctx->buffersize = threshold * size;
  ctx->buffer = XMALLOC( ctx->buffersize );
  
  if( ctx->buffer == NULL ) {
    int saved_errno = errno;
    XFREE( ctx->sharenrs );
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  return ctx;
}

/* Initialise a gfshare context for producing shares */
gfshare_ctx *
gfshare_ctx_init_enc( unsigned char* sharenrs,
                      unsigned int sharecount,
                      unsigned char threshold,
                      unsigned int size )
{
  unsigned int i;
  for (i = 0; i < sharecount; i++) {
    if (sharenrs[i] == 0) {
      /* can't have x[i] = 0 - that would just be a copy of the secret, in
       * theory (in fact, due to the way we use exp/log for multiplication and
       * treat log(0) as 0, it ends up as a copy of x[i] = 1) */
      errno = EINVAL;
      return NULL;
    }
  }

  return _gfshare_ctx_init_core( sharenrs, sharecount, threshold, size );
}

/* Initialise a gfshare context for recombining shares */
gfshare_ctx*
gfshare_ctx_init_dec( unsigned char* sharenrs,
                      unsigned int sharecount,
                      unsigned int size )
{
  gfshare_ctx *ctx = _gfshare_ctx_init_core( sharenrs, sharecount, sharecount, size );
  
  if( ctx != NULL )
    ctx->threshold = 0;
  
  return ctx;
}

/* Free a share context's memory. */
void 
gfshare_ctx_free( gfshare_ctx* ctx )
{
  gfshare_fill_rand( ctx->buffer, ctx->buffersize );
  gfshare_fill_rand( ctx->sharenrs, ctx->sharecount );
  XFREE( ctx->sharenrs );
  XFREE( ctx->buffer );
  gfshare_fill_rand( (unsigned char*)ctx, sizeof(struct _gfshare_ctx) );
  XFREE( ctx );
}

/* --------------------------------------------------------[ Splitting ]---- */

/* Provide a secret to the encoder. (this re-scrambles the coefficients) */
void 
gfshare_ctx_enc_setsecret( gfshare_ctx* ctx,
                           unsigned char* secret)
{
  memcpy( ctx->buffer + ((ctx->threshold-1) * ctx->size),
          secret,
          ctx->size );
  gfshare_fill_rand( ctx->buffer, (ctx->threshold-1) * ctx->size );
}

/* Extract a share from the context. 
 * 'share' must be preallocated and at least 'size' bytes long.
 * 'sharenr' is the index into the 'sharenrs' array of the share you want.
 */
void 
gfshare_ctx_enc_getshare( gfshare_ctx* ctx,
                          unsigned char sharenr,
                          unsigned char* share)
{
  unsigned int pos, coefficient;
  unsigned int ilog = logs[ctx->sharenrs[sharenr]];
  unsigned char *coefficient_ptr = ctx->buffer;
  unsigned char *share_ptr;
  for( pos = 0; pos < ctx->size; ++pos )
    share[pos] = *(coefficient_ptr++);
  for( coefficient = 1; coefficient < ctx->threshold; ++coefficient ) {
    share_ptr = share;
    for( pos = 0; pos < ctx->size; ++pos ) {
      unsigned char share_byte = *share_ptr;
      if( share_byte )
        share_byte = exps[ilog + logs[share_byte]];
      *share_ptr++ = share_byte ^ *coefficient_ptr++;
    }
  }
}

/* ----------------------------------------------------[ Recombination ]---- */

/* Inform a recombination context of a change in share indexes */
void 
gfshare_ctx_dec_newshares( gfshare_ctx* ctx,
                           unsigned char* sharenrs)
{
  memcpy( ctx->sharenrs, sharenrs, ctx->sharecount );
}

/* Provide a share context with one of the shares.
 * The 'sharenr' is the index into the 'sharenrs' array
 */
void 
gfshare_ctx_dec_giveshare( gfshare_ctx* ctx,
                           unsigned char sharenr,
                           unsigned char* share )
{
  memcpy( ctx->buffer + (sharenr * ctx->size), share, ctx->size );
}

/* Extract the secret by interpolation of the shares.
 * secretbuf must be allocated and at least 'size' bytes long
 */
void
gfshare_ctx_dec_extract( gfshare_ctx* ctx,
                         unsigned char* secretbuf )
{
  unsigned int i, j;
  unsigned char *secret_ptr, *share_ptr;
  
  for( i = 0; i < ctx->size; ++i )
    secretbuf[i] = 0;
  
  for( i = 0; i < ctx->sharecount; ++i ) {
    /* Compute L(i) as per Lagrange Interpolation */
    unsigned Li_top = 0, Li_bottom = 0;
    
    if( ctx->sharenrs[i] == 0 ) continue; /* this share is not provided. */
    
    for( j = 0; j < ctx->sharecount; ++j ) {
      if( i == j ) continue;
      if( ctx->sharenrs[j] == 0 ) continue; /* skip empty share */
      Li_top += logs[ctx->sharenrs[j]];
      if( Li_top >= 0xff ) Li_top -= 0xff;
      Li_bottom += logs[(ctx->sharenrs[i]) ^ (ctx->sharenrs[j])];
      if( Li_bottom >= 0xff ) Li_bottom -= 0xff;
    }
    if( Li_bottom  > Li_top ) Li_top += 0xff;
    Li_top -= Li_bottom; /* Li_top is now log(L(i)) */
    
    secret_ptr = secretbuf; share_ptr = ctx->buffer + (ctx->size * i);
    for( j = 0; j < ctx->size; ++j ) {
      if( *share_ptr )
        *secret_ptr ^= exps[Li_top + logs[*share_ptr]];
      share_ptr++; secret_ptr++;
    }
  }
}

void _calculate_digest(char *digest, const char *password,
    unsigned int length) {
  EVP_MD_CTX mctx;

  EVP_MD_CTX_init(&mctx);
  EVP_DigestInit_ex(&mctx, EVP_sha256(), NULL); 
                                               
                                              
  EVP_DigestUpdate(&mctx, password, length);
  EVP_DigestFinal_ex(&mctx,  digest, 0);
  EVP_MD_CTX_cleanup(&mctx);

  return;

}

void _encrypt_digest(char *result, char *digest, char *AES_key, char* iv) {

  EVP_CIPHER_CTX en_ctx;
  int c_len,f_len;

  // encrypt the generated digest
  EVP_CIPHER_CTX_init(&en_ctx);
  EVP_EncryptInit_ex(&en_ctx, EVP_aes_256_ctr(), NULL, AES_key, iv);
  EVP_EncryptUpdate(&en_ctx, result, &c_len,
      digest, DIGEST_LENGTH);
  EVP_EncryptFinal_ex(&en_ctx, result+c_len, &f_len);
  EVP_CIPHER_CTX_cleanup(&en_ctx);

  return;


}

