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
#include "libpolypasswordhasher_sgx.h"

#define RB_MODE_RD 0
#define RB_MODE_WR 1
#define MAX_NUMBER_OF_SHARES 255
#define SHARE_LENGTH 256/8 
#define DIGEST_LENGTH SHARE_LENGTH
#define SIGNATURE_HASH_ITERATIONS 10000
#define MAX_SALT_LENGTH 16  

#define uint8 unsigned char
/*INCLUDE SGX-MALLOC Insted of stdlib malloc*/
#define XMALLOC malloc
#define XFREE free
/*INCLUDE SGX-MALLOC Insted of stdlib malloc*/

char TMP_DIRECTORY_CONF[] = "/tmp/ipc_conf";
char TMP_DIRECTORY_RUN[] = "/tmp/ipc_run";
char TMP_FILE_NUMBER_FMT[] =  "/pipe_";
int NAME_BUF_SIZE = 256;
char TAG[] = __FILE__;

struct _gfshare_ctx {
  unsigned int sharecount;
  unsigned int threshold;
  unsigned int size;
  unsigned char* sharenrs;
  unsigned char* buffer;
  unsigned int buffersize;
};

//Stores the sensitive data that was stored in libpph before.
typedef struct _enclave_context {
  uint8 * secret; //store secret
  uint8 * AES; // copy- unused 
  gfshare_ctx *share_context;  //store gfshare context after its init
  int threshold;
  uint8 secret_integrity[DIGEST_LENGTH];//digest
} enclave_context;

enclave_context ** contexts = NULL; //should contain array of contexts
int current_idx = -1;
int MAX_SUPPORTED_CONTEXTS = 1;
/*this means we share a single pipe*/
int fd_ea = -1;
int fd_ae = -1;

//Function prototype
uint8 *generate_pph_secret(uint8 *integrity_check);
void handle_pph_request(char * command, int len);

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

/*
 * at context creation, we need to generate sensitive data (ex: secret) inside the enclave
 * return 0 for success, -1 for error
 */
int pph_context_create(int threshold)
{
  unsigned char share_numbers[MAX_NUMBER_OF_SHARES];
  int i;

  if(MAX_SUPPORTED_CONTEXTS-1 == current_idx)// we cant handle any more contexts
  {
    printf("[%s] contexts exhausted! max supported [%d] \n",TAG,MAX_SUPPORTED_CONTEXTS);
    return -1;
  }
  //Create Enclave Context
  contexts[++current_idx] = malloc(sizeof(enclave_context));

  //Generate secret
  contexts[current_idx]->secret = contexts[current_idx]->AES = generate_pph_secret(contexts[current_idx]->secret_integrity);
  if(contexts[current_idx]->secret == NULL) {
    free(contexts[current_idx]);
    return -1;
  }

  contexts[current_idx]->threshold=threshold;
  // 5) Initialize share context
  for(i=0;i<MAX_NUMBER_OF_SHARES;i++) {
    share_numbers[i] = (short)i+1;
  }

  contexts[current_idx]->share_context = NULL;

  contexts[current_idx]->share_context = gfshare_ctx_init_enc( share_numbers,
                                                 MAX_NUMBER_OF_SHARES-1,
                                                 contexts[current_idx]->threshold,
                                                 SHARE_LENGTH);

  if(contexts[current_idx]->share_context == NULL) {
    free(contexts[current_idx]->secret);
    free(contexts[current_idx]); 
    return -1; 
  }

  gfshare_ctx_enc_setsecret(contexts[current_idx]->share_context, contexts[current_idx]->secret);

  printf("[%s] context is created [%d] \n",TAG,current_idx);
  return current_idx;
}


/*
 * at context deletion, we need to free sensitive data inside the enclave
 * return 0 for success, -1 for error
 */
int pph_context_destroy(int contextId)
{
  // return -1 for error
  int retval = -1;

  if(contexts[contextId] == NULL)
    return retval;

  //Lets free the secret
  if(contexts[contextId]->secret != NULL)
  {
    free(contexts[contextId]->secret);
    contexts[contextId]->secret = NULL;
  }

  //dont free AES again, its the same as secret

  //free gfshare context
  if(contexts[contextId]->share_context != NULL)
  {
    gfshare_ctx_free( contexts[contextId]->share_context);
    contexts[contextId]->share_context=NULL;
  }

  //free the enclave context
  free(contexts[contextId]);

  //book keeping update
  if(current_idx >0)
    current_idx--;
  else
    current_idx=-1;

  retval =0; //success
  printf("[%s] context [%d] is successfully destroyed  \n",TAG,contextId);
  return retval;
}

// this generates a random secret of the form [stream][streamhash], the
// parameters are the length of each section of the secret

uint8 *generate_pph_secret(uint8 *integrity_check)
{
  

  uint8 *secret;
  uint8 stream_digest[DIGEST_LENGTH], temp_digest[DIGEST_LENGTH];
  int i;

  if (integrity_check == NULL) {
    return NULL;
  }

  // allocate memory
  secret=malloc(sizeof(*secret)*DIGEST_LENGTH);
  if(secret == NULL){
    
    return NULL;
    
  }

  // generate a random stream
  RAND_bytes(secret, DIGEST_LENGTH);
 
  // Calculate the integrity check
  _calculate_digest(stream_digest, secret, DIGEST_LENGTH);
  for (i = 0; i < SIGNATURE_HASH_ITERATIONS - 1; i++){
    memcpy(temp_digest, stream_digest, DIGEST_LENGTH);
    _calculate_digest(stream_digest, temp_digest, DIGEST_LENGTH);
  }
  memcpy(integrity_check, stream_digest, DIGEST_LENGTH);

  return secret;
    
}

// isProtected is 1 or 0
int pph_create_account(int contextId, uint8 * sharedxorhash, int isProtected)
{
  int retval=0;
  printf("cont id [%d] , isProtected [%d] \n",contextId, isProtected);
  if(isProtected)
  {
    uint8 share_num;
    uint8 digest[DIGEST_LENGTH];
    uint8 share_data[SHARE_LENGTH];
    read(fd_ae, &share_num, sizeof(uint8)); //read share number
    //printf("\n share num is [%d] \n",share_num);
    read(fd_ae, digest, sizeof(uint8)*DIGEST_LENGTH);//read the salted hash
    gfshare_ctx_enc_getshare( contexts[contextId]->share_context, share_num,
        share_data);
    _xor_share_with_digest(sharedxorhash, digest, share_data, SHARE_LENGTH);
  }
  else
  {
    uint8 salted_hash[DIGEST_LENGTH];
    uint8 salt[MAX_SALT_LENGTH];
    read(fd_ae, salt, sizeof(uint8)*MAX_SALT_LENGTH);//read the salt
    read(fd_ae, salted_hash, sizeof(uint8)*DIGEST_LENGTH);//read the salted hash
    _encrypt_digest(sharedxorhash, salted_hash,
          contexts[contextId]->AES, salt);
  }
  return retval;
}

//Add for all API calls
void handle_pph_request(char * command, int len)
{
  printf(" handle_request  enter command [%s] \n",command);

  //Add else if conditions for API calls. 
  //All COMMANDS must go in libpolypasswordhasher_sgx.h
  if(!strncmp(command, INIT_CONTEXT, len)) //This call handles Init context
  {
    int threshold;
    read(fd_ae, &threshold, sizeof(threshold));
    int context_id = pph_context_create(threshold);
    write(fd_ea, &context_id, sizeof(int));
  }
  else if(!strncmp(command, DEL_CONTEXT, len)) //This call handles Delete context
  {
    unsigned int context_id;
    read(fd_ae, &context_id, sizeof(context_id));
    int success_msg = pph_context_destroy(context_id);
    write(fd_ea, &success_msg, sizeof(int));
  }
  else if(!strncmp(command, PROTECTED_HASH, len)) //This call handles Protected account creation
  {
    unsigned int context_id;
    read(fd_ae, &context_id, sizeof(context_id));
    uint8 sharedxorhash[DIGEST_LENGTH];
    int success_msg = pph_create_account(context_id, sharedxorhash, 1);
    write(fd_ea, &success_msg, sizeof(int));
    if(success_msg == 0)
      write(fd_ea, sharedxorhash, sizeof(uint8) * DIGEST_LENGTH);
  }
  else if(!strncmp(command, SHIELDED_HASH, len)) //This call handles Shielded account creation
  {
    unsigned int context_id;
    read(fd_ae, &context_id, sizeof(context_id));
    uint8 sharedxorhash[DIGEST_LENGTH];
    int success_msg = pph_create_account(context_id, sharedxorhash, 0);
    write(fd_ea, &success_msg, sizeof(int));
    if(success_msg == 0)
      write(fd_ea, sharedxorhash, sizeof(uint8) * DIGEST_LENGTH);
  }
}

/* main operation. communicate with santiago */
void enclave_main(int argc, char **argv)
{
	int i;

  char port_enc_to_app[NAME_BUF_SIZE];
  char port_app_to_enc[NAME_BUF_SIZE];
  printf("[%d] \n",argc);

  if(argc != 5) {
      printf("Usage: [PORT_ENCLAVE_TO_APP] [PORT_APP_TO_ENCLAVE]\n");
      sgx_exit(NULL);
  }
  
  strcpy(port_enc_to_app, argv[3]);
  strcpy(port_app_to_enc, argv[4]);

  //printf("PIPE to app is  [%s] PIPE to enclave is [%s] \n",port_enc_to_app,port_app_to_enc);
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

  //printf(" before malloc \n");
  //Init context array
  contexts = malloc(sizeof(enclave_context *) * MAX_SUPPORTED_CONTEXTS);//For now only one context TODO: dynamic
  //printf(" after malloc \n");
  // Read the request operations
  int len;
  
 
  while(1)
  {
    char msg[20]={0};
    //printf(" reading \n");
    read(fd_ae, &len, sizeof(int));//first read how many characters
    //printf(" first [%d] \n",len);
    read(fd_ae, msg, len+1);
    //printf(" second [%s] \n",msg);
    //printf(" goto handle request \n");
    handle_pph_request(msg, len);
  }

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

void _calculate_digest(uint8 *digest, const uint8 *password,
    unsigned int length) {
  EVP_MD_CTX mctx;

  EVP_MD_CTX_init(&mctx);
  EVP_DigestInit_ex(&mctx, EVP_sha256(), NULL); 
                                               
                                              
  EVP_DigestUpdate(&mctx, password, length);
  EVP_DigestFinal_ex(&mctx,  digest, 0);
  EVP_MD_CTX_cleanup(&mctx);

  return;

}

// xoring two streams of bytes. 
void _xor_share_with_digest(uint8 *result, uint8 *share,
     uint8 * digest,unsigned int length) {
  int i;
  unsigned int *xor_digest_pointer;
  unsigned int *xor_share_pointer;
  unsigned int *xor_result_pointer;
  int aligned_length = length/sizeof(*xor_result_pointer);
  int char_aligned_length = aligned_length * sizeof(*xor_result_pointer);
  int char_aligned_offset = length%sizeof(*xor_result_pointer);

  // xor the whole thing, we do this in an unsigned int fashion imagining 
  // this is where usually where the processor aligns things and is, hence
  // faster
  xor_digest_pointer = (unsigned int*)digest;
  xor_share_pointer = (unsigned int*)share;
  xor_result_pointer = (unsigned int*)result;
  
  for(i=0;i<aligned_length;i++) {
      *(xor_result_pointer + i) = 
        *(xor_share_pointer+i)^*(xor_digest_pointer +i);
  }
  
  // xor the rest, if we have a number that's not divisible by a word.
  for(i = char_aligned_length; i<char_aligned_length+char_aligned_offset;i++) {
    *(result+i) = *(share+i) ^ *(digest+i); 
  }
    
  return;// :/
    
}

void _encrypt_digest(uint8 *result, uint8 *digest, uint8 *AES_key, uint8* iv) {

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

