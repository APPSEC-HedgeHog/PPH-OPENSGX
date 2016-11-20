#ifndef LIBPOLYPASSWORDHASHER_OPENSGX
#define LIBPOLYPASSWORDHASHER_OPENSGX

int initializePipe(char *enc_to_app, char * app_to_enc);
void write_to_enclave(char *data, int len);
void read_from_enclave(char *buf, int len);

#endif
