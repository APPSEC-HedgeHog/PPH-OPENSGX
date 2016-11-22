#ifndef LIBPOLYPASSWORDHASHER_OPENSGX
#define LIBPOLYPASSWORDHASHER_OPENSGX

/*All messages request code */
const char INIT_CONTEXT [] = "INIT_CONTEXT";
// Added delete context message request code
const char DEL_CONTEXT [] ="DEL_CONTEXT";

int initializePipe(char *enc_to_app, char * app_to_enc);
void write_to_enclave(char *data, int len);
void read_from_enclave(char *buf, int len);

#endif
