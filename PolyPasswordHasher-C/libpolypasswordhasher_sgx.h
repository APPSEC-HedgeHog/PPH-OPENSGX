#ifndef LIBPOLYPASSWORDHASHER_OPENSGX
#define LIBPOLYPASSWORDHASHER_OPENSGX

/*All messages request code */
const char INIT_CONTEXT [] = "INIT_CONTEXT";
// Added delete context message request code
const char DEL_CONTEXT [] ="DEL_CONTEXT";
//send hash for protected accounts
const char PROTECTED_HASH [] ="PROTECTED_HASH";
//send hash for shielded accounts
const char SHIELDED_HASH [] ="SHIELDED_HASH";
// Added to indicate reloading of context
const char RELOAD_CONTEXT []="RELOAD_CONTEXT";
//Added for unlocking the password database
const char UNLOCK_PASSWD_DB []="UNLOCK_PASSWD_DB";

int initializePipe(char *enc_to_app, char * app_to_enc);
void write_to_enclave(char *data, int len);
void read_from_enclave(char *buf, int len);
unsigned int getAE();

unsigned int getEA();
#endif
