#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <err.h>
#include <assert.h>
#include <sys/stat.h>

#include <sgx.h>
#include <sgx-user.h>
#include <sgx-kern.h>
#include <sgx-lib.h>

#include "libgfshare.h"

#define RB_MODE_RD 0
#define RB_MODE_WR 1
#define MAX_NUMBER_OF_SHARES 255
#define SHARE_LENGTH 256/8 

char TMP_DIRECTORY_CONF[] = "/tmp/ipc_conf";
char TMP_DIRECTORY_RUN[] = "/tmp/ipc_run";
char TMP_FILE_NUMBER_FMT[] =  "/pipe_";
int NAME_BUF_SIZE = 256;

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
	unsigned char share_numbers[MAX_NUMBER_OF_SHARES];

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

	printf("PIPE 1 [%s] PIPE 2 [%s] \n",port_enc_to_app,port_app_to_enc);
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
