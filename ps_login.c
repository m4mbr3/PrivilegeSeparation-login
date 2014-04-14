#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv local_conversation = {
    misc_conv,
    NULL
};
int 
authenticate_system(const char *username)
{
    pam_handle_t *pamh = NULL;
    int retval;

    retval = pam_start("ps_login", username, &local_conversation, &pamh);
    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);
    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);

    if (retval == PAM_SUCCESS) {
        fprintf(stdout, "Authenticated \n");
    } else {
        fprintf(stdout, "Not Authenticated \n");
    }

    if (pam_end(pamh, retval) != PAM_SUCCESS) {
        pamh = NULL;
        fprintf(stderr, "ps_login: failed to release authenticator\n");
    }
    return (retval == PAM_SUCCESS ? 0:1 );
}

int
main(void) 
{
        char *ps = (char *) malloc(sizeof(char)*4);
        char *ptr;
        char lev_buf[4];
        int fp = open("/dev/ps_pwd", O_RDWR);
        int flag;
        int num;
        if (fp < 0) {
            printf ("Cannot open the char device ps_pwd under /dev\n");
            exit (-1);
        }
        while (1) {
           memset(lev_buf, 0, 4);
           flag = 0;
           do{
               num = read(fp, lev_buf, 3); 
               int i;
               for (i=0; i<num; i++) {
                    if((lev_buf[i] < '0') || (lev_buf[i] > '9')) lev_buf[i] = '\0';
                    else 
                        flag = 1;
               } 
           }while(!flag); 
           memset(ps, 0, 4);
           strncpy(ps, "ps_", 3); 
           ptr = strncat(ps, lev_buf, 4);
           write(fp, ((authenticate_system(ptr) == 0 )? "OK":"NO"),2);  
        }
   close(fp);
   exit(EXIT_SUCCESS);
}
