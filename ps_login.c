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
struct pam_response *reply;
int 
conv(int num_msg, 
         const struct pam_message **msgm,
         struct pam_response **response, 
         void *appdata_ptr)
{    
    *response = reply;  
    return PAM_SUCCESS;
}
static struct pam_conv local_conversation = {
    conv,
    NULL
};
int 
authenticate_system(const char *username, 
                        const char *password)
{
    pam_handle_t *pamh = NULL;
    int retval;
    reply = (struct pam_response*) malloc(sizeof(struct pam_response));
    reply->resp = strdup(password);
    reply->resp_retcode = 0;

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
        
        /* Our process ID and Session ID */
        //pid_t pid, sid;
        
        /* Fork off the parent process */
        //pid = fork();
        //if (pid < 0) {
        //        exit(EXIT_FAILURE);
        //}
        /* If we got a good PID, then
           we can exit the parent process. */
        //if (pid > 0) {
        //        exit(EXIT_SUCCESS);
        //}

        /* Change the file mode mask */
        //umask(0);
                
        /* Open any logs here */        
                
        /* Create a new SID for the child process */
        //sid = setsid();
        //if (sid < 0) {
                /* Log the failure */
        //        exit(EXIT_FAILURE);
        //}
        

        
        /* Change the current working directory */
        //if ((chdir("/")) < 0) {
                /* Log the failure */
        //        exit(EXIT_FAILURE);
        //}
        
        /* Close out the standard file descriptors */
        //close(STDIN_FILENO);
        //close(STDOUT_FILENO);
        //close(STDERR_FILENO);
        
        /* Daemon-specific initialization goes here */
                /* The Big Loop */
        char *ps = (char *) malloc(sizeof(char)*4);
        while (1) {
           /* Do some task here ... */
           int fp = open("/dev/ps_pwd", O_RDWR);
           if (fp < 0) {
               printf ("Cannot open the char device ps_pwd under /dev\n");
               exit (-1);
           }
           char lev_buf[4];
           char buf[80];
           char *ptr; 
           memset(lev_buf, 0, 4);
           memset(buf, 0, 80);
           memset(ptr, 0, 6);
           int flag;
           do{
               flag = 0;
               int num = read(fp, lev_buf, 3); 
               printf ("num = %d \n",num);
               int i;
               for (i=0; i<num; i++) {
                    if((lev_buf[i] < '0') || (lev_buf[i] > '9')) lev_buf[i] = '\0';
                    else 
                        flag = 1;
               } 
           }while(!flag); 
           printf("Insert your password for the ps_%s user\n", lev_buf);
           printf("Password: \n");
           scanf("%s", buf);
           memset(ps, 0, 4);
           strncpy(ps, "ps_", 3); 
           ptr = strncat(ps, lev_buf, 4);
           close(fp);
           authenticate_system(ptr, buf);  
        }
   exit(EXIT_SUCCESS);
}
