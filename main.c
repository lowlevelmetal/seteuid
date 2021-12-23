/*
 * main.c
 * seteuid
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <grp.h>
#include <fcntl.h>

#define FATAL(str, ...) { \
    fprintf(stderr, str "\nerrno: %s\n", strerror(errno), ##__VA_ARGS__); \
    exit(EXIT_FAILURE); \
}

#define USAGE(str, ...) { \
    printf(str "\n", ##__VA_ARGS__); \
    exit(EXIT_SUCCESS); \
}

#define SETEUID_FILE "/etc/seteuid"

__attribute__((always_inline)) inline void *
inec_malloc(const unsigned int size) {
    void *ptr = malloc(size);
    if(ptr == NULL) FATAL("malloc()");
    memset(ptr, 0, size);
    return ptr;
}

static void *
ec_malloc(const unsigned int size) {
    return inec_malloc(size);
}

static struct spwd *
spwd_from_username(const char *name) {
    struct spwd *sPwd;
    char *endptr;
    unsigned long s;

    if (name == NULL || *name == '\0')
        return NULL;

    s = strtol(name, &endptr, 10);
    if(endptr == NULL || *endptr == '\0')
        return NULL;

    if (s)
        sPwd = getspnam(endptr);
    else
        sPwd = getspnam(name);

    return (sPwd == NULL) ? NULL : sPwd;
}

static int
filelen(const int fd) {
    int cur_pos = lseek(fd, 0, SEEK_CUR);
    if(cur_pos == -1) FATAL("lseek()");

    lseek(fd, 0, SEEK_SET);
    int len = lseek(fd, 0, SEEK_END);
    lseek(fd, cur_pos, SEEK_SET);

    return len - 1;
}

static char
is_user_seteuid(const char * const name) {
    int fd = open(SETEUID_FILE, O_RDONLY);
    if(fd == -1) FATAL("open()");

    int len = filelen(fd);
    int ret = 0;

    char *fbuf = (char *)ec_malloc(len + 1);
    if(read(fd, fbuf, len) != len) FATAL("read");

    {
        char *ptr = fbuf;
        int count = 0;
        for(; (ptr = strstr(ptr, "\n")) != NULL; count++) {
            *ptr = 0;
            ptr++;
        }

        ptr = fbuf;
        for(int i = 0; i < count; i++) {
            if(strcmp(name, ptr) == 0) {
                ret = 1;
                printf("%s is seteuid capable\n", name);
                break;
            }

            ptr = ptr + strlen(ptr) + 1;
        }
    }

    free(fbuf); 
    close(fd);

    return ret;
}

static char check_uid(const char * const name) {
    struct passwd *p_pwd = getpwnam(name);
    if(p_pwd == NULL) FATAL("getpwnam()");

    if(p_pwd->pw_uid != getuid()) return 0;

    return 1;
}

int main(int argc, char **argv, char **envp) {
    char *envp_path = NULL;
    char *user = getenv("USER");
    if(user == NULL) FATAL("getenv()");

    if(argc < 2) USAGE("%s [COMMAND...]", argv[0]);

    if(check_uid(user) == 0) {
        fprintf(stderr, "Nice try jackass\n");
        exit(EXIT_FAILURE);
    }
    
    if(is_user_seteuid(user) == 0) {
         fprintf(stderr, "User not seteuid!\n");
         exit(EXIT_FAILURE);
    } 

    if(seteuid(0) == -1) FATAL("Failed to set euid!");

    struct spwd *p_spwd = spwd_from_username(user);
    if(p_spwd == NULL) FATAL("spwd_from_username()");

    char *password = getpass("Enter seteuid password: ");
    char *encrypted = crypt(password, p_spwd->sp_pwdp);

    if(strcmp(encrypted, p_spwd->sp_pwdp) != 0) {
        fprintf(stderr, "Incorrect password entered\n");
        exit(EXIT_FAILURE);
    }

    // Create argument list
    char **cmd = (char **)ec_malloc(sizeof(char *) * argc);
    
    for(int i = 1; i < argc; i++) {
        cmd[i-1] = (char *)inec_malloc(strlen(argv[i]) + 1);
        strcpy(cmd[i-1], argv[i]);
    }

    // Attempt exec
    if(execve(*cmd, cmd, envp) == -1) {
        // If failed: look for binary in $PATH
        if((envp_path = getenv("PATH")) == NULL) FATAL("PATH env var does not exist");
       
        // Cut $PATH into multiple strings
        unsigned int count = 0;
        char *ptr = envp_path;
        while((ptr = strstr(ptr, ":")) != NULL) {
            *ptr = 0;
            count++;
            ptr++;
        }

        // Loop through string list and retry exec
        ptr = envp_path;
        
        {
            unsigned int i = 0;
            for(; i < count; i++) {
                ptr = ptr + (strlen(ptr) + 1);

                free(cmd[0]);
                cmd[0] = (char *)inec_malloc(strlen(ptr) + 1 + strlen(argv[1]));
                sprintf(cmd[0], "%s/%s", ptr, argv[1]);
            
                if(execve(*cmd, cmd, envp) != -1)
                    break;
            }

            if(i == count) FATAL("Could not find executable");
        }
    }

    for(int i = 0; i < argc - 1; i++) free(cmd[i]);

    free(cmd);

    return EXIT_SUCCESS;
}
