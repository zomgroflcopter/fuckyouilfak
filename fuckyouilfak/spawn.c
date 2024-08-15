/*
 ___________             __     _____.___.
 \_   _____/_ __   ____ |  | __ \__  |   | ____  __ __
  |    __)|  |  \_/ ___\|  |/ /  /   |   |/  _ \|  |  \
  |     \ |  |  /\  \___|    <   \____   (  <_> )  |  /
  \___  / |____/  \___  >__|_ \  / ______|\____/|____/
      \/              \/     \/  \/
 .___.__   _____        __     ._.
 |   |  |_/ ____\____  |  | __ | |
 |   |  |\   __\\__  \ |  |/ / | |
 |   |  |_|  |   / __ \|    <   \|
 |___|____/__|  (____  /__|_ \  __
                     \/     \/  \/
 Fuck You Ilfak!
 IDA Pro 9.0 Beta 2 macOS x64 Fix Loader
 (c) fG! 2024 - reverser@put.as - https://reverse.put.as
 
 spawn.c
 
 */

#include "spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <dlfcn.h>
#include <signal.h>
#include <mach-o/loader.h>
#include <spawn.h>
#include <fcntl.h>
#include <pwd.h>
#include <uuid/uuid.h>
#include <sys/param.h>

#include "log.h"

#define _POSIX_SPAWN_DISABLE_ASLR 0x100

 // setup the environment variables
char ** generate_spawn_env(void)
{
    /*
     char *spawnedEnv[] = { "HOME=/Users/username", "USER=username", "LOGNAME=username", "LC_CTYPE=UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", NULL };
     */
    int env_size = 5 + 1; // +1 is for NULL termination
    uid_t uid = geteuid();
    struct passwd *uid_pw = getpwuid(uid);
    static char home[MAXPATHLEN] = {0};
    static char user[MAXPATHLEN] = {0};
    static char logname[MAXPATHLEN] = {0};
    static char path[MAXPATHLEN] = {0};
    static char lc[MAXPATHLEN] = {0};
    snprintf(home, sizeof(home), "HOME=/Users/%s", uid_pw->pw_name);
    snprintf(user, sizeof(user), "USER=%s", uid_pw->pw_name);
    snprintf(logname, sizeof(logname), "LOGNAME=%s", uid_pw->pw_name);
    snprintf(path, sizeof(path), "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    snprintf(lc, sizeof(lc), "LC_CTYPE=UTF-8");
    char **env_array = malloc(sizeof(char*) * env_size);
    // keep in sync with env_size
    env_array[0] = home;
    env_array[1] = user;
    env_array[2] = logname;
    env_array[3] = path;
    env_array[4] = lc;
    env_array[5] = NULL;
    return env_array;
}

pid_t spawn_new_process(const char *input_filename)
{
    int fd = 0;
    fd = open(input_filename, O_RDONLY);
    if (fd < 0) {
        ERROR_MSG("Failed to open target %s. Error: %s.", input_filename, strerror(errno));
        return -1;
    }
    
    uint32_t magic = 0;
    if (read(fd, &magic, 4) != 4) {
        ERROR_MSG("Failed to read magic from target file.");
        close(fd);
        return -1;
    }
    close(fd);
    
    char *spawnedArgv[] = { (char*)input_filename, (char *)0 };
    char **spawnedEnv = generate_spawn_env();
    
    /* pid will contain the PID of the spawned process if successful */
    pid_t pid;
    posix_spawnattr_t attr;
    sigset_t signal_mask_set;
    size_t copied=1;
    int ret = 0;
    ret = posix_spawnattr_init(&attr);
    if (ret != 0) {
        ERROR_MSG("posix_spawnattr_init returned %d", ret);
        return -1;
    }
    sigemptyset(&signal_mask_set);
    ret = posix_spawnattr_setsigmask(&attr, &signal_mask_set);
    if (ret != 0) {
        ERROR_MSG("posix_spawnattr_setsigmask returned %d", ret);
        return -1;
    }
    ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_DISABLE_ASLR);
    if (ret != 0) {
        ERROR_MSG("posix_spawnattr_setflags returned %d", ret);
        return -1;
    }
    
    /* set the cpu type otherwise we might get wrong arch errors (error 86) */
    cpu_type_t cpu;
    switch (magic) {
        case MH_MAGIC_64:
            cpu = CPU_TYPE_X86_64;
            break;
        default:
            ERROR_MSG("Invalid arch.");
            return -1;
    }
    ret = posix_spawnattr_setbinpref_np(&attr, 1, &cpu, &copied);
    if (ret != 0) {
        ERROR_MSG("posix_spawnattr_setbinpref_np returned %d", ret);
        return -1;
    }
    
    DEBUG_MSG("Executing spawn...");
    ret = posix_spawn(&pid, input_filename, NULL, &attr, spawnedArgv, spawnedEnv);
    posix_spawnattr_destroy (&attr);
    
    if (ret != 0) {
        switch (ret) {
            case EACCES:
                ERROR_MSG("Please check target binary permissions, probably not executable.");
                break;
            case EBADMACHO:
                ERROR_MSG("Bad macho file. Maybe no PAGEZERO segment?");
                break;
            default:
                ERROR_MSG("posix_spawn() failed: %d.", ret);
                break;
        }
        return -1;
    }
    
    /* everything went fine so return the new PID to the caller */
    DEBUG_MSG("Spawned process with PID %d", pid);
    return pid;
}
