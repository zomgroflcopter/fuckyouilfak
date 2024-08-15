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
 
 main.c
 
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <mach/mach.h>
#include <mach/task.h>

#include "log.h"
#include "spawn.h"
#include "debug.h"
#include "symbol.h"
#include "breakpoint.h"
#include "exception_processors.h"

int main(int argc, const char * argv[]) {
    char *input_file = "/Applications/IDA Professional 9.0.app/Contents/MacOS/ida64orig";
    // spawn the target process in suspended state
    pid_t new_pid = spawn_new_process(input_file);
    if (new_pid < 0) {
        ERROR_MSG("Failed to spawn new process.");
        return EXIT_FAILURE;
    }
    // we love task_for_pid() !!!!!
    task_t target_task_port;
    if (install_debugger(new_pid, &target_task_port) < 0) {
        ERROR_MSG("Failed to install debugger.");
        return EXIT_FAILURE;
    }
    /*
     * since we passed POSIX_SPAWN_START_SUSPENDED when starting the debugee, it is stopped at _dyld_start
     * we can do whatever we want to it :-)
     * in this case we just want to find the symbol where we want to breakpooint and resume execution
     * because of the dyld shared cache we don't need to install a image notifier to get a callback
     * when the right image is mapped into the process
     */
    mach_vm_address_t handler = find_dyldcache_symbol("__NSAddAltHandler2");
    if (handler == 0) {
        ERROR_MSG("Failed to find NSAddAltHandler2 symbol. Can't proceed!");
        // we don't need to kill the debugee process in case of error
        return EXIT_FAILURE;
    }
    // insert the breakpoint with the exception processor that will handle it
    // we will just fix the return value and return early from the function to skip its execution
    // and that's it :-)
    kern_return_t kr = insert_breakpoint(target_task_port, handler, process_NSAddAltHandler2, "NSAddAltHandler2");
    if (kr != KERN_SUCCESS) {
        ERROR_MSG("Failed to insert breakpoint. Can't proceed!");
        return EXIT_FAILURE;
    }
    // we need to breakpoint the new instance process launch because otherwise IDA will execute a copy of itself
    // and not our loader so that only the original instance we be fixed
    // we go the easy way and hack the _launch_process call where the binary path is and modify it to point to our loader again
    // since we are targetting a very specific version we can hardcode and cheat like this :PPPP
    // ah, and ASLR is disabled on our spawn so this is why it's easy to cheat
    // we can handle this with ASLR, just find the slide and fix these values
    // the address is one instruction before the call because it's easier to emulate and avoid extra work :PPP
    kr = insert_breakpoint(target_task_port, 0x100167F93, process_launch, "IDA_launch_process");
    
    // let the debugee resume execution - we take control when breakpoint is hit
    kill(new_pid, SIGCONT);
    int status;
    DEBUG_MSG("Waiting for spawned process to end...");
    waitpid(new_pid, &status, 0);
    DEBUG_MSG("Spawned process is over, all done!");
    return 0;
}
