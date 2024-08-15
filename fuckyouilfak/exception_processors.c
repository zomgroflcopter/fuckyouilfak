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
 
 exception_processors.c
 
 */

#include "exception_processors.h"

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
#include <mach-o/dyld_images.h>
#include <sys/param.h>

#include "log.h"
#include "memory.h"
#include "symbol.h"

// this function is responsible for handling the breakpoint at NSAddAltHandler2
// essentially we just need to set the return value to 0 and return to the caller immediately
// bypassing execution of this function
kern_return_t process_NSAddAltHandler2(mach_port_t thread, int flavor, thread_state_t old_state, thread_state_t new_state)
{
//    DEBUG_MSG("Hit process_NSAddAltHandler2");
    if (flavor == x86_THREAD_STATE) {
        x86_thread_state_t *ts = (x86_thread_state_t*)old_state;
        if (ts->tsh.flavor == x86_THREAD_STATE64) {
            // set return value to 0
            ts->uts.ts64.__rax = 0;
            // we are at the beginning of the function but didn't execute anything yet
            // so current stack position contains the return address
            // so we need to read the content of the stack to find the return address
            mach_vm_address_t read_addr = ts->uts.ts64.__rsp;
            uint8_t *buf = read_memory(thread, read_addr, 8);
            if (buf == NULL) {
                ERROR_MSG("Failed to read dyld info array");
                return KERN_FAILURE;
            }
            DEBUG_MSG("Return address is 0x%llx", *(uint64_t*)buf);
            // set RIP to the return address
            ts->uts.ts64.__rip = *(uint64_t*)buf;
            // don't forget to pop the return address from stack
            ts->uts.ts64.__rsp += 8;
            // avoid memory leak from our stack read
            mach_vm_deallocate(mach_task_self(), (vm_offset_t)buf, 8);
        }
        // update the thread state so execution can resume
        memcpy(new_state, old_state, sizeof(x86_thread_state_t));
        return KERN_SUCCESS;
    }
    ERROR_MSG("Unsupported flavor...");
    return KERN_FAILURE;
}

// breakpoint the place where IDA creates a new instance and fix the string to point to our loader
kern_return_t process_launch(mach_port_t thread, int flavor, thread_state_t old_state, thread_state_t new_state)
{
//    DEBUG_MSG("Hit process_launch");
    if (flavor == x86_THREAD_STATE) {
        x86_thread_state_t *ts = (x86_thread_state_t*)old_state;
        if (ts->tsh.flavor == x86_THREAD_STATE64) {
            // we are sitting at the call to _launch_process
            // if we disassemble and debug ida64 binary, we can observe that RDI contains a structure
            // with the data that we want to modify
            // 16 bytes from the base address in RDI we can find the pointer to the binary path
            // so we just want to insert a NUL byte to make it point to the ida64 loader instead of ida64orig binary
            mach_vm_address_t rdi = ts->uts.ts64.__rdi;
            // the original path is 59 chars long (assuming default naming!)
            // so we need to write a NUL byte at position 60
            
            // first lets find the pointer to the string
            mach_vm_address_t read_addr = rdi + 0x10;
            uint8_t *buf = read_memory(thread, read_addr, 8);
            if (buf == NULL) {
                ERROR_MSG("Failed to read dyld info array");
                return KERN_FAILURE;
            }
            DEBUG_MSG("Launch path string pointer is 0x%llx", *(uint64_t*)buf);
            // now we want to write a NUL byte at *(uint64_t*)buf + 59
            uint8_t opcode = 0x0;
            mach_msg_type_number_t len = 1;
            mach_vm_address_t write_addr = *(uint64_t*)buf + 59;
            // write the int3
            kern_return_t kr = mach_vm_write(thread, write_addr, (vm_offset_t)&opcode, len);
            if (kr != KERN_SUCCESS) {
                ERROR_MSG("Failed to write NUL @ 0x%llx", write_addr);
                return KERN_FAILURE;
            }
            // the instruction we breakpoint is mov rsi, rsp
            // so we just emulate it
            ts->uts.ts64.__rsi = ts->uts.ts64.__rsp;
            // advance rip to next instruction
            // original instruction is 3 bytes but we are one byte ahead because of int3
            ts->uts.ts64.__rip +=2;
            // avoid memory leak from our stack read
            mach_vm_deallocate(mach_task_self(), (vm_offset_t)buf, 8);
        }
        // update the thread state so execution can resume
        memcpy(new_state, old_state, sizeof(x86_thread_state_t));
        return KERN_SUCCESS;
    }
    ERROR_MSG("Unsupported flavor...");
    return KERN_FAILURE;
}
