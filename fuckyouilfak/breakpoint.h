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
 
 breakpoint.h
 
 */

#pragma once

#include <stdio.h>
#include <sys/queue.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/thread_status.h>

struct breakpoint
{
    TAILQ_ENTRY(breakpoint) entries;
    kern_return_t (*exception_processor)(mach_port_t port, int flavor, thread_state_t old_state, thread_state_t new_state, struct breakpoint *bp);
    char *name;                    // exception processor name
    mach_vm_address_t address;
    vm_offset_t originalopcode;    // needs to be mach_vm_deallocate'd
    vm_prot_t originalprotection;  // original memory protection
};

TAILQ_HEAD(breakpoints_q, breakpoint);

kern_return_t insert_breakpoint(mach_port_t task, mach_vm_address_t address, void* exception_processor, char *processor_name);
