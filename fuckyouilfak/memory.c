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
 
 memory.c
 
 */

#include "memory.h"

#include <stdio.h>

#include "log.h"

uint8_t *
read_memory(task_t task, mach_vm_address_t address, mach_vm_size_t size)
{
    mach_msg_type_number_t bytesread;
    vm_offset_t buf;
    
    kern_return_t kr = mach_vm_read(task, (mach_vm_address_t)address, size, &buf, &bytesread);
    if (kr != KERN_SUCCESS) {
        ERROR_MSG("Error reading memory. Error: 0x%x", kr);
        return NULL;
    }
    return (uint8_t*)buf;
}