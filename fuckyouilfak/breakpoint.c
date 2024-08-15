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
 
 breakpoint.c
 
 */

#include "breakpoint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/thread_status.h>
#include <mach/mach_vm.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <mach-o/loader.h>

#include "log.h"

struct breakpoints_q g_breakpoints;

static kern_return_t set_protection(mach_port_t task, mach_vm_address_t address, const char *protection, const uint32_t size);
static vm_prot_t get_protection(mach_port_t task, mach_vm_address_t address);
static vm_prot_t parse_protection(const char * protection);
static const char * unparse_protection(vm_prot_t p);
static kern_return_t write_int3(mach_port_t task, mach_vm_address_t address);

kern_return_t insert_breakpoint(mach_port_t task, mach_vm_address_t address, void* exception_processor, char *processor_name)
{
    kern_return_t kr = 0;
    mach_vm_size_t len = 4;
    vm_offset_t originalopcode = 0;
    mach_msg_type_number_t bytesread = 0;
    
    kr = task_suspend(task);
    if (kr != KERN_SUCCESS) {
        ERROR_MSG("Failed to suspend task for breakpoints");
        return KERN_FAILURE;
    }
    
    // verify if current address is already on the list
    struct breakpoint *el = NULL;
    TAILQ_FOREACH(el, &g_breakpoints, entries) {
        if (el->address == address) {
            break;
        }
    }
    if (el != NULL) {
        ERROR_MSG("Address %p is already into the linked list!", (void*)address);
        // XXX: shouldn't this be KERN_FAILURE ?
        task_resume(task);
        return KERN_SUCCESS;
    }
    
    struct breakpoint *new = malloc(sizeof(struct breakpoint));
    if (new == NULL) {
        ERROR_MSG("Allocation for new element failed!");
        task_resume(task);
        return KERN_FAILURE;
    }
    
    new->address = address;
    TAILQ_INSERT_HEAD(&g_breakpoints, new, entries);
    
    DEBUG_MSG("Inserting software breakpoint at 0x%llx with process %s", address, processor_name);
    // read & store original byte
    kr = mach_vm_read(task, address, len, &originalopcode, &bytesread);
    if (kr != KERN_SUCCESS) {
        ERROR_MSG("Failed to read original bytes at breakpoint address. Error: %d", kr);
        task_resume(task);
        return KERN_FAILURE;
    }
    // copy the original byte into our breakpoints information structure
    new->originalopcode = *(unsigned char *)originalopcode;
    // copy the original permissions into our information structure
    new->originalprotection = get_protection(task, address);
    // modify memory permissions
    set_protection(task, address, "rw-", 1);
    // replace it with int3
    write_int3(task, address);
    // restore original memory permissions
    set_protection(task, address, unparse_protection(new->originalprotection), 1);
    // everything went well so we can add it to the breakpoint list
    new->address = address;
    new->exception_processor = exception_processor;
    size_t name_len = strlen(processor_name) + 1;
    new->name = malloc(name_len);
    strlcpy(new->name, processor_name, name_len);
    kr = mach_vm_deallocate(mach_task_self(), originalopcode, len);
    task_resume(task);
    return KERN_SUCCESS;
}

/*
 * write an int3/brk byte to the target address
 */
static kern_return_t write_int3(mach_port_t task, mach_vm_address_t address)
{
    kern_return_t kr = 0;
    uint8_t opcode = 0xCC;
    mach_msg_type_number_t len = 1;
    // write the int3
    kr = mach_vm_write(task, address, (vm_offset_t)&opcode, len);
    if (kr != KERN_SUCCESS) {
        ERROR_MSG("Failed to write int3 @ 0x%llx", address);
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/*
 * this will parse protection in the format --- (r,w,x)
 * and convert to vm_prot_t so we can pass it to set_protection or something else
 */
static vm_prot_t parse_protection(const char * protection)
{
    // default values
    vm_prot_t read = 0;
    vm_prot_t write = 0;
    vm_prot_t execute = 0;
    // parse the protection input
    if (protection[0] == 'r') {
        read = VM_PROT_READ;
    }
    if (protection[1] == 'w') {
        write = VM_PROT_WRITE | VM_PROT_COPY; // iOS requires this!
    }
    if (protection[2] == 'x') {
        execute = VM_PROT_EXECUTE;
    }
    // and convert it to vm_prot_t type
    return (read | write | execute);
}

static const char * unparse_protection(vm_prot_t p)
{
    switch (p)
    {
        case VM_PROT_NONE:
            return "---";
        case VM_PROT_READ:
            return "r--";
        case VM_PROT_WRITE:
            return "-w-";
        case VM_PROT_READ | VM_PROT_WRITE:
        case VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY:
            return "rw-";
        case VM_PROT_EXECUTE:
            return "--x";
        case VM_PROT_EXECUTE | VM_PROT_READ:
            return "r-x";
        case VM_PROT_EXECUTE | VM_PROT_WRITE:
        case VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_COPY:
            return "-wx";
        case VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_READ:
        case VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_READ | VM_PROT_COPY:
            return "rwx";
        default:
            return "???";
    }
}

/*
 * set the permissions on a given memory address
 */
static kern_return_t set_protection(mach_port_t task, mach_vm_address_t address, const char *protection, const uint32_t size)
{
    kern_return_t kr = 0;
    mach_vm_size_t len = size;
    vm_prot_t new_protection = parse_protection(protection);
    // modify memory permissions
    kr = mach_vm_protect(task, address, len, FALSE, new_protection);
    if (kr != KERN_SUCCESS) {
        ERROR_MSG("Failed to set memory protection: %d", kr);
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/*
 * retrieve the protection flags of any given address
 */
static vm_prot_t get_protection(mach_port_t task, mach_vm_address_t address)
{
    kern_return_t kr = 0;

    vm_region_submap_short_info_data_64_t info;
    mach_vm_size_t size = 0;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t region_depth = 1000;
    kr = mach_vm_region_recurse(task, &address, &size, &region_depth, (vm_region_recurse_info_t) &info, &count);
    if (kr != KERN_SUCCESS) {
        ERROR_MSG("Failed to mach_vm_region @ 0x%llx", address);
        return KERN_FAILURE;
    }
    return info.protection;
}
