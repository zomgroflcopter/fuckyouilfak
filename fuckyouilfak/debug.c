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
 
 debugger.c
 
 */

#include "debug.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <debugger_mach.h>
#include <debugger_machServer.h>

#include "memory.h"
#include "breakpoint.h"
#include "exception_processors.h"

mach_port_t g_exceptionPort;
extern struct breakpoints_q g_breakpoints;

extern boolean_t mach_exc_server(mach_msg_header_t *request,mach_msg_header_t *reply);
static void debug_loop(void);

typedef __Request__mach_exception_raise_state_identity_t exc_msg_t;
typedef __Reply__mach_exception_raise_state_identity_t reply_msg_t;

/* this will install the debug port into the target task */
int install_debugger(pid_t pid, task_t *target_task_port)
{
    DEBUG_MSG("Trying to install debugger on PID %d", pid);
    kern_return_t kr = 0;
    /* exception mask related only to breakpoints */
    exception_mask_t mask = EXC_MASK_ALL;
    /* get a send right */
    mach_port_t myself = mach_task_self();
    /* create a receive right in our task */
    if ( (kr = mach_port_allocate(myself, MACH_PORT_RIGHT_RECEIVE, &g_exceptionPort)) ) {
        ERROR_MSG("mach_port_allocate failed: %d.", kr);
        return -1;
    }
    /* insert a send right: we will now have combined receive/send rights */
    if ( (kr = mach_port_insert_right(myself, g_exceptionPort, g_exceptionPort, MACH_MSG_TYPE_MAKE_SEND)) ) {
        ERROR_MSG("mach_port_insert_right failed: %d.", kr);
        return -1;
    }
    /* retrieve the target task of our target process */
    if ( (kr = task_for_pid(myself, pid, target_task_port)) != KERN_SUCCESS) {
        ERROR_MSG("retrieving task for pid! Do you have the correct permissions? Error: 0x%x", kr);
        return -1;
    }
    /* add an exception port in the target */
    if ( (kr = task_set_exception_ports(*target_task_port, mask, g_exceptionPort, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, MACHINE_THREAD_STATE)) ) {
        ERROR_MSG("thread_set_exception_ports failed: %d.", kr);
        return -1;
    }
    /* create the debugger thread and start it */
    pthread_t exception_thread;
    if ((pthread_create(&exception_thread, (pthread_attr_t*)0, (void *(*)(void *))debug_loop, (void*)0))) {
        ERROR_MSG("Can't create debugger thread.");
        return -1;
    }
    pthread_detach(exception_thread);
    return 0;
}

/*
 * the debug loop in a new thread that will be responsible for receiving and delivering the mach messages
 * mach_exc_server does the delivery magic
 */
static void debug_loop(void)
{
    kern_return_t kr = 0;
    exc_msg_t   msg_recv = {0};
    reply_msg_t msg_resp = {0};
    /* loop forever, receiving and sending the exception mach messages */
    while (1) {
        msg_recv.Head.msgh_local_port = g_exceptionPort;
        msg_recv.Head.msgh_size = sizeof(msg_recv);
        
        kr = mach_msg(&(msg_recv.Head),                 // message
                      MACH_RCV_MSG|MACH_RCV_LARGE,      // options -> timeout MACH_RCV_TIMEOUT
                      0,                                // send size (irrelevant here)
                      sizeof(msg_recv),                 // receive limit
                      g_exceptionPort,                  // port for receiving
                      0,                                // no timeout
                      MACH_PORT_NULL);                  // notify port (irrelevant here)
        
        if (kr == MACH_RCV_TIMED_OUT) {
            ERROR_MSG("Receive message timeout!");
            continue;
        } else if (kr != MACH_MSG_SUCCESS) {
            ERROR_MSG("Got bad Mach message on receive!");
            continue;
        }
        /* dispatch the message */
        mach_exc_server(&msg_recv.Head, &msg_resp.Head);
        /* now msg_resp.RetCode contains return value of catch_exception_raise_state_identify() */
        kr = mach_msg(&(msg_resp.Head),             // message
                      MACH_SEND_MSG,                // options -> timeout MACH_SEND_TIMEOUT
                      msg_resp.Head.msgh_size,      // send size
                      0,                            // receive limit (irrelevant here)
                      MACH_PORT_NULL,               // port for receiving (none)
                      0,                            // no timeout
                      MACH_PORT_NULL);              // notify port (we don't want one)
        
        if (kr == MACH_SEND_TIMED_OUT) {
            ERROR_MSG("Send message timeout!");
            continue;
        } else if (kr != MACH_MSG_SUCCESS) {
            ERROR_MSG("Got bad Mach message on response!");
            continue;
        }
    }
}

/* this is just here because compiler complaints... */
extern kern_return_t
catch_mach_exception_raise(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, mach_exception_data_t code, mach_msg_type_number_t codeCnt)
{
    return KERN_FAILURE;
}

/* this is just here because compiler complaints... */
extern kern_return_t catch_mach_exception_raise_state(mach_port_t exception_port, exception_type_t exception, const mach_exception_data_t code, mach_msg_type_number_t codeCnt, int *flavor, const thread_state_t old_state, mach_msg_type_number_t old_stateCnt, thread_state_t new_state, mach_msg_type_number_t *new_stateCnt)
{
    return KERN_FAILURE;
}

/*
 * the function that receives the exceptions
 * this version receives the thread state and sets the new one
 * we avoid calls to thread_get_state and thread_set_state, improving performance
 */
extern kern_return_t
catch_mach_exception_raise_state_identity (mach_port_t exception_port,
                                           mach_port_t thread,
                                           mach_port_t task,
                                           exception_type_t exception,
                                           mach_exception_data_t code,
                                           mach_msg_type_number_t codeCnt,
                                           int *flavor,
                                           thread_state_t old_state,
                                           mach_msg_type_number_t old_stateCnt,
                                           thread_state_t new_state,
                                           mach_msg_type_number_t *new_stateCnt)
{
#pragma unused(exception_port)
#pragma unused(task)
    // retrieve current IP - we don't really need this much other than x86
    mach_vm_address_t eip = 0;
    if (*flavor == x86_THREAD_STATE) {
        x86_thread_state_t *ts = (x86_thread_state_t*)old_state;
        switch (ts->tsh.flavor) {
            case x86_THREAD_STATE64:
                eip = ts->uts.ts64.__rip;
                break;
            default:
                ERROR_MSG("Unknown thread state...Dying!!!");
                exit(1);
        }
    }
    
    // process whatever exceptions we get
    // while developing it's useful to retrieve fault addresses on error exceptions
    // and other information to help debugging any problems
    // here we just give up to simplify things
    switch (exception) {
        case EXC_BAD_ACCESS:
            ERROR_MSG("Unhandled EXC_BAD_ACCESS");
            return KERN_FAILURE;

        case EXC_BAD_INSTRUCTION:
            ERROR_MSG("Unhandled bad instruction @ 0x%llx", eip);
            return KERN_FAILURE;

        case EXC_BREAKPOINT:
        {
//            DEBUG_MSG("[+] Software breakpoint hit at 0x%llx", eip);
            /* int3 EIP/RIP is one byte ahead */
            eip--;
            struct breakpoint *el = NULL;
            // check if we know this breakpoint and pass control to its exception handler
            TAILQ_FOREACH(el, &g_breakpoints, entries) {
                if (el->address == eip) {
                    /* update the state count here */
                    *new_stateCnt = MACHINE_THREAD_STATE_COUNT;
                    /* the exception processor needs to set the new_state and new_stateCnt to updated values else CABOOOM */
                    return el->exception_processor(task, *flavor, old_state, new_state, el);
                }
            }
            /* unreachable under normal conditions */
            ERROR_MSG("Unhandled software breakpoint @ 0x%llx", eip);
            return KERN_FAILURE;
        }
        default:
            ERROR_MSG("Can't process exception %d at address 0x%llx...", exception, eip);
            /* pass control to system crash reporter */
            return KERN_FAILURE;
    }
}
