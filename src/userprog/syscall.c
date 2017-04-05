#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/kernel/console.h"
#include "userprog/process.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int* sys_call_number = (int*) f->esp;
  //printf("System call number is: %d\n",*sys_call_number);
  switch(*sys_call_number){
    case SYS_HALT: {
      printf("Halt!\n");
      shutdown_power_off();
      break;
    }
    case SYS_EXIT: {
      printf("Exit call!\n");
      process_exit();
      break;
    }
    case SYS_EXEC: {
      break;
    }
    case SYS_WAIT: {
      break;
    }
    case SYS_CREATE: {
      break;
    }
    case SYS_REMOVE: {
      break;
    }
    case SYS_OPEN: {
      break;
    }
    case SYS_FILESIZE: {
      break;
    }
    case SYS_READ: {
      break;
    }
    case SYS_WRITE: {
      int* fd = (int*) (f->esp + 4);
      char* buffer = *((char**) (f->esp + 8));
      unsigned size = *((unsigned*) (f->esp+12));
     // printf("Write Call!\n");
      int retval = 0;
      if (*fd == 1){
        //printf("Write to Console:\n");
        putbuf(buffer,size);
        retval = size;
      }
      f->eax = retval;
      break;
    }
    case SYS_SEEK: {
      break;
    }
    case SYS_TELL: {
      break;
    }
    case SYS_CLOSE: {
      break;
    }
    default: {
      // Code for bad system call number goes here.
      break;
    }
  }
}
