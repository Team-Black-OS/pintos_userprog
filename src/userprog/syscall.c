#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

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
  printf("System call number is: %d\n",*sys_call_number);
  switch(*sys_call_number){
    case SYS_HALT: {
      break;
    }
    case SYS_EXIT: {
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
      int* fd = (int*) (f->esp - 4);
      char* buffer = (char*) (f->esp - 8);
      unsigned* size = (unsigned*) (f->esp-12);
      printf("Current Values: fd: %d, buffer: %s, size: %d",*fd,buffer,*size);
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
  thread_exit ();
}
