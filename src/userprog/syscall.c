#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/kernel/console.h"
#include "lib/user/syscall.h"
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
      int *exit_code = (int*) (f->esp + 4);
      int retval = *exit_code;
      f->eax = retval;
      exit(retval);
      break;
    }
    case SYS_EXEC: {
      //printf("Execute call:\n");
      char* buffer = *((char**) (f->esp + 4));
      printf("Executing: %s\n",buffer);
      f->eax = process_execute(buffer);
      printf("After execution.\n");
      break;
    }
    case SYS_WAIT: {
      pid_t wait_pid = *((pid_t*) (f->esp + 4));
      printf("Waiting for thread: %d\n",wait_pid);
      process_wait(wait_pid);
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
      unsigned size = *((unsigned*) (f->esp + 12));
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
void exit(int exit_code){
  struct thread *t = thread_current();
  t->parent_share->exit_code = exit_code;
  t->parent_share->ref_count -= 1;
  char* thr_name = thread_name();
  printf("%s: exit(%d)\n",thr_name,exit_code);
  sema_up(&thread_current()->wait_sema);
  thread_exit();
}