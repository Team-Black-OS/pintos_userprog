#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "lib/kernel/console.h"
#include "lib/user/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <string.h>
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
static struct lock file_lock;
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int* sys_call_number = (int*) f->esp;
  validate(sys_call_number);
  //printf("System call number is: %d\n",*sys_call_number);
  switch(*sys_call_number){
    case SYS_HALT: {
      //printf("Halt!\n");
      shutdown_power_off();
      break;
    }
    case SYS_EXIT: {
      int *exit_code = (int*) ((char*)f->esp + 4);
      validate(exit_code);
      int retval = *exit_code;
      f->eax = retval;
      exit(retval);
      break;
    }
    case SYS_EXEC: {
      char** raw = (char**) ((char*)f->esp+4);
      validate(raw);
      validate(*raw);
      for(int i = 0; i < strlen(*raw); ++i){
        validate(*raw + i);
      }
      f->eax = process_execute(*raw);
      break;
    }
    case SYS_WAIT: {
      pid_t *wait_pid = (pid_t*) ((char*)f->esp + 4);
      validate(wait_pid);
      //printf("Waiting for thread: %d\n",wait_pid);
      f->eax = process_wait(*wait_pid);
      break;
    }
    case SYS_CREATE: {

      char** raw = (char**) ((char*)f->esp+4);
      validate(raw);
      validate(*raw);
      for(int i = 0; i < strlen(*raw); ++i){
        validate(*raw + i);
      }
      unsigned *size = (unsigned*) ((char*)f->esp+8);
      validate(size);
      f->eax = s_create(*raw,*size);
      break;
    }
    case SYS_REMOVE: {
      char** raw = (char**) ((char*)f->esp+4);
      validate(raw);
      validate(*raw);
      for(int i = 0; i < strlen(*raw); ++i){
      validate(*raw + i);
      }
      f->eax = s_remove(*raw);
      break;
    }
    case SYS_OPEN: {
      char** raw = (char**) ((char*)f->esp+4);
      validate(raw);
      validate(*raw);
      for(int i = 0; i < strlen(*raw); ++i){
        validate(*raw + i);
      }
      f->eax = s_open(*raw);
      break;
    }
    case SYS_FILESIZE: {
      int *fd = (int*) ((char*)f->esp +4);
      validate(fd);

      f->eax = s_filesize(*fd);

      break;
    }
    case SYS_READ: {
      int* fd = (int*) ((char*)f->esp +4);
      char** raw = (char**) ((char*)f->esp+8);
      unsigned* size = (unsigned*) ((char*)f->esp + 12);
      validate(fd);
      validate(raw);
      validate(size);
      for(int i = 0; i < *size; ++i){
      validate(*raw+i);
      }

      f->eax = s_read(*fd,*raw,*size);

      break;
    }
    case SYS_WRITE: {
      int* fd = (int*) ((char*)f->esp + 4);
      validate(fd);

      unsigned* size = (unsigned*) ((char*)f->esp + 12);
      validate(size);

      char** raw = (char**) ((char*)f->esp+8);
      validate(raw);
      validate(*raw);
      for(int i = 0; i < *size; ++i){
        validate(*raw + i);
      }

      f->eax = s_write(*fd,*raw,*size);

      break;
    }
    case SYS_SEEK: {
      int* fd = (int*) ((char*)f->esp + 4);
      validate(fd);
      unsigned* pos = (unsigned*) ((char*)f->esp + 8);
      validate(pos);
      s_seek(*fd,*pos);
      break;
    }
    case SYS_TELL: {
      int* fd = (int*) ((char*)f->esp + 4);
      validate(fd);
      f->eax = s_tell(*fd);
      break;
    }
    case SYS_CLOSE: {
      int* fd = (int*) ((char*)f->esp + 4);
      validate(fd);
      s_close(*fd);
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
  //t->parent_share->ref_count -= 1;
  thread_exit();
}

int s_open(char* file){
    lock_acquire(&file_lock);
    struct thread *t = thread_current();
    int retval;
    struct file* op = filesys_open(file);
    struct file_map* fm = (struct file_map*) malloc(sizeof(struct file_map));
    if(op == NULL){
      retval = -1;
    }else{
      fm->fd = ++t->next_fd;
      fm->file = op;
      list_push_back(&t->files,&fm->file_elem);
      retval = fm->fd;
    }
    lock_release(&file_lock);
    return retval;
}

int s_create(char* file, unsigned size) {
    lock_acquire(&file_lock);
    int retval;
    retval = filesys_create(file,size);
    lock_release(&file_lock);
    return retval;
}

int s_filesize(int fd) {
    lock_acquire(&file_lock);
    int retval = -1;
    struct thread* t = thread_current();
    struct list_elem *e;
    for (e = list_begin (&t->files); e != list_end (&t->files);
      e = list_next (e))
      {
        struct file_map* fmp = list_entry (e, struct file_map, file_elem);
        if(fmp->fd == fd){
            retval = file_length(fmp->file);
            break;
          }
      
      }
    lock_release(&file_lock);
    return retval;
}
int s_read(int fd, char* buf, unsigned size){
    lock_acquire(&file_lock);
    // Initialize retval to 0.
    int retval = 0;
    // Check if this is a console read.
    if(fd == 0){
      for(int i = 0; i < size; ++i){
        buf[i] = input_getc();
      }
        retval = size;
    }
    // Otherwise, it is a file read. Search for the file in the thread's
    // file descriptor list.
    else{
      struct thread* t = thread_current();
      struct list_elem *e;
      for (e = list_begin (&t->files); e != list_end (&t->files);
        e = list_next (e))
        {
          struct file_map* fmp = list_entry (e, struct file_map, file_elem);
          if(fmp->fd == fd){
            // If found read the file.
            retval = file_read(fmp->file,buf,size);
            break;
          }
        }
    }
    lock_release(&file_lock);
    // Return the number of bytes read.
    return retval;
}
int s_write(int fd, char* buf, unsigned size){
      lock_acquire(&file_lock);
      // Initialize return value to 0.
      int retval = 0;
      // If this is a console write, call putbuf().
      if (fd == 1){
        putbuf(buf,size);
        retval = size;
      }
      // Otherwise, this is a file write, so search for the correct file
      // descriptor in the thread's file_map.
      else{
        struct thread* t = thread_current();
        struct list_elem *e;
        for (e = list_begin (&t->files); e != list_end (&t->files);
          e = list_next (e))
          {
            struct file_map* fmp = list_entry (e, struct file_map, file_elem);
            if(fmp->fd == fd){
              // Write to the file if found.
              retval = file_write(fmp->file,buf,size);
              break;
            }
          }
      }
      lock_release(&file_lock);
      return retval;
}

void s_seek(int fd, unsigned position){
    lock_acquire(&file_lock);
    struct thread* t = thread_current();
    struct list_elem *e;
    for (e = list_begin (&t->files); e != list_end (&t->files);
      e = list_next (e))
      {
        struct file_map* fmp = list_entry (e, struct file_map, file_elem);
        if(fmp->fd == fd){
            file_seek(fmp->file,position);
            break;
        }
      }
    lock_release(&file_lock);
}

unsigned s_tell(int fd) {
    struct thread* t = thread_current();
    struct list_elem *e;
    int retval = 0;
    lock_acquire(&file_lock);
    for (e = list_begin (&t->files); e != list_end (&t->files);
      e = list_next (e))
      {
        struct file_map* fmp = list_entry (e, struct file_map, file_elem);
        if(fmp->fd == fd){
            retval = file_tell(fmp->file);
            break;
        }
      }
    lock_release(&file_lock);
    return retval;
}

void s_close(int fd){
    struct thread* t = thread_current();
    lock_acquire(&file_lock);
    if(fd != 0 && fd != 1){
      struct list_elem *e;
      for (e = list_begin (&t->files); e != list_end (&t->files);
        e = list_next (e))
        {
          struct file_map* fmp = list_entry (e, struct file_map, file_elem);
          if(fmp->fd == fd){
            list_remove(e);
            file_close(fmp->file);
            free(fmp);
            break;
          }
        }
    }
    lock_release(&file_lock);
}

int s_remove(char* name){
    lock_acquire(&file_lock);
    int retval;
    retval = filesys_remove(name);
    lock_release(&file_lock);
    return retval;
}

void validate(void* addr){
  for(int i = 0; i < 4; ++i){
    if(addr+i == NULL || !is_user_vaddr(addr+i) || pagedir_get_page(thread_current()->pagedir,addr+i) == NULL){
      exit(-1);
    }
  }
}