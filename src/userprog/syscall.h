#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
void syscall_init (void);
void exit(int);

// Accepts an address, calls exit(-1) if the address is out of range
void validate(void* addr);
#endif /* userprog/syscall.h */
