#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
void syscall_init (void);
void exit(int);

// Accepts an address, calls exit(-1) if the address is out of range
void validate(void* addr);

// Reads from a file represented by fd.
int s_read(int fd, char* buf, unsigned size);

// Writes to a file represented by fd.
int s_write(int fd, char* buf, unsigned size);
#endif /* userprog/syscall.h */
