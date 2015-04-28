#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
// Do we need close all?
#define CLOSE_FILE -1
void syscall_init (void);
void close_remove_file (int fd);
#endif /* userprog/syscall.h */
