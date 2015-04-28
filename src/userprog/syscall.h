#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
// Do we need close all?
#define CLOSE_FILE -1
#define ERROR -1

struct child{
  int pid;
  bool wait;
  bool exit;
  int load;
  int status;

  struct lock waitLock;
  struct list_elem listElem;
}

void syscall_init (void);
void close_remove_file (int fd);

struct child *get_child (int pid);
void delete_child (int pid); 
#endif /* userprog/syscall.h */
