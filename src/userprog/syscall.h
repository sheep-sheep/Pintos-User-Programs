#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

#define CLOSE_FILE -1
#define ERROR -1

struct child{
  int pid;			/* The current process's pid. */
  bool wait;		/* Parent process is waiting. */
  bool exit;		/* The process has exited. */
  int load;			/* Whether the process has loaded or not. */
  int status;		/* Exit status of the process. */

  struct lock waitLock;
  struct list_elem listElem;	/* List element. */
};

void syscall_init (void);
void close_remove_file (int fd);

struct child *get_child (int pid);
struct child *push_child (int pid);
void delete_child (struct child *child);
void delete_childs (void);
#endif /* userprog/syscall.h */
