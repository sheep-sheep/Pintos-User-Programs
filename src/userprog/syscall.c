#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

int user_provide_ptr(const void *vaddr){
	// Verify the validity of a user-provided pointer
	if (!is_user_vaddr(vaddr)){
  	thread_exit();
  	return 0;
  }

  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr){
  	thread_exit();
  	return 0; // Double check whether we could get right pointer address
  }
  return (int) ptr;
}
