#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame *);
int user_provide_ptr(const void *vaddr);
int put_file(struct file *f);
struct file* get_file(int fd);
void close_remove_file(int fd);

#define SIZE 4
#define ERROR -1 // Where does the ERROR comes from?

struct lock file_lock;
/* Create the file object structure to hold the processing files. */	 
struct file_object {
	struct file *file;
	int fd;
	struct list_elem elem;
};

void
syscall_init(void) 
{
	/* Initializes LOCK.  A lock can be held by at most a single 
	thread at any given time. */
	lock_init(&file_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED){
	int i, arg[SIZE];
	// Get the argument value.
	for (i = 0; i < SIZE; i++){
		arg[i] = *((int *)f->esp + i);
	}
	/* These state value comes from lib_syscall_nr which defines the
	sys call numbers. */
	switch (arg[0]){
		case SYS_HALT:{
			halt(); 
			break;
		}
		case SYS_EXIT:{
			exit(arg[1]);
			break;
		}
		case SYS_EXEC:{
			arg[1] = user_provide_ptr((const void *) arg[1]);
			/* f->eax, Saved EAX in Interrrupt Frame. Need to explain why we need it*/
			f->eax = exec((const char *)arg[1]); 
			break;
		}
		case SYS_WAIT:{
		/* f->eax, Saved EAX in Interrrupt Frame. */
			f->eax = wait(arg[1]);
			break;
		}
		case SYS_CREATE:
		{
			arg[1] = user_provide_ptr((const void *) arg[1]);
			f->eax = create((const char *)arg[1], (unsigned) arg[2]);
			break;
		}
		case SYS_REMOVE:{
			arg[1] = user_provide_ptr((const void *) arg[1]);
			f->eax = remove((const char *) arg[1]);
			break;
		}
		case SYS_OPEN:{
			arg[1] = user_provide_ptr((const void *) arg[1]);
			f->eax = open((const char *) arg[1]);
			break; 		
		}
		case SYS_FILESIZE:{
			f->eax = filesize(arg[1]);
			break;
		}
		case SYS_READ:{
			arg[2] = user_provide_ptr((const void *) arg[2]);
			f->eax = read(arg[1], (void *) arg[2], (unsigned) arg[3]);
			break;
		}
		case SYS_WRITE:{ 
			arg[2] = user_provide_ptr((const void *) arg[2]);
			f->eax = write(arg[1], (const void *) arg[2], (unsigned) arg[3]);
			break;
		}
		case SYS_SEEK:{
			seek(arg[1], (unsigned) arg[2]);
			break;
		} 
		case SYS_TELL:{ 
			f->eax = tell(arg[1]);
			break;
		}
		case SYS_CLOSE:{ 
			close(arg[1]);
			break;
		} 
	}
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
  	return 0; // Double check whether we could get right pointer address.
  }
  return (int) ptr;
}

void halt(void){
	/* From devices/shutdown.c: Powers down the machine we're running on.*/
	shutdown_power_off();
}

void exit(int status){
  struct thread *currentThread = thread_current();  
  
  if(thread_exists (currentThread->parent)) {
    if(currentThread->child->wait) {
      currentThread->child->status = status;
    }
  }
	// Process Termination Messages
	printf ("%s: exit(%d)\n", currentThread->name, status);
	thread_exit();
}// Terminates the current user program, returning status to the kernel. 

pid_t exec(const char *cmd_line){
	/*Starts a new thread running a user program loaded from
	FILENAME. Returns the new process's thread id, or TID_ERROR 
	if the thread cannot be created. TID_ERROR is tid_t-1=-1.*/
	pid_t pid = process_execute(cmd_line);

  struct child *child = get_child(pid);
  if(!child || child->load == 2) { //2 means load failed
    return ERROR;
  }

  while(child->load == 0) { //0 means hasn't loaded yet
    barrier();
  }
	return pid;
}

int wait(pid_t pid){
	/* Waits for thread TID to die and returns its exit status. To be 
	implemented in process.c. */
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size){
// Add lock to this part
	lock_acquire(&file_lock);
	/* From filesys.c, Creates a file named NAME with 
	the given INITIAL_SIZE. Returns true if successful, 
	false otherwise. Fails if a file named NAME already exists,
	or if internal memory allocation fails. */
	bool success = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return success;
}

bool remove(const char *file){
// Add lock to this part
	lock_acquire(&file_lock);
	lock_release(&file_lock);
	return true;
}

int open(const char *file){
// Add lock to this part
	lock_acquire(&file_lock);
	// Open a file and add it to a file list. Each 
	// process has an independent set of file descriptors. 
	/* Returns the new file if successful or a null pointer
   otherwise. */
	struct file *f = filesys_open(file);
	// Implement a way to get the fd of current file.
	int fd = put_file(f);
	lock_release(&file_lock);
	return fd;
}

int filesize(int fd){
// Add lock to this part
	lock_acquire(&file_lock);
	// Implement a way to get the fd of current file.
	struct file *f = get_file(fd);
	// From file.c, Returns the size, in bytes, of the file open as fd.
	int size = file_length(f);
	lock_release(&file_lock);
	return size;
}

int read(int fd, void *buffer, unsigned size){
	if(fd == STDIN_FILENO){
		unsigned i;
		uint8_t *temp_buffer = (uint8_t *)buffer;

		// Fd 0 reads from the keyboard using input_getc().
		for (i = 0; i < size; i){
			temp_buffer[i] = input_getc();
		}
		return size;
	}
// Add lock to this part
	lock_acquire(&file_lock);
	struct file *f = get_file(fd);
	int bytes = file_read(f, buffer, size);
	lock_release(&file_lock);
	return bytes;
}

int write(int fd, const void *buffer, unsigned size){
	// Fd 1 writes to the console. Your code to write to the console 
	// should write all of buffer in one call to putbuf()
	if(fd == STDOUT_FILENO){
		putbuf(buffer, size);
		return size;
	}
// Add lock to this part
	lock_acquire(&file_lock);
	struct file *f = get_file(fd);
	int bytes = file_write(f, buffer, size);
	lock_release(&file_lock);
	return bytes;
}

void seek(int fd, unsigned position){
	lock_acquire(&file_lock);
	struct file *f = get_file(fd);
	/* Sets the current position in FILE to NEW_POS bytes from the
   start of the file. */
	lock_release(&file_lock);
	file_seek(f, position);
}

unsigned tell(int fd){
	lock_acquire(&file_lock);
	struct file *f = get_file(fd);
	/* Returns the current position in FILE as a byte offset from the
   start of the file. */
	off_t offset = file_tell(f);
	lock_release(&file_lock);
	return offset;	
}

void close(int fd){
	lock_acquire(&file_lock);
	/* Since we have a list to store the files, when we want to delete
	one file, we also need to search the file in that list and remove the 
	file from list. To be implemented later. */
	close_remove_file(fd);
	lock_release(&file_lock);
}

int put_file(struct file *f){
	struct thread *t = thread_current();
	struct file_object *pf = malloc(sizeof(struct file_object));

	pf->file = f;
	pf->fd = &t->fd;
	// I have a doubt here. use thread_current() instead?
	t->fd++;
	// Don't need to maintain an order here.
	list_push_back(&t->file_list, &pf->elem);
	return pf->fd;
}

struct file* get_file(int fd){
	struct thread *t = thread_current();
	struct list_elem *e;
	/* Iterate through the file list and compare the fd value, if they're the
	same, then this pf->file is the file we are looking for.*/
	for(e = list_begin(&t->file_list); e!=list_end(&t->file_list);
		e = list_next(e)){
		struct file_object *pf = list_entry(e, struct file_object, elem);
		if(fd == pf->fd){
			return pf->file;
		}
	}
	return NULL;
}

void close_remove_file(int fd){
	struct thread *t = thread_current();
	struct list_elem *e;
	for(e = list_begin(&t->file_list); e != list_end (&t->file_list); 
		e = list_next(e)){
		struct file_object *pf = list_entry(e, struct file_object, elem);
		if (fd == pf->fd || fd == CLOSE_FILE){
			file_close(pf->file);
			list_remove(&pf->elem);
			free(pf);
		}
	}
	return;
}

struct child *get_child (int pid)
{
  struct thread *thread = thread_current();
  struct list_elem *element;

  for(element = list_begin(&thread->listOfChild); element != list_end(&thread->listOfChild); element = list_next(element)) {
    struct child *child = list_entry(element, struct child, listElem);
    if(pid == child->pid)
      return child;
  }

  return NULL;
}

struct child *push_child (int pid)
{
  struct child *child = malloc(sizeof(struct child));
  child->pid = pid;
  child->wait = false;
  child->exit = false;
  child->load = 0; //meaning that hasn't been loaded yet
  lock_init (&child->waitLock);
  list_push_back (&thread_current()->listOfChild, &child->listElem);

  return child;
}

void delete_childs (void)
{
  struct thread *thread = thread_current();
  struct list_elem *element;

  for(element = list_begin(&thread->listOfChild); element != list_end(&thread->listOfChild); element = list_next(element)) {
    struct child *child = list_entry(element, struct child, listElem);
    list_remove(&child->listElem);
    free (child);
  }
}

void delete_child (struct child *child) 
{
  list_remove(&child->listElem);
  free (child);
}
