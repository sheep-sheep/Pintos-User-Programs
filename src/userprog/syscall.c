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

void Check_ptr_valid(const void *vaddr);
//void buffer_isValid (void *buffer, unsigned size);
//void getArgument (struct intr_frame *f, int *arg, int n);

#define SIZE 3

struct lock global_file_lock;
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
	lock_init(&global_file_lock);
	// Start interrupt and call syscall_handler.
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED){
	int arg[SIZE],i;
	//ptr_isValid ((const void *) f->esp);
	// *esp points to the syscall number.
	for (i = 0; i <= SIZE; i++){
		arg[i] = * ((int *) f->esp + i);
    }
	/* These state value comes from lib_syscall_nr which defines the
	sys call numbers. */
	switch (arg[0]){
		case SYS_HALT:{
			halt(); 
			break;
		}
		case SYS_EXIT:{
			//getArgument(f, &arg[0], 1);
			exit (arg[1]);
			break;
		}
		case SYS_EXEC:{
			//getArgument (f, &arg[0], 1);
			arg[1] = user_provide_ptr ((const void *) arg[1]);
			f->eax = exec ((const char *) arg[1]);
			break;
		}
		case SYS_WAIT:{
		/* f->eax, Saved EAX in Interrrupt Frame. */
			//getArgument (f, &arg[0], 1);
			f->eax = wait(arg[1]);
			break;
		}
		case SYS_CREATE:
		{
			//getArgument (f, &arg[0], 2);
			arg[1] = user_provide_ptr((const void *) arg[1]);
			f->eax = create((const char *)arg[1], (unsigned) arg[2]);
			break;
		}
		case SYS_REMOVE:{
			//getArgument (f, &arg[0], 1);
			arg[1] = user_provide_ptr((const void *) arg[1]);
			f->eax = remove((const char *) arg[1]);
			break;
		}
		case SYS_OPEN:{
			//getArgument (f, &arg[0], 1);
			arg[1] = user_provide_ptr((const void *) arg[1]);
			f->eax = open((const char *) arg[1]);
			break; 		
		}
		case SYS_FILESIZE:{
			//getArgument (f, &arg[0], 1);
			f->eax = filesize(arg[1]);
			break;
		}
		case SYS_READ:{
			//getArgument (f, &arg[0], 3);
			//buffer_isValid ((void *) arg[1], (unsigned) arg[2]);
			arg[2] = user_provide_ptr((const void *) arg[2]);
			f->eax = read(arg[1], (void *) arg[2], (unsigned) arg[3]);
			break;
		}
		case SYS_WRITE:{ 
			//getArgument (f, &arg[0], 3);
			//buffer_isValid ((void *) arg[1], (unsigned) arg[2]);
			arg[2] = user_provide_ptr((const void *) arg[2]);
			f->eax = write(arg[1], (const void *) arg[2], (unsigned) arg[3]);
			break;
		}
		case SYS_SEEK:{
			//getArgument (f, &arg[0], 2);
			seek(arg[1], (unsigned) arg[2]);
			break;
		} 
		case SYS_TELL:{ 
			//getArgument (f, &arg[0], 1);
			f->eax = tell(arg[1]);
			break;
		}
		case SYS_CLOSE:{ 
			//getArgument (f, &arg[0], 1);
			close(arg[1]);
			break;
		} 
	}
}

int user_provide_ptr(const void *vaddr){
	// Verify the validity of a user-provided pointer
  	Check_ptr_valid(vaddr);

  	struct thread *t = thread_current();  
  	void *ptr = pagedir_get_page (t->pagedir, vaddr);
  	if(!ptr) {
    	exit (ERROR);
  	}
  	return (int) ptr;
}
// Make sure the ptr is in valid range.
void Check_ptr_valid(const void *vaddr) {
  //  || vaddr < VADDR_OF_USER
  if(!is_user_vaddr (vaddr))
    exit (ERROR);
}

// void buffer_isValid (void *buffer, unsigned size) {
//   char *temp = (char *) buffer;
//   int i;

//   for(i = 0; i < size; i++) {
//     ptr_isValid ((const void *)temp);
//     temp++;
//   }
// }

// void getArgument (struct intr_frame *f, int *arg, int n) {
//   int *ptr;
//   int i;
  
//   for(i = 0; i < n; i++) {
//     ptr = (int *) f->esp + i + 1;
//     ptr_isValid ((const void *) ptr);
//     arg[i] = *ptr;
//   }
// }

void halt(void){
	/* From devices/shutdown.c: Powers down the machine we're running on.*/
	shutdown_power_off();
}

// Terminates the current user program, returning status to the kernel.
void exit(int status){
  struct thread *t = thread_current();  
  
  if(thread_exists (t->parent_pid)) {
      t->child_elem->status = status;
  }
	// Process Termination Messages
	printf ("%s: exit(%d)\n", t->name, status);
	thread_exit();
} 

pid_t exec(const char *cmd_line){
	/*Starts a new thread running a user program loaded from
	FILENAME. Returns the new process's thread id, or TID_ERROR 
	if the thread cannot be created. TID_ERROR is tid_t-1=-1.*/
	pid_t pid = process_execute(cmd_line);
	
	struct child *child = get_child(pid);
	while(child->load == 0){ //0 means hasn't loaded yet
		barrier();
	}
	if(!child || child->load == 2){ //2 means load failed
		return ERROR;
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
	lock_acquire(&global_file_lock);
	/* From filesys.c, Creates a file named NAME with 
	the given INITIAL_SIZE. Returns true if successful, 
	false otherwise. Fails if a file named NAME already exists,
	or if internal memory allocation fails. */
	bool success = filesys_create(file, initial_size);
	lock_release(&global_file_lock);
	return success;
}

bool remove(const char *file){
// Add lock to this part
	lock_acquire(&global_file_lock);
	lock_release(&global_file_lock);
	return true;
}

int open(const char *file){
// Add lock to this part
	lock_acquire(&global_file_lock);
	// Open a file and add it to a file list. Each 
	// process has an independent set of file descriptors. 
	/* Returns the new file if successful or a null pointer
   otherwise. */
	struct file *f = filesys_open(file);
	if(!f){
		lock_release(&global_file_lock);
		return ERROR;
	}
	// Implement a way to get the fd of current file.
	int fd = put_file(f);
	lock_release(&global_file_lock);
	return fd;
}

int filesize(int fd){
// Add lock to this part
	lock_acquire(&global_file_lock);
	// Implement a way to get the fd of current file.
	struct file *f = get_file(fd);
	// if(!f){
	// 	lock_release(&filesys_lock);
	// 	return ERROR;
	// }
	// From file.c, Returns the size, in bytes, of the file open as fd.
	int size = file_length(f);
	lock_release(&global_file_lock);
	return size;
}

int read(int fd, void *buffer, unsigned size){
	if(fd == STDIN_FILENO){
		unsigned i;
		uint8_t *temp_buffer;
		*temp_buffer = (uint8_t *)buffer;

		// Fd 0 reads from the keyboard using input_getc().
		for (i = 0; i < size; i++){
			temp_buffer[i] = input_getc();
		}
		return size;
	}
// Add lock to this part
	lock_acquire(&global_file_lock);
	struct file *f = get_file(fd);
	int bytes = file_read(f, buffer, size);
	lock_release(&global_file_lock);
	return bytes;
}

int write(int fd, const void *buffer, unsigned size){
	// printf("Running write function===\n");
	// Fd 1 writes to the console. Your code to write to the console 
	// should write all of buffer in one call to putbuf()
	if(fd == STDOUT_FILENO){
		putbuf(buffer, size);
		return size;
	}
// Add lock to this part
	lock_acquire(&global_file_lock);
	struct file *f = get_file(fd);
	// if(!f){
	// 	lock_release(&filesys_lock);
	// 	return ERROR;
	// }
	int bytes = file_write(f, buffer, size);
	lock_release(&global_file_lock);
	return bytes;
}

void seek(int fd, unsigned position){
	lock_acquire(&global_file_lock);
	struct file *f = get_file(fd);
	/* Sets the current position in FILE to NEW_POS bytes from the
   start of the file. */
	lock_release(&global_file_lock);
	file_seek(f, position);
}

unsigned tell(int fd){
	lock_acquire(&global_file_lock);
	struct file *f = get_file(fd);
	/* Returns the current position in FILE as a byte offset from the
   start of the file. */
	off_t offset = file_tell(f);
	lock_release(&global_file_lock);
	return offset;	
}

void close(int fd){
	lock_acquire(&global_file_lock);
	/* Since we have a list to store the files, when we want to delete
	one file, we also need to search the file in that list and remove the 
	file from list. To be implemented later. */
	close_remove_file(fd);
	lock_release(&global_file_lock);
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
