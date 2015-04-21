#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
int user_provide_ptr(const void *vaddr);
int put_file (struct file *f);
struct file* get_file (int fd);
void close_file (int fd);

#define SIZE 4
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED){
	int i, arg[SIZE];
	// Get the argument value.
	for (i = 0; i < SIZE; i++){
		arg[i] = *((int *)f->esp + i);
	}
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
			exec((const char *)arg[1]); 
			break;
		}
		case SYS_WAIT:{
			wait(arg[1]);
			break;
		}
		case SYS_CREATE:
		{
			arg[1] = user_provide_ptr((const void *) arg[1]);
			create((const char *)arg[1], (unsigned) arg[2]);
			break;
		}
		case SYS_REMOVE:{
			arg[1] = user_provide_ptr((const void *) arg[1]);
			remove((const char *) arg[1]);
			break;
		}
		case SYS_OPEN:{
			arg[1] = user_provide_ptr((const void *) arg[1]);
			open((const char *) arg[1]);
			break; 		
		}
		case SYS_FILESIZE:{
			filesize(arg[1]);
			break;
		}
		case SYS_READ:{
			arg[2] = user_provide_ptr((const void *) arg[2]);
			read(arg[1], (void *) arg[2], (unsigned) arg[3]);
			break;
		}
		case SYS_WRITE:{ 
			arg[2] = user_provide_ptr((const void *) arg[2]);
			write(arg[1], (const void *) arg[2], (unsigned) arg[3]);
			break;
		}
		case SYS_SEEK:{
			seek(arg[1], (unsigned) arg[2]);
			break;
		} 
		case SYS_TELL:{ 
			tell(arg[1]);
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

void halt (void){
	shutdown_power_off();
}

void exit (int status){
	// Process Termination Messages
	printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}// Terminates the current user program, returning status to the kernel. 

pid_t exec (const char *cmd_line){
	pid_t pid = process_execute(cmd_line);
	
	// Returns the new process's program id (pid) or -1.
	return pid;
}

int wait (pid_t pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
// Add lock to this part
	bool success = filesys_create(file, initial_size);
	return success;
}

bool remove (const char *file){
// Add lock to this part
	return true;
}

int open (const char *file){
// Add lock to this part
	// Open a file and add it to a file list. Each 
	// process has an independent set of file descriptors. 
	struct file *f = filesys_open(file);
	int fd = put_file(f);
	return fd;
}

int filesize (int fd){
// Add lock to this part
	struct file *f = get_file(fd);
	int size = file_length(f);
	// Returns the size, in bytes, of the file open as fd.
	return size;
}

int read (int fd, void *buffer, unsigned size){
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
	struct file *f = get_file(fd);
	int bytes = file_read(f, buffer, size);
	return bytes;
}

int write (int fd, const void *buffer, unsigned size){
	// Fd 1 writes to the console. Your code to write to the console 
	// should write all of buffer in one call to putbuf()
	if(fd == STDOUT_FILENO){
		putbuf(buffer, size);
		return size;
	}
// Add lock to this part
	struct file *f = get_file(fd);
	int bytes = file_write(f, buffer, size);
	return bytes;
}

void seek (int fd, unsigned position){
	struct file *f = get_file(fd);
	file_seek(f, position);
}

unsigned tell (int fd){
	struct file *f = get_file(fd);
	off_t offset = file_tell(f);
return offset;	
}

void close (int fd){
	struct file *f = get_file(fd);
	file_close(f);
	close_file(fd);
}

int put_file (struct file *f){
	return 1;
}

struct file* get_file (int fd){
	return NULL;
}

void close_file (int fd){
	return;
}