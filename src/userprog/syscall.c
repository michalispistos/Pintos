#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <inttypes.h>
#include "lib/stdio.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "lib/string.h"
#include "devices/input.h"
#include "threads/malloc.h"

/* The maximum size for a single buffer to be written to the console. */
#define MAX_SINGLE_BUFFER_SIZE (256)

/* Lock needed to use the filesystem. */
static struct lock file_lock;

/* File descriptor for open. */
static int fd = 2;

static void syscall_handler(struct intr_frame *);

void exit(int status);

/* Verifies a given memory address. */
static bool verify_memory_address(void **user_pointer)
{
  if (!user_pointer || !is_user_vaddr(user_pointer) || pagedir_get_page(thread_current()->pagedir, user_pointer) == NULL)
  {
    exit(-1);
    return false;
  }
  return true;
}

/* Tries to retrieve an open file with file descriptor fd. Returns a pointer to
   struct open_file if found and NULL if it fails. */
static struct open_file *find_file_from_fd(int fd)
{
  struct list_elem *e;
  struct open_file *of;
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      return of;
    }
  }
  return NULL;
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

/* Terminates Pintos by calling shutdown_power_off(). */
static void halt(struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

/* Terminates the current user program. */
void exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  /* We add the exit code into the thread_info struct. */
  struct thread_info *info = thread_current()->thread_info;
  info->exited_normally = true;
  info->exit_code = status;
  thread_exit();
}

/* Runs the executable whose name is given in cmd line, passing any given arguments, 
  and returns the new process’s program id (pid). Must return pid -1, which otherwise
  should not be a valid pid, if the program cannot load or run for any reason. */
static pid_t exec(struct intr_frame *f)
{

  const char *cmd_line = *(char **)(f->esp + 4);
  verify_memory_address((void *)cmd_line);
  lock_acquire(&file_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&file_lock);
  return pid;
}

/* Waits for a child process pid and retrieves the child’s exit status. */
static int wait(struct intr_frame *f)
{
  pid_t pid = *(pid_t *)(f->esp + 4);
  return process_wait(pid);
}

/* Creates a new file called file initially initial size bytes in size. Returns true 
   if successful, false otherwise. */
static bool create(struct intr_frame *f)
{
  //verify_memory_address(f->esp + 4);
  //verify_memory_address(f->esp + 8);
  const char *file = *(const char **)(f->esp + 4);
  unsigned initial_size = *(unsigned *)(f->esp + 8);
  verify_memory_address((void *)file);
  lock_acquire(&file_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return result;
}

/* Deletes the file called file. Returns true if successful, false otherwise. A file 
  may be removed regardless of whether it is open or closed, and removing an open 
  file does not close it. */
static bool remove(struct intr_frame *f)
{
  const char *file = *(char **)(f->esp + 4);
  verify_memory_address((void *)file);
  lock_acquire(&file_lock);
  bool result = filesys_remove(file);
  lock_release(&file_lock);
  return result;
}

/* Opens the file called file. Returns a nonnegative integer handle called a “file
 descriptor” (fd), or -1 if the file could not be opened. */
static int open(struct intr_frame *f)
{
  const char *file = *(char **)(f->esp + 4);
  verify_memory_address((void *)file);
  lock_acquire(&file_lock);
  struct file *file_to_open = filesys_open(file);
  if (file_to_open == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }
  struct open_file *of = malloc(sizeof(struct open_file));
  if (of == NULL)
  {
    lock_release(&file_lock);
    return TID_ERROR;
  }
  of->fd = fd++;
  of->file = file_to_open;
  list_push_front(&thread_current()->open_files, &of->fd_elem);
  lock_release(&file_lock);
  return of->fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int filesize(struct intr_frame *f)
{
  int fd = *(int *)(f->esp + 4);
  lock_acquire(&file_lock);
  struct open_file *of = find_file_from_fd(fd);
  if (of != NULL)
  {
    lock_release(&file_lock);
    return file_length(of->file);
  }
  lock_release(&file_lock);
  return -1;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
  read (0 at end of file), or -1 if the file could not be read. */
static int read(struct intr_frame *f)
{
  int fd = *(int *)(f->esp + 4);
  void *buffer = *(void **)(f->esp + 8);
  unsigned size = *(unsigned *)(f->esp + 12);
  verify_memory_address(buffer);
  lock_acquire(&file_lock);
  if (fd == STDIN_FILENO)
  {
    char *buffer_ = (char *)buffer;
    for (unsigned tracker = 0; tracker < size; tracker++)
    {
      buffer_[tracker] = input_getc();
    }
    lock_release(&file_lock);
    return size;
  }
  struct open_file *of = find_file_from_fd(fd);
  if (of != NULL)
  {
    lock_release(&file_lock);
    return file_read(of->file, buffer, size);
  }
  lock_release(&file_lock);
  return -1;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
   written, which may be less than size if some bytes could not be written. */
static int write(struct intr_frame *f)
{
  int fd = *(int *)(f->esp + 4);
  const void *buffer = *(const void **)(f->esp + 8);
  unsigned size = *(unsigned *)(f->esp + 12);
  verify_memory_address((void *)buffer);
  lock_acquire(&file_lock);
  if (fd == STDOUT_FILENO)
  {
    unsigned temp_size = size;
    while (temp_size >= MAX_SINGLE_BUFFER_SIZE)
    {
      putbuf(buffer, MAX_SINGLE_BUFFER_SIZE);
      temp_size -= MAX_SINGLE_BUFFER_SIZE;
    }
    putbuf(buffer, temp_size);
    lock_release(&file_lock);
    return size;
  }
  struct open_file *of = find_file_from_fd(fd);
  if (of != NULL)
  {
    lock_release(&file_lock);
    return file_write(of->file, buffer, size);
  }
  lock_release(&file_lock);
  return 0;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes
  from the beginning of the file. */
static void seek(struct intr_frame *f)
{
  int fd = *(int *)(f->esp + 4);
  unsigned position = *(unsigned *)(f->esp + 8);
  lock_acquire(&file_lock);
  struct open_file *of = find_file_from_fd(fd);
  if (of != NULL)
  {
    file_seek(of->file, position);
  }
  lock_release(&file_lock);
}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes
   from the beginning of the file. */
static unsigned tell(struct intr_frame *f)
{
  int fd = *(int *)(f->esp + 4);
  lock_acquire(&file_lock);
  struct open_file *of = find_file_from_fd(fd);
  if (of != NULL)
  {
    lock_release(&file_lock);
    return file_tell(of->file);
  }
  lock_release(&file_lock);
  return -1;
}

/* Closes file descriptor fd. */
static void close(struct intr_frame *f)
{
  int fd = *(int *)(f->esp + 4);
  lock_acquire(&file_lock);
  struct open_file *of = find_file_from_fd(fd);
  if (of != NULL)
  {
    file_deny_write(of->file);
    file_close(of->file);
    list_remove(&of->fd_elem);
    free(of);
  }
  lock_release(&file_lock);
}

typedef void *syscall(struct intr_frame *f);

static syscall *syscalls[13] = {
    (void *)halt,
    (void *)exit,
    (void *)exec,
    (void *)wait,
    (void *)create,
    (void *)remove,
    (void *)open,
    (void *)filesize,
    (void *)read,
    (void *)write,
    (void *)seek,
    (void *)tell,
    (void *)close};

/* Retrieve the system call number, then any system call arguments, 
  and carry out appropriate actions */
static void
syscall_handler(struct intr_frame *f)
{
  verify_memory_address(f->esp);
  int syscall_num = *(int *)(f->esp);
  int counter = 4;
  while (counter <= 12 && *(void **)(f->esp + counter) != NULL)
  {
    verify_memory_address(f->esp + counter);
    counter += 4;
  }
  if (syscall_num == SYS_EXIT)
  {
    exit(*(int *)(f->esp + 4));
  }
  else
  {
    f->eax = (uint32_t)syscalls[syscall_num](f);
  }
}