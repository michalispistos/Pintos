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
#include "threads/palloc.h"

typedef int pid_t;

/* The maximum size for a single buffer to be written to the console. */
#define MAX_SINGLE_BUFFER_SIZE (200)

/* Lock needed to use the filesystem. */
static struct lock file_lock;

/* File descriptor for open. */
static int fd = 2;

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void halt(void)
{
  shutdown_power_off();
}

/* Terminates the current user program */
static void
exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_current()->thread_info->exited_normally = true;
  thread_current()->thread_info->exit_code = status;
  thread_exit();
}

// TODO: Check this is correct
static pid_t exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

static int wait(pid_t pid)
{
  process_wait(pid);
}

static bool create(const char *file, unsigned initial_size)
{
  lock_acquire(&file_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return result;
}

static bool remove(const char *file)
{
  lock_acquire(&file_lock);
  bool result = filesys_remove(file);
  lock_release(&file_lock);
  return result;
}

static int open(const char *file)
{
  lock_acquire(&file_lock);
  struct file *file_to_open = filesys_open(file);
  if (file_to_open == NULL)
  {
    return -1;
  }

  struct open_file *of = palloc_get_page(PAL_ZERO);
  if (of == NULL)
  {
    return TID_ERROR;
  }

  of->fd = fd++;
  of->file = file_to_open;
  list_push_front(thread_current()->open_files, &of->fd_elem);

  lock_release(&file_lock);
  return of->fd;
}

static int filesize(int fd)
{

  struct list_elem *e;
  struct open_file *of;
  lock_acquire(&file_lock);
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      lock_release(&file_lock);
      return file_length(of->file);
    }
  }
  // Not found
  lock_release(&file_lock);
  return -1;
}

// static int read(int fd, void *buffer, unsigned size) {}

/* Writes size bytes from buffer to the open file fd.
  Currently it can only write to console
TODO: implement full 
*/
static int
write(int fd, const void *buffer, unsigned size)
{
  int tracker = 0;
  if (fd == STDOUT_FILENO)
  {
    while (size > MAX_SINGLE_BUFFER_SIZE)
    {
      putbuf(buffer + tracker, MAX_SINGLE_BUFFER_SIZE);
      tracker += MAX_SINGLE_BUFFER_SIZE;
      size -= MAX_SINGLE_BUFFER_SIZE;
    }
    putbuf(buffer + tracker, size);
  }
  return size;
}

// static void seek(int fd, unsigned position) {}

// static unsigned tell(int fd) {}

// static void close(int fd) {}

/* Verifies a given memory address. */
static bool
verify_memory_address(struct thread *t, void *user_pointer)
{
  if (!user_pointer || !is_user_vaddr(user_pointer) || pagedir_get_page(t->pagedir, user_pointer) == NULL)
  {
    /* TODO: Need to call exit() after implementing it. */
    //pagedir_destroy(t->pagedir);
    thread_exit();
    return false;
  }
  return true;
}

/* Retrieve the system call number, then any system call arguments, 
  and carry out appropriate actions
TODO: Implement fully
*/
static void
syscall_handler(struct intr_frame *f)
{
  int syscall_num = *(int *)(f->esp);
  printf("The syscall number is: %d\n", syscall_num);
  exit(0);
}