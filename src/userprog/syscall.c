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
#include "lib/user/syscall.h"

typedef int pid_t;

/* The maximum size for a single buffer to be written to the console. */
#define MAX_SINGLE_BUFFER_SIZE (256)

/* Lock needed to use the exec system call */
static struct lock exec_lock;

/* Lock needed to use the filesystem. */
static struct lock file_lock;

/* File descriptor for open. */
static int fd = 2;

static void syscall_handler(struct intr_frame *);
void exit(int status);
static bool verify_memory_address(struct thread *t, void **user_pointer);

// Checks that name is not NULL and verifies the pointer to name
void check_content(void *content)
{
  if (content == NULL)
  {
    exit(-1);
  }
  verify_memory_address(thread_current(), content);
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  lock_init(&exec_lock);
}

void halt(void)
{
  shutdown_power_off();
}

/* Terminates the current user program */
void exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  struct thread_info *info = thread_current()->thread_info;
  if (info)
  {
    info->exited_normally = true;
    info->exit_code = status;
  }
  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  check_content((void *)cmd_line);
  //printf("in exec,cmd_line = %s\n", cmd_line);
  lock_acquire(&file_lock);
  // pid_t pid;
  // pid = wait(process_execute(cmd_line));
  pid_t pid = process_execute(cmd_line);
  lock_release(&file_lock);
  return pid;
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size)
{
  check_content((void *)file);
  //printf("name of file: %s\n", file);
  lock_acquire(&file_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return result;
}

bool remove(const char *file)
{
  check_content((void *)file);
  lock_acquire(&file_lock);
  bool result = filesys_remove(file);
  lock_release(&file_lock);
  return result;
}

int open(const char *file)
{
  check_content((void *)file);
  lock_acquire(&file_lock);
  struct file *file_to_open = filesys_open(file);
  if (file_to_open == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }

  struct open_file *of = palloc_get_page(PAL_ZERO);
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

int filesize(int fd)
{
  struct list_elem *e;
  struct open_file *of;
  lock_acquire(&file_lock);
  // Create helper function for this
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

int read(int fd, void *buffer, unsigned size)
{
  check_content(buffer);
  lock_acquire(&file_lock);
  for (unsigned i = 0; i < size; i += PGSIZE)
  {
    if ((buffer + i) == NULL || !is_user_vaddr(buffer + i) || pagedir_get_page(thread_current()->pagedir, buffer + i) == NULL)
    {
      lock_release(&file_lock);
      return -1;
    }
  }
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

  struct list_elem *e;
  struct open_file *of;
  // Implement helper function
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      //verify_memory_address(thread_current(), (void **)buffer);
      // Does not advance position after reading
      lock_release(&file_lock);
      return file_read(of->file, buffer, size);
      //return file_read_at(of->file, buffer, size, 0);
    }
  }
  // Fail
  lock_release(&file_lock);
  return -1;
}

/* Writes size bytes from buffer to the open file fd. */
int write(int fd, const void *buffer, unsigned size)
{
  check_content((void *)buffer);
  lock_acquire(&file_lock);
  //printf("BUF: %s\n", (char *)buffer);
  // Fd 1 writes to the console
  //printf("REACHED WRITE\n");
  for (unsigned i = 0; i < size; i += PGSIZE)
  {
    if ((buffer + i) == NULL || !is_user_vaddr(buffer + i) || pagedir_get_page(thread_current()->pagedir, buffer + i) == NULL)
    {
      lock_release(&file_lock);
      return -1;
    }
  }
  if (fd == STDOUT_FILENO)
  {
    unsigned temp_size = size;
    //int tracker = 0;
    while (temp_size >= MAX_SINGLE_BUFFER_SIZE)
    {
      //check_content((void *)(buffer + MAX_SINGLE_BUFFER_SIZE));
      putbuf(buffer, MAX_SINGLE_BUFFER_SIZE);
      //tracker += MAX_SINGLE_BUFFER_SIZE;
      temp_size -= MAX_SINGLE_BUFFER_SIZE;
      // verify_memory_address(thread_current(), (buffer + temp_size));
    }
    putbuf(buffer, temp_size);
    lock_release(&file_lock);
    return size;
  }
  struct list_elem *e;
  struct open_file *of;
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      lock_release(&file_lock);
      /* Advances position after writing
       Make sure can't write to program file */
      return file_write(of->file, buffer, size);
    }
  }
  lock_release(&file_lock);
  return 0;
}

void seek(int fd, unsigned position)
{
  lock_acquire(&file_lock);
  struct list_elem *e;
  struct open_file *of;
  // Implement helper function
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      file_seek(of->file, position);
      break;
    }
  }
  lock_release(&file_lock);
}

unsigned tell(int fd)
{
  lock_acquire(&file_lock);
  struct list_elem *e;
  struct open_file *of;
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      lock_release(&file_lock);
      return file_tell(of->file);
    }
  }
  lock_release(&file_lock);
  return -1;
}

void close(int fd)
{
  lock_acquire(&file_lock);
  struct list_elem *e;
  struct open_file *of;
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      file_deny_write(of->file);
      file_close(of->file);
      list_remove(e);
      break;
    }
  }
  lock_release(&file_lock);
}

/* Verifies a given memory address. */
static bool
verify_memory_address(struct thread *t, void **user_pointer)
{
  if (!user_pointer || !is_user_vaddr(user_pointer) || pagedir_get_page(t->pagedir, user_pointer) == NULL)
  {
    exit(-1);
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
  verify_memory_address(thread_current(), f->esp);
  int syscall_num = *(int *)(f->esp);
  //printf("Sycall_num:%d\n", syscall_num);
  if (syscall_num == 1)
  {
    //printf("EXIT CODE = %d\n", *(int *)(f->esp + 4));
  }

  /*
  printf("Syscall num: %d(%p)\n", syscall_num, f->esp);
  void **argv = palloc_get_page(0);
  int i = 0;
  int counter = 4;
  while (*(void **)(f->esp + counter) != NULL)
  {
    //memcpy(argv[i], f->esp + counter, 4);
    argv[i] = *(void **)(f->esp + counter);
    i++;
    counter += 4;
  }
  */

  //printf("Syscall argv[0]: %d\n", argv[0]);
  //printf("argv[1]: %s\n", (void *)argv[1]);
  // printf("argv[2]: %d", argv[2]);
  switch (syscall_num)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    //exit((int)argv[0]);
    verify_memory_address(thread_current(), f->esp + 4);
    exit(*(int *)(f->esp + 4));
    break;
  case SYS_EXEC:
    verify_memory_address(thread_current(), f->esp + 4);
    //f->eax = exec((const char *)argv[0]);
    f->eax = exec(*(const char **)(f->esp + 4));
    break;
  case SYS_WAIT:
    //f->eax = wait((int)argv[0]);
    verify_memory_address(thread_current(), f->esp + 4);
    f->eax = wait(*(int *)(f->esp + 4));
    break;
  case SYS_CREATE:
    //verify_memory_address(thread_current(), argv[0]);
    //f->eax = create((const char *)argv[0], (unsigned int)argv[1]);
    verify_memory_address(thread_current(), f->esp + 4);
    verify_memory_address(thread_current(), f->esp + 8);
    f->eax = create(*(const char **)(f->esp + 4), *(unsigned int *)(f->esp + 8));
    break;
  case SYS_REMOVE:
    //verify_memory_address(thread_current(), argv[0]);
    //f->eax = remove((const char *)argv[0]);
    verify_memory_address(thread_current(), f->esp + 4);
    f->eax = remove(*(const char **)(f->esp + 4));
    break;
  case SYS_OPEN:
    //verify_memory_address(thread_current(), argv[0]);
    //f->eax = open((const char *)argv[0]);
    verify_memory_address(thread_current(), f->esp + 4);
    f->eax = open(*(const char **)(f->esp + 4));
    break;
  case SYS_FILESIZE:
    //f->eax = filesize((int)argv[0]);
    verify_memory_address(thread_current(), f->esp + 4);
    f->eax = filesize(*(int *)(f->esp + 4));
    break;
  case SYS_READ:
    //verify_memory_address(thread_current(), argv[1]);
    //f->eax = read((int)argv[0], (void *)argv[1], (unsigned int)argv[2]);
    verify_memory_address(thread_current(), f->esp + 4);
    verify_memory_address(thread_current(), f->esp + 8);
    verify_memory_address(thread_current(), f->esp + 12);
    f->eax = read(*(int *)(f->esp + 4), *(void **)(f->esp + 8), *(unsigned int *)(f->esp + 12));
    break;
  case SYS_WRITE:
    //verify_memory_address(thread_current(), *(void **)(f->esp + 8));
    //f->eax = write((int)argv[0], (const void *)argv[1], (unsigned int)argv[2]);
    //f->eax = write((int)argv[0], (const void *)argv[1], (unsigned int)argv[2]);
    verify_memory_address(thread_current(), f->esp + 4);
    verify_memory_address(thread_current(), f->esp + 8);
    verify_memory_address(thread_current(), f->esp + 12);
    //printf("verified and write\n");
    f->eax = write(*(int *)(f->esp + 4), *(void **)(f->esp + 8), *(unsigned int *)(f->esp + 12));
    break;
  case SYS_SEEK:
    //seek((int)argv[0], (unsigned int)argv[1]);
    verify_memory_address(thread_current(), f->esp + 4);
    verify_memory_address(thread_current(), f->esp + 8);
    seek(*(int *)(f->esp + 4), *(unsigned int *)(f->esp + 8));
    break;
  case SYS_TELL:
    verify_memory_address(thread_current(), f->esp + 4);
    tell(*(int *)(f->esp + 4));
    break;
  case SYS_CLOSE:
    verify_memory_address(thread_current(), f->esp + 4);
    close(*(int *)(f->esp + 4));
    break;
  }
  //palloc_free_page(argv);
}