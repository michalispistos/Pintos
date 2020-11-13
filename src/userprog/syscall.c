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


typedef int pid_t;

/* The maximum size for a single buffer to be written to the console. */
#define MAX_SINGLE_BUFFER_SIZE (200)

/* Lock needed to use the filesystem. */
static struct lock file_lock;

static struct lock exec_lock;

/* File descriptor for open. */
static int fd = 2;

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  lock_init(&exec_lock);
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
  struct thread_info *info = thread_current()->thread_info;
  if (info){
    info->exited_normally = true;
    info->exit_code = status;
  }
  thread_exit();
}

// TODO: Check this is correct
static pid_t exec(const char *cmd_line)
{
  lock_acquire(&exec_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&exec_lock);
  return pid; 
}

static int wait(pid_t pid)
{
  return process_wait(pid);
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

static int filesize(int fd)
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

static int read(int fd, void *buffer, unsigned size)
{
  lock_acquire(&file_lock);
  if (fd == STDIN_FILENO)
  {
    char* buffer_ = (char*) buffer;
    uint32_t buffer_length = strlen(buffer_);
    char word[size];
    for (uint32_t i = 0; i < size; i++) {             
      word[i] = input_getc();                        
    }
    strlcpy (buffer_, word, size); 
    if(buffer_length<=size){
      lock_release(&file_lock);
      return buffer_length;
    }else{
      lock_release(&file_lock);
      return size;
    }
  }

  struct list_elem *e;
  struct open_file *of;
  // Implement helper function
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      lock_release(&file_lock);
      // Does not advance position after reading
      return file_read_at(of->file, buffer, size, 0);
    }
  }
  lock_release(&file_lock);
  return -1;
}

/* Writes size bytes from buffer to the open file fd. */
static int
write(int fd, const void *buffer, unsigned size)
{
  lock_acquire(&file_lock);
  if (fd == STDOUT_FILENO)
  {
    int tracker = 0;
    while (size > MAX_SINGLE_BUFFER_SIZE)
    {
      putbuf(buffer + tracker, MAX_SINGLE_BUFFER_SIZE);
      tracker += MAX_SINGLE_BUFFER_SIZE;
      size -= MAX_SINGLE_BUFFER_SIZE;
    }
    putbuf(buffer + tracker, size);
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
      // Advances position after writing
      // Make sure can't write to program file
      return file_write(of->file, buffer, size);
    }
  }
  lock_release(&file_lock);
  return 0;
}

static void seek(int fd, unsigned position)
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

static unsigned tell(int fd)
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

static void close(int fd)
{
  lock_acquire(&file_lock);
  struct list_elem *e;
  struct open_file *of;
  for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
  {
    of = list_entry(e, struct open_file, fd_elem);
    if (of->fd == fd)
    {
      file_close(of->file);
      break;
    }
  }
  list_remove(e);
  lock_release(&file_lock);
}

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
  void** argv;
  int i=0;
  f->esp = f->esp+4;
  while(f->esp!=NULL){
    argv[i] = *(void **)f->esp;
     i++;
  }
  switch (syscall_num){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit((int) argv[0]);
      break;
    case SYS_EXEC:
      verify_memory_address(thread_current(),argv[0]);
      f->eax = exec((const char *) argv[0]);
      break;
    case SYS_WAIT:
      f->eax = wait((int) argv[0]);
      break;
    case SYS_CREATE:
      verify_memory_address(thread_current(),argv[0]);
      f->eax = create((const char *) argv[0], (unsigned int) argv[1]);
      break;
    case SYS_REMOVE:
      verify_memory_address(thread_current(),argv[0]);
      f->eax = remove((const char *) argv[0]);
      break;
    case SYS_OPEN:
      verify_memory_address(thread_current(),argv[0]);
      f->eax = open((const char *) argv[0]);
      break;
    case SYS_FILESIZE:
      f->eax = filesize((int) argv[0]);
      break;
    case SYS_READ:
      verify_memory_address(thread_current(),argv[1]);
      f->eax = read((int) argv[0], (void *) argv[1], (unsigned int) argv[2]);
      break;
    case SYS_WRITE:
      verify_memory_address(thread_current(),argv[1]);
      f->eax = write((int) argv[0], (const void*) argv[1], (unsigned int) argv[2]);
      break;
    case SYS_SEEK:
      seek((int) argv[0], (unsigned int) argv[1]);
      break;
    case SYS_TELL:
      tell((int) argv[0]);
      break;  
    case SYS_CLOSE:
      close((int) argv[0]);
      break;
  }
}