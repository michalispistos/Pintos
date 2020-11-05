#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <inttypes.h>

typedef int pid_t;

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// static void halt(void) {}

/* Terminates the current user program */
static void exit(int status)
{
  printf("%s: exit%08" PRId32 "\n", thread_current()->name, status);
  thread_exit();
}

// static pid_t exec(const char *cmd_line) {}

// static int wait(pid_t pid) {}

// static bool create(const char *file, unsigned initial_size) {}

// static bool remove(const char *file) {}

// static int open(const char *file) {}

// static int filesize(int fd) {}

// static int read(int fd, void *buffer, unsigned size) {}

// static int write(int fd, const void *buffer, unsigned size) {}

// static void seek(int fd, unsigned position) {}

// static unsigned tell(int fd) {}

// static void close(int fd) {}

/* Verifies a given memory address.
*/
static bool
verify_memory_address(struct thread *t, void *user_pointer)
{
  if (!user_pointer || !is_user_vaddr(user_pointer) || !pagedir_get_page(t->pagedir, user_pointer))
  {
    thread_exit();
    // TODO: Need to call exit() after implementing it
    pagedir_destroy(t->pagedir);
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
  printf("The syscall number is: %08" PRIu32 "\n", syscall_num);
  exit(0);
}