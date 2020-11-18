#include "threads/thread.h"
#include "threads/interrupt.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* Typedef for pid. */
typedef int pid_t;

/* Typedef for syscall function pointers. */
typedef void *syscall(struct intr_frame *f);

void exit(int);
void syscall_init(void);

struct open_file
{
    struct list_elem fd_elem; /* List elem to track open_file struct in open_files list of thread. */
    int fd;                   /* The file descriptor of the open_file with respect to process. */
    struct file *file;        /* Pointer to the structure of the open file. */
};

#endif /* userprog/syscall.h */