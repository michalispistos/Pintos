#include "threads/thread.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void exit(int);
void syscall_init(void);
struct open_file
{
    struct list_elem fd_elem;
    int fd;
    struct file *file;
};

#endif /* userprog/syscall.h */
