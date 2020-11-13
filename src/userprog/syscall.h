#include "threads/thread.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

struct open_file
{
    struct list_elem fd_elem;
    int fd;
    struct file *file;
};

#endif /* userprog/syscall.h */
