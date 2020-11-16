#include "threads/thread.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void check_content(void *content);
struct open_file
{
    struct list_elem fd_elem;
    int fd;
    struct file *file;
    char *file_name;
};

#endif /* userprog/syscall.h */
