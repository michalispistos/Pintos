#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* Not neccessarily alive */
struct child_thread_info
{
    struct list_elem tid_elem; /* List element stored in struct thread. */
    tid_t tid;                 /* Tid of the child. */
    int exit_code;             /* Exit code of the child thread when terminated by the kernel. */
    bool has_been_waited_on;   /* True if child thread has been called by process_wait(). */
    bool has_died;             /* True if it has been terminated by the kernel. */
};

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

#endif /* userprog/process.h */
