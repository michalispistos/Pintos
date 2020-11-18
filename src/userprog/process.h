#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* Not neccessarily alive */
struct thread_info
{
    struct list_elem child_elem; /* List element stored in struct thread. */
    tid_t tid;                   /* tid of the child. */
    int exit_code;               /* Exit code of the child thread. */
    bool has_been_waited_on;     /* True if child thread has been called by process_wait(). */
    bool exited_normally;        /* True if exit() was called on it. */
    bool load_failed;            /* True if thread failed to load. */
    struct semaphore wait_sema;  /* A semaphore used for process_wait(). */
    struct semaphore load_sema;  /* A semaphore used to block parent thread until child loads. */
    char **args;                 /* Arguments needed for argument parsing */
};

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

#endif /* userprog/process.h */
