#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixedpoint.h"
#include "threads/malloc.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

static struct semaphore sema;
/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Array of queues of threads. Each queue contains threads of
the same priority - from 63 to 0. */
static struct list priority_queues_array[64];

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
{
  void *eip;             /* Return address. */
  thread_func *function; /* Function to call. */
  void *aux;             /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks;                 /* # of timer ticks spent idle. */
static long long kernel_ticks;               /* # of timer ticks in kernel threads. */
static long long user_ticks;                 /* # of timer ticks in user programs. */
static int load_avg;                         /* Load average for system. Treated as FIXED_POINT. */
static int number_of_threads_in_queue_array; /* Number of threads held in queue array. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
#define TIMER_FREQ 100        /* # of timer ticks per second. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-mlfqs". */
bool thread_mlfqs;

/* A lock for thread_set_effective_priority and thread_set_nice. */
static struct lock multi_purpose_lock;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *running_thread(void);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static bool is_thread(struct thread *) UNUSED;
static void *alloc_frame(struct thread *, size_t size);
static void schedule(void);
void thread_schedule_tail(struct thread *prev);
static tid_t allocate_tid(void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void)
{
  ASSERT(intr_get_level() == INTR_OFF);

  sema_init(&sema, 1);
  lock_init(&tid_lock);
  lock_init(&multi_purpose_lock);
  list_init(&ready_list);
  list_init(&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();
  sema_init(&initial_thread->sema, 0);

  /* The priority queues, load_avg and number_of_threads_in_queue_array 
     are initialised. */
  if (thread_mlfqs)
  {
    for (int i = PRI_MIN; i <= PRI_MAX; i++)
    {
      list_init(&priority_queues_array[i]);
    }

    load_avg = 0;
    number_of_threads_in_queue_array = 0;
  }
#ifdef USERPROG
  list_init(&initial_thread->children_info);
  list_init(&initial_thread->open_files);
#endif
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

/* Returns the number of threads currently in the 
   ready list or in the priority_queue_array.*/
size_t threads_ready(void)
{
  if (!thread_mlfqs)
  {
    return list_size(&ready_list);
  }
  else
  {
    return number_of_threads_in_queue_array;
  }
}

/* Recalculates recent CPU. */
static void recalculate_recent_cpu(struct thread *t, void *aux UNUSED)
{
  /* Ignore if it is the idle thread because 
     it is an unneeded calculation */
  if (t != idle_thread)
  {
    int twice_load_avg = MUL_INT(load_avg, 2);
    t->recent_cpu = ADD_INT((MUL_FIXED(DIV_FIXED(twice_load_avg, ADD_INT(twice_load_avg, 1)), t->recent_cpu)), t->nice);
  }
}

/* Calculates the new priority of a thread. If needed, moves thread
   to it's new priority queue. */
static void update_priority(struct thread *t, void *aux UNUSED)
{
  if (t != idle_thread)
  {
    int new_priority = ROUNDNEAR_INT(SUB_FIXED(FIXPOINT(PRI_MAX), (ADD_INT(DIV_INT(t->recent_cpu, 4), (t->nice * 2)))));
    if (new_priority > PRI_MAX)
    {
      new_priority = PRI_MAX;
    }
    if (new_priority < PRI_MIN)
    {
      new_priority = PRI_MIN;
    }
    t->effective_priority = new_priority;

    if (t->status == THREAD_READY)
    {
      list_remove(&t->elem);
      list_push_back(&priority_queues_array[new_priority], &t->elem);
    }
  }
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
  struct thread *t = thread_current();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Updates recent_cpu, priority values and load_avg if needed */
  if (thread_mlfqs)
  {
    long long timer_ticks = idle_ticks + user_ticks + kernel_ticks;
    if (t != idle_thread)
    {
      t->recent_cpu = ADD_INT(t->recent_cpu, 1);
    }

    /* Every 4 ticks */
    if (timer_ticks % TIME_SLICE == 0)
    {

      /* Every second (100 ticks) */
      if (timer_ticks % TIMER_FREQ == 0)
      {
        int ready_threads = threads_ready();
        if (t != idle_thread)
        {
          ready_threads++;
        }
        load_avg = ADD_FIXED(MUL_FIXED(DIV_INT(FIXPOINT(59), 60), load_avg), MUL_INT(DIV_INT(FIXPOINT(1), 60), ready_threads));
        thread_foreach(&recalculate_recent_cpu, NULL);
        thread_foreach(&update_priority, NULL);
      }
      else
      {
        update_priority(t, NULL);
      }
    }
  }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
         idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority,
                    thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable();

#ifdef USERPROG
  t->fd = 2;
  list_init(&t->children_info);
  list_init(&t->open_files);
  t->thread_info = aux;
#endif

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void (*)(void))kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level(old_level);

  /* Add to run queue. */
  thread_unblock(t);

  if (t->effective_priority > thread_get_priority())
  {
    thread_yield();
  }
  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);

  thread_current()->status = THREAD_BLOCKED;
  schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t)
{
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);

  if (thread_mlfqs)
  {
    list_push_back(&priority_queues_array[t->effective_priority], &t->elem);
    number_of_threads_in_queue_array++;
  }
  else
  {
    list_push_back(&ready_list, &t->elem);
  }

  ASSERT(threads_ready() != 0);
  t->status = THREAD_READY;
  intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *thread_name(void)
{
  return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *thread_current(void)
{
  struct thread *t = running_thread();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
  return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void)
{
  ASSERT(!intr_context());

#ifdef USERPROG
  process_exit();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable();
  list_remove(&thread_current()->allelem);
  thread_current()->status = THREAD_DYING;
  schedule();
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void)
{
  struct thread *cur = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());

  old_level = intr_disable();
  if (cur != idle_thread)
  {
    if (thread_mlfqs)
    {
      list_push_back(&priority_queues_array[cur->effective_priority], &cur->elem);
      number_of_threads_in_queue_array++;
    }
    else
    {
      list_push_back(&ready_list, &cur->elem);
    }
  }
  cur->status = THREAD_READY;
  schedule();
  intr_set_level(old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void thread_foreach(thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT(intr_get_level() == INTR_OFF);

  for (e = list_begin(&all_list); e != list_end(&all_list);
       e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, allelem);
    func(t, aux);
  }
}

/* Return the highest_priority_thread from a list of elems. */
struct thread *highest_priority_thread(struct list *list)
{
  struct thread *highest_priority_thread = list_entry(list_begin(list), struct thread, elem);
  struct list_elem *e;
  for (e = list_begin(list); e != list_end(list); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, elem);
    if (t->effective_priority > highest_priority_thread->effective_priority)
    {
      highest_priority_thread = t;
    }
  }
  return highest_priority_thread;
}

/* Return the highest_thread_priority from a list of blocked_elems. */
int highest_blocked_thread_priority(struct list *list)
{

  int highest_thread_priority = list_entry(list_begin(list), struct thread, blocked_elem)->effective_priority;
  struct list_elem *e;
  for (e = list_begin(list); e != list_end(list); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, blocked_elem);
    if (t->effective_priority > highest_thread_priority)
    {
      highest_thread_priority = t->effective_priority;
    }
  }
  return highest_thread_priority;
}

/* Sets the effective_priority. */
void thread_set_effective_priority(struct thread *t, int new_priority)
{
  lock_acquire(&multi_purpose_lock);
  if (t->effective_priority < new_priority || list_empty(&t->blocked_threads))
  {
    t->effective_priority = new_priority;
  }
  else if (t->effective_priority > new_priority)
  {
    int highest_blocked_threads_priority = highest_blocked_thread_priority(&t->blocked_threads);
    if (highest_blocked_threads_priority > new_priority)
    {
      t->effective_priority = highest_blocked_threads_priority;
    }
    else
    {
      t->effective_priority = new_priority;
    }
  }
  lock_release(&multi_purpose_lock);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority)
{
  if (thread_mlfqs)
  {
    return;
  }
  thread_current()->base_priority = new_priority;

  thread_set_effective_priority(thread_current(), new_priority);

  if (highest_priority_thread(&ready_list)->effective_priority > thread_get_priority())
  {
    thread_yield();
  }
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
  return thread_current()->effective_priority;
}

/* Sets the current thread's nice value to NICE and updates the priority. */
void thread_set_nice(int nice)
{
  lock_acquire(&multi_purpose_lock);
  ASSERT(nice >= -20 && nice <= 20);
  thread_current()->nice = nice;
  update_priority(thread_current(), NULL);

  int priority = PRI_MAX;
  while (priority >= PRI_MIN && list_empty(&priority_queues_array[priority]))
  {
    priority--;
  }

  lock_release(&multi_purpose_lock);

  if (priority > thread_current()->effective_priority)
  {
    thread_yield();
  }
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
  return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void)
{
  return ROUNDNEAR_INT(MUL_INT(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void)
{
  return ROUNDNEAR_INT(MUL_INT((thread_current()->recent_cpu), 100));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;)
  {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
    asm volatile("sti; hlt"
                 :
                 :
                 : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func *function, void *aux)
{
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *running_thread(void)
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm("mov %%esp, %0"
      : "=g"(esp));
  return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool is_thread(struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread with name
   given as parameter. */
static void init_thread(struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->stack = (uint8_t *)t + PGSIZE;
  t->magic = THREAD_MAGIC;
  sema_init(&t->sema, 0);

  if (!thread_mlfqs)
  {
    t->effective_priority = priority;
    t->base_priority = priority;
    list_init(&t->blocked_threads);
    t->priority_receiver = NULL;
  }
  old_level = intr_disable();
  list_push_back(&all_list, &t->allelem);

  /* The new thread inherits the parent thread's nice and recent_cpu value. */
  if (thread_mlfqs)
  {
    if (t == initial_thread)
    {
      t->nice = 0;
      t->recent_cpu = 0;
      t->effective_priority = PRI_MAX;
    }
    else
    {
      t->nice = thread_get_nice();
      t->recent_cpu = thread_current()->recent_cpu;
      update_priority(t, NULL);
    }
  }

  intr_set_level(old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *alloc_frame(struct thread *t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled (highest priority thread). 
   Should return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *next_thread_to_run(void)
{
  if (thread_mlfqs)
  {
    int priority = PRI_MAX;
    while (priority >= PRI_MIN && list_empty(&priority_queues_array[priority]))
    {
      priority--;
    }

    /* All queues are empty */
    if (priority == -1)
    {
      return idle_thread;
    }
    struct thread *next = list_entry(list_pop_front(&priority_queues_array[priority]), struct thread, elem);
    number_of_threads_in_queue_array--;
    return next;
  }
  else
  {
    if (list_empty(&ready_list))
    {
      return idle_thread;
    }
    else
    {
      struct thread *next = highest_priority_thread(&ready_list);
      list_remove(&next->elem);
      return next;
    }
  }
}
/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void thread_schedule_tail(struct thread *prev)
{
  struct thread *cur = running_thread();

  ASSERT(intr_get_level() == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
  {
    ASSERT(prev != cur);
    palloc_free_page(prev);
  }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void schedule(void)
{
  struct thread *cur = running_thread();
  struct thread *next = next_thread_to_run();
  struct thread *prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  if (cur != next)
    prev = switch_threads(cur, next);
  thread_schedule_tail(prev);
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);
