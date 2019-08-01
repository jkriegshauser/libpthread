#include <pthread.h>
#include <semaphore.h>

#include <stdlib.h>
#include <stdbool.h>
#if defined(_MSC_VER)
#include <malloc.h>
#endif
#include <process.h>
#include <signal.h>
#include <sys/queue.h>
#if _DURANGO
#include <limits.h>
#include <stddef.h>
#endif
#include "private.h"

#define MAX_READ_LOCKS              (INT_MAX-1)

#define PTHREAD_ONCE_RACEWINNER     (1)
#define PTHREAD_ONCE_DONE           ((LONG)(~0))

#define ALLOCATED_KEY               ((destructor)(size_t)1)

/* additional flags */
#define PTHREAD_EXITING             (0x1000)

#define INLINE __inline
#define FORCEINLINE __forceinline

void *malloc_wrapper(size_t size)
{
    return malloc(size);
}

void free_wrapper(void *mem)
{
    free(mem);
}

__declspec(selectany) extern void *(*libpthread_malloc)(size_t size) = &malloc_wrapper;
__declspec(selectany) extern void  (*libpthread_free)(void *mem) = &free_wrapper;

#ifdef _MSC_VER
#pragma warning(disable: 4702) /* unreachable code */
#endif

void* libpthread_calloc(size_t num, size_t size)
{
    void* mem = libpthread_malloc(num * size);
    if (mem)
    {
        memset(mem, 0, num * size);
    }
    return mem;
}

struct THREADNAME_INFO
{
    DWORD dwType;
    LPCSTR szName;
    DWORD dwThreadID;
    DWORD dwFlags;
};

/* structures */

typedef enum join_state
{
    destroyed           = -4, /* pthread_s struct is in a destroyed state */
    detached_exited     = -3, /* pthread is detached, and has completed, but not yet destroyed */
    detached            = -2, /* pthread is running and is detached */
    joinable_exited     = -1, /* pthread is joinable, and has completed */
    joinable            = 0   /* pthread is running and is joinable */
} join_state;

typedef enum _pthread_waittype
{
    wt_immediate = 0,
    wt_infinite,
    wt_timed
} _pthread_waittype;


struct pthread_s
{
    int magic;
    unsigned tid;
    LIST_ENTRY(pthread_s) entry;
    void *arg;
    void *retval;
    void *(*func)(void *);
    HANDLE h;
    volatile join_state joined; /* Or thread ID of joined thread */
    int canceled;
    unsigned state;
    cpu_set_t affinity;
    struct pthread_cleanup_s* cfn;
    char name[64];
    const void *keys[PTHREAD_KEYS_MAX];
};

struct sem_s
{
    int magic;
    long  value;
    void* handle;
    long  waiting;
};

struct pthread_rwlock_entry
{
    pthread_t thr;
    LIST_ENTRY(pthread_rwlock_entry) entry;
};

struct pthread_rwlock_s
{
    int magic;
    int state;
    pthread_mutex_t lock;
    pthread_cond_t readcond;
    pthread_cond_t writecond;
    int blocked_writers;
    LIST_HEAD(, pthread_rwlock_entry) locklist;
    LIST_HEAD(, pthread_rwlock_entry) freelist;
};

struct pthread_barrier_s
{
    int magic;
    unsigned count;
    void *sem;
    pthread_spinlock_t spin;
    unsigned waiting;
    volatile unsigned generation;
};

/* static vars */

/* key (thread-local variable) management */
typedef void(*destructor)(void *);
static int maxkey = -1;
static destructor destructors[PTHREAD_KEYS_MAX];

/* thread list */
__declspec(thread) static pthread_t _thisthread;
static struct pthread_s _main_thread = 
{
    PTHREAD_MAGIC_PTHREAD,  /* magic        */
    0,                      /* tid          */
    { NULL, NULL },         /* entry        */
    NULL,                   /* arg          */
    NULL,                   /* retval       */
    NULL,                   /* func         */
    NULL,                   /* h            */
    joinable,               /* joined       */
    0,                      /* canceled     */
    PTHREAD_DEFAULT_ATTR,   /* state        */
    (cpu_set_t)-1,          /* affinity     */
    NULL,                   /* cfn          */
    { '\0' },               /* name         */
    { NULL }                /* keys         */
};
static pthread_mutex_t pthread_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(pthread_list_t, pthread_s) pthread_list = LIST_HEAD_INITIALIZER(pthread_list_t);

/* prototypes */
static DWORD _pthread_ms_from_now(const FILETIME *ft);
static void  _pthread_convert_timespec(const struct timespec *tp, FILETIME *ft);

/* functions */

static INLINE int _pthread_setstate(unsigned *state, int flag, int val)
{
    unsigned old, new;
    RETURN_IF(~flag & val, EINVAL);

    for (;;)
    {
        old = *state;
        new = (old & ~flag) | val;
        if ((unsigned)ATOMIC_CMPXCHG(state, new, old) == old)
        {
            break;
        }
        PROC_YIELD();
    }

    return 0;
}

static INLINE int _pthread_getstate(unsigned state, int flag, int *val)
{
    RETURN_IF(!val, EINVAL);

    *val = state & flag;
    return 0;
}

static INLINE void _pthread_destruct_delay()
{
    /* Another thread may have a pointer to our thread data and may be 
       trying to use it while this thread is wanting to free memory and
       destroy itself. Therefore, we introduce a slight delay before 
       actually freeing memory. */
    Sleep(1000); /* Sleep for one second. */
}

static void _pthread_call_destructors(pthread_t t)
{
    int i, j, loop = 1;

    for (j = 0; j < PTHREAD_DESTRUCTOR_ITERATIONS && loop; ++j)
    {
        loop = 0;
        for (i = 0; i <= maxkey; ++i)
        {
            if ((size_t)destructors[i] > (size_t)ALLOCATED_KEY)
            {
                void *val = (void*)t->keys[i];
                if (val)
                {
                    t->keys[i] = NULL;
                    (*destructors[i])(val);
                    loop = 1; /* do another round */
                }
            }
        }
    }
}

inline static void _pthread_destroy(pthread_t p, int delay)
{
    HANDLE h = p->h;
    int res;

    /* clear the magic value first (abort if it's not expected) */
    ABORT_IF(ATOMIC_XCHG(&p->magic, 0) != PTHREAD_MAGIC_PTHREAD);

    /* remove from pthread list */
    ABORT_IF((res = pthread_mutex_lock(&pthread_list_mutex)) != 0);
    LIST_REMOVE(p, entry);
    ABORT_IF((res = pthread_mutex_unlock(&pthread_list_mutex)) != 0);

    if (delay)
    {
        _pthread_destruct_delay();
    }

    if (h) { CloseHandle(h); p->h = NULL; }
    
    if (p != &_main_thread)
    {
        libpthread_free(p);
    }
}

int pthread_attr_init(pthread_attr_t *attr)
{
    RETURN_IF(!attr, EINVAL);

    attr->p_state = PTHREAD_DEFAULT_ATTR;
    attr->s_size = 0;
    attr->cpuset = ((unsigned long long)~0);
    return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int flag)
{
    return attr ? _pthread_setstate(&attr->p_state, PTHREAD_MASK_JOINABLE_NP, flag) : EINVAL;
}

int pthread_attr_getdetachstate(pthread_attr_t *attr, int *flag)
{
    return attr ? _pthread_getstate(attr->p_state, PTHREAD_MASK_JOINABLE_NP, flag) : EINVAL;
}

int pthread_attr_setinheritsched(pthread_attr_t *attr, int flag)
{
    return attr ? _pthread_setstate(&attr->p_state, PTHREAD_MASK_SCHED_NP, flag) : EINVAL;
}

int pthread_attr_getinheritsched(pthread_attr_t *attr, int *flag)
{
    return attr ? _pthread_getstate(attr->p_state, PTHREAD_MASK_SCHED_NP, flag) : EINVAL;
}

int pthread_attr_setscope(pthread_attr_t *attr, int flag)
{
    return attr ? _pthread_setstate(&attr->p_state, PTHREAD_MASK_SCOPE_NP, flag) : EINVAL;
}

int pthread_attr_getscope(pthread_attr_t *attr, int *flag)
{
    return attr ? _pthread_getstate(attr->p_state, PTHREAD_MASK_SCOPE_NP, flag) : EINVAL;
}

int pthread_attr_setstacksize(pthread_attr_t *attr, int size)
{
    RETURN_IF(!attr, EINVAL);

    attr->s_size = size;
    return 0;
}

int pthread_attr_getstacksize(pthread_attr_t *attr, int *size)
{
    RETURN_IF(!attr, EINVAL);

    if (size)
        *size = (int)attr->s_size;
    return 0;
}

int pthread_attr_setaffinity_np(pthread_attr_t *attr, const cpu_set_t *cpuset)
{
    RETURN_IF(!attr || !cpuset, EINVAL);

    attr->cpuset = *cpuset;
    return 0;
}

int pthread_attr_getaffinity_np(pthread_attr_t *attr, cpu_set_t *cpuset)
{
    RETURN_IF(!attr || !cpuset, EINVAL);

    *cpuset = attr->cpuset;
    return 0;
}

void _pthread_push_cfn(struct pthread_cleanup_s *cfn, void (* func)(void *), void *arg)
{
    pthread_t self = pthread_self();
    cfn->next = self->cfn;
    cfn->func = func;
    cfn->arg = arg;
    self->cfn = cfn;
}

void _pthread_pop_cfn(int execute)
{
    pthread_t self = pthread_self();
    struct pthread_cleanup_s *cfn = self->cfn;
    assert(cfn);
    self->cfn = cfn->next;
    if (execute)
    {
        (*cfn->func)(cfn->arg);
    }
}

static pthread_t _pthread_create_external(int mainthread)
{
    int res;

    /* thread not created through pthread_create */

    ABORT_IF((res = pthread_mutex_lock(&pthread_list_mutex)) != 0);
    if (mainthread || LIST_EMPTY(&pthread_list))
    {
        /* no other threads; we're probably the main thread */
        mainthread = 1;

        /* hold the lock until we're done */
    }
    else
    {
        ABORT_IF((res = pthread_mutex_unlock(&pthread_list_mutex)) != 0);
    }

    pthread_t p = 
        mainthread ? &_main_thread : (struct pthread_s*)libpthread_calloc(1, sizeof(struct pthread_s));
    ABORT_IF(!p);

    /* Docs state that GetCurrentThread() isn't a handle that threads can refer to each other by,
    so this wouldn't be valid for joining. Therefore, we duplicate it. */
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &p->h, SYNCHRONIZE | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, FALSE, 0);
    assert(p->h);

    p->joined = joinable;
    p->state = PTHREAD_DEFAULT_ATTR;
    p->tid = GetCurrentThreadId();
    p->magic = PTHREAD_MAGIC_PTHREAD;

    _thisthread = p;

    /* add to pthread_list */
    if (!mainthread)
    {
        ABORT_IF((res = pthread_mutex_lock(&pthread_list_mutex)) != 0);
    }
    LIST_INSERT_HEAD(&pthread_list, p, entry);
    ABORT_IF((res = pthread_mutex_unlock(&pthread_list_mutex)) != 0);

    return p;
}

pthread_t pthread_self(void)
{
    pthread_t p = _thisthread;

    if (!p)
    {
        p = _pthread_create_external(0);
    }

    ABORT_IF(p->magic != PTHREAD_MAGIC_PTHREAD); /* possibly destroyed */

    return p;
}

/* thread entry point */
static unsigned WINAPI pthread_start(void *arg)
{
    pthread_t p = (pthread_t)arg;
    ABORT_IF(!p->h || p->h == INVALID_HANDLE_VALUE);
    ABORT_IF(p->magic != PTHREAD_MAGIC_PTHREAD);

    _thisthread = p;

    /* thread affinity */
    SetThreadAffinityMask(GetCurrentThread(), p->affinity);

    /* call thread function and pass result to pthread_exit() */
    pthread_exit((*p->func)(p->arg));

    return 0;
}

int pthread_create(pthread_t *th, pthread_attr_t *attr, void *(*func) (void *), void *arg)
{
    int res;
    pthread_t p;
    size_t stacksize = 0;
    DWORD_PTR paffinity, saffinity;

    RETURN_IF(!th || !func, EINVAL);

    *th = p = (struct pthread_s*)libpthread_calloc(1, sizeof(struct pthread_s));
    RETURN_IF(!p, EAGAIN);

    p->arg = arg;
    p->func = func;
    p->state = PTHREAD_DEFAULT_ATTR;
    p->h = INVALID_HANDLE_VALUE; /* initialize to invalid value */
    p->joined = joinable;
    GetProcessAffinityMask(GetCurrentProcess(), &paffinity, &saffinity);
    p->affinity = paffinity; /* process */

    if (attr)
    {
        p->state = attr->p_state;
        stacksize = attr->s_size;
        if (p->state & PTHREAD_CREATE_DETACHED)
        {
            p->joined = detached;
        }
        CPU_AND(p->affinity, p->affinity, attr->cpuset);
    }

    p->magic = PTHREAD_MAGIC_PTHREAD;

    /* add to the list of pthreads */
    ABORT_IF((res = pthread_mutex_lock(&pthread_list_mutex)) != 0);
    LIST_INSERT_HEAD(&pthread_list, p, entry);
    ABORT_IF((res = pthread_mutex_unlock(&pthread_list_mutex)) != 0);

    p->h = (HANDLE)_beginthreadex(NULL, (unsigned)stacksize, pthread_start, p, CREATE_SUSPENDED, &p->tid);
    if (!p->h)
    {
        _pthread_destroy(p, 0);
        *th = NULL;
        return EAGAIN;
    }

    /* started suspended, so resume now */
    ABORT_IF(ResumeThread(p->h) == -1);

    return 0;
}

static void _pthread_join_cancel(void* v)
{
    pthread_t p = (pthread_t)v;
    join_state s = !!(p->state & PTHREAD_EXITING) ? joinable_exited : joinable;
    ATOMIC_XCHG(&p->joined, s);
}

int pthread_join(pthread_t t, void **res)
{
    int retval;
    join_state s;
    pthread_t self = pthread_self();
    HANDLE h;
    
    /* error if the target thread is not valid */
    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);
    h = t->h;
    RETURN_IF(!h, ESRCH);

    /* error if we're joining ourself or we've been joined by the target */
    RETURN_IF(self == t || self->joined == (LONG)t->tid, EDEADLK);

    /* attempt to join this thread */
join_attempt:
    s = t->joined;
    RETURN_IF(s <= detached, ESRCH); /* detached or destroyed */
    RETURN_IF(s > joinable, EINVAL); /* already joined by another thread */
    if (ATOMIC_CMPXCHG(&t->joined, (long)self->tid, s) != s)
    {
        goto join_attempt;
    }

    ATOMIC_READ_WRITE_BARRIER();

    /* Check again that we were not joined simultaneously by the target thread.
       If we were, un-join. */
    if (self->joined == (LONG)t->tid)
    {
        _pthread_join_cancel(t);
        return EDEADLK;
    }

    /* Push a cancellation function. POSIX specifies that if 
       our thread is canceled, the thread should remain joinable. */
    pthread_cleanup_push(_pthread_join_cancel, t);

    /* Wait for thread to finish or cancellation */
    retval = 0;
again:
    switch (WaitForSingleObjectEx(h, INFINITE, TRUE))
    {
    case WAIT_IO_COMPLETION:
        goto again;

    case WAIT_OBJECT_0:
        /* thread finished. Read result and return */
        if (res) *res = t->retval;

        _pthread_destroy(t, 0);
        retval = 0;
        break;

    default:
        /* Waiting failed for some reason */
        retval = ESRCH;
        break;
    }

    pthread_cleanup_pop(0);

    return retval;
}

int pthread_detach(pthread_t t)
{
    join_state val;
    HANDLE h;

    /* check for invalid thread */
    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);
    h = t->h;
    RETURN_IF(!h, ESRCH);

    /* Mark as not joinable */
detach_retry:
    val = t->joined;
    RETURN_IF(val > joinable, EINVAL); /* another thread has already joined */
    RETURN_IF(val == destroyed, EINVAL); /* already destroyed */

    /* try to set detached state keeping exited status */
    if ((val == joinable && ATOMIC_CMPXCHG(&t->joined, detached, val) != val) ||
        (val == joinable_exited && ATOMIC_CMPXCHG(&t->joined, detached_exited, val) != val))
    {
        goto detach_retry;
    }

    /* if already exited, try to win the race for destruction */
detach_retry2:
    val = t->joined;
    if (val == joinable_exited || val == detached_exited)
    {
        if (ATOMIC_CMPXCHG(&t->joined, destroyed, val) != val)
        {
            goto detach_retry2;
        }

        /* we won the race for destruction */
        _pthread_destroy(t, 0);
    }

    return 0;
}

int pthread_kill(pthread_t t, int sig)
{
    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);
    switch (sig)
    {
    case 0: /* error checking, see if thread is still running */
        RETURN_IF(!!(t->state & PTHREAD_EXITING), ESRCH);
        return 0;

    default:
        /* unsupported signal number */
        return EINVAL;
    }
}

void pthread_exit(void *result)
{
    join_state s;
    int use_win32_api;
    pthread_t self = pthread_self();

    ABORT_IF(!self || self->magic != PTHREAD_MAGIC_PTHREAD);

    /* set the PTHREAD_EXITING flag */
    /* this used to abort() if it was already set, but occasionally the user APC can be re-entered. It appears that Windows doesn't remove
       a queued APC before calling it, so entering an alertable state again can re-call it. Therefore, everything in this function should
       be re-enterable. */
    ATOMIC_OR(&self->state, PTHREAD_EXITING);
    self->retval = result;

    /* pop and execute any cancellation handlers */
    while (self->cfn)
    {
        struct pthread_cleanup_s* cfn = self->cfn;
        self->cfn = self->cfn->next; /* pop */
        (*cfn->func)(cfn->arg);
    }

    /* call any pthread_key destructors */
    _pthread_call_destructors(self);

    /* mark our joined state as exited. this is a hint to pthread_join and pthread_detach so
       that we don't have a race condition where the thread struct is never destroyed */
exit_retry:
    s = self->joined;
    if ((s == joinable && ATOMIC_CMPXCHG(&self->joined, joinable_exited, s) != s) ||
        (s == detached && ATOMIC_CMPXCHG(&self->joined, detached_exited, s) != s))
    {
        goto exit_retry;
    }

    /* the thread function will be NULL if the pthread_t struct was created by pthread_self() instead of pthread_create() */
    use_win32_api = !self->func;

    /* try to mark as destroyed if we were detached. This will give us rights to destroy the thread data */
exit_retry2:
    s = self->joined;
    if (s == detached || s == detached_exited)
    {
        if (ATOMIC_CMPXCHG(&self->joined, destroyed, s) != s)
        {
            goto exit_retry2;
        }

        /* won the race to destroy thread data. if the thread is joined, then the thread that has joined will destroy the thread data */
        _pthread_destroy(self, 1);
        self = NULL; /* self is destroyed now */
    }

    if (use_win32_api)
    {
        /* Unknown how this thread started, so use Win32 API to terminate */
        ExitThread((DWORD)(size_t)result);
    }
    else
    {
        /* We started this thread, so terminate with _endthreadex */
        _endthreadex((unsigned)(size_t)result);
    }
}

int pthread_main_np(void)
{
    if (&_main_thread == pthread_self())
    {
        /* -1 if the thread's initialization has not yet completed */
        return _main_thread.tid == 0 ? -1 : 1;
    }
    return 0;
}

/* See http://msdn.microsoft.com/en-us/library/xcb2z8hs(v=vs.100).aspx */
#define MS_VC_EXCEPTION (0x406D1388)
int pthread_setname_np(pthread_t t, const char *name)
{
    struct THREADNAME_INFO info;
    size_t len;

    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);
    RETURN_IF(!name, EINVAL);

    len = strlen(name);
    if (len >= sizeof(t->name)) { len = sizeof(t->name) - 1; }
    memcpy(t->name, name, len);
    memset(t->name + len, 0, sizeof(t->name) - len);

    /* stop here if tid is zero */
    RETURN_IF(t->tid == 0, 0);

    info.dwType = 0x1000;
    info.szName = name;
    info.dwThreadID = t->tid;
    info.dwFlags = 0;

    __try
    {
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info)/sizeof(ULONG_PTR), (ULONG_PTR*)&info);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return 0;
}

int pthread_getname_np(pthread_t t, char *name, size_t len)
{
    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);
    RETURN_IF(!name, EINVAL);
    RETURN_IF(len < 16, ERANGE); /* NOTE: This hard-coded value comes from the pthread spec, but we support longer strings. */

    memcpy(name, t->name, len < sizeof(t->name) ? len : sizeof(t->name));
    name[len - 1] = '\0';
    return 0;
}

static void _pthread_once_cancel(void *control)
{
    *(pthread_once_t*)control = PTHREAD_ONCE_INIT;
}

int pthread_once(pthread_once_t *control, void (*fn)())
{
    long state;

    RETURN_IF(!control || !fn, EINVAL);

    state = *control;

    ATOMIC_READ_WRITE_BARRIER();

    /* spin while not done (~0). ideally this would put threads to sleep instead of spinning as initialization can take a long time */
    while (state != PTHREAD_ONCE_DONE)
    {
        if (state == PTHREAD_ONCE_INIT)
        {
            /* try to be the one to win the init privilege */
            if (ATOMIC_CMPXCHG(control, PTHREAD_ONCE_RACEWINNER, PTHREAD_ONCE_INIT) == PTHREAD_ONCE_INIT)
            {
                /* we won the race */

                /* the docs specify that cancellation during fn execution behaves as though
                   pthread_once was not called. */
                /* Also, pthread_once is NOT a cancellation point, so we can't test cancel here */
                pthread_cleanup_push(_pthread_once_cancel, control);
                
                (*fn)();

                /* If a thread /does/ get canceled inside of the function call, then we never get here. 
                   Either another thread that is contending inside of pthread_once() or a future call
                   will complete the process (if it is not canceled itself) and mark the control as done. */

                pthread_cleanup_pop(0);

                /* mark as done */
                ATOMIC_XCHG(control, PTHREAD_ONCE_DONE);

                return 0;
            }
        }

        PROC_YIELD();
        ATOMIC_READ_WRITE_BARRIER();

        state = *control;
    }

    return 0;
}

static void WINAPI _pthread_cancel_self(ULONG_PTR ignore)
{
    (void)ignore;
    /* terminate */
    pthread_exit(PTHREAD_CANCELED);
    /* THIS FUNCTION MUST NOT RETURN */
    abort();
}

static int _pthread_async_cancel(pthread_t t)
{
    /* async cancel is ugly since we don't have signal support */
    CONTEXT context;
    HANDLE h = t->h;

    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_CONTROL;

    /* t is guaranteed to be a different thread */
    /* if the cancellation has already succeeded via the queued APC then this can fail */
    if (SuspendThread(h) == (DWORD)-1)
    {
        return !(t->state & PTHREAD_EXITING) ? ESRCH : 0;
    }

    /* make sure that we haven't started exiting yet */
    if (!(t->state & PTHREAD_EXITING))
    {
        RETURN_IF(GetThreadContext(h, &context) != TRUE, ESRCH);

        /* Set the instruction pointer to the cancel function. Yes, this is scary. */
        context.ContextFlags = CONTEXT_CONTROL;
#if _M_X64 || _M_IA64
        context.Rip = (uintptr_t)_pthread_cancel_self;
#else
        context.Eip = (uintptr_t)_pthread_cancel_self;
#endif

        RETURN_IF(SetThreadContext(h, &context) != TRUE, ESRCH);
    }
    RETURN_IF(ResumeThread(h) == (DWORD)-1, ESRCH);

    return 0;
}

int pthread_cancel(pthread_t t)
{
    int err;

    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);

    /* deferred cancel always; if we've already canceled then return */
    RETURN_IF(ATOMIC_XCHG(&t->canceled, 1) != 0, 0); 

    /* Can't proceed if cancellation is disabled, but it will be checked when canceling is enabled. */
    RETURN_IF((t->state & PTHREAD_MASK_CANCELABLE_NP) == PTHREAD_CANCEL_DISABLE, 0);

    if (pthread_self() == t)
    {
        /* canceling ourself */
        _pthread_cancel_self(0);
        return 0;
    }

    /* try async cancel if allowed */
    if ((t->state & PTHREAD_MASK_CANCELTYPE_NP) == PTHREAD_CANCEL_ASYNCHRONOUS)
    {
        err = _pthread_async_cancel(t);
        if (err != 0)
        {
            return err;
        }
    }

    /* Queue a user APC for when the thread enters a cancelable function */
    QueueUserAPC(_pthread_cancel_self, t->h, 0);

    return 0;
}

void pthread_testcancel(void)
{
    pthread_t self = pthread_self();
    if (self->canceled && (self->state & PTHREAD_MASK_CANCELABLE_NP) == PTHREAD_CANCEL_ENABLE)
    {
        _pthread_cancel_self(0);
    }
}

int pthread_setcancelstate(int state, int *oldstate)
{
    int retval;
    pthread_t self = pthread_self();

    if (oldstate) *oldstate = self->state & PTHREAD_MASK_CANCELABLE_NP;
    retval = _pthread_setstate(&self->state, PTHREAD_MASK_CANCELABLE_NP, state);
    
    /* always check our cancel state */
    pthread_testcancel();
    
    return retval;
}

int pthread_setcanceltype(int type, int *oldtype)
{
    pthread_t self = pthread_self();

    if (oldtype) *oldtype = self->state & PTHREAD_MASK_CANCELTYPE_NP;
    return _pthread_setstate(&self->state, PTHREAD_MASK_CANCELTYPE_NP, type);
}

int pthread_setschedprio(pthread_t t, int prio)
{
    int winprio = THREAD_PRIORITY_NORMAL;

    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, EINVAL);

    /* re-map the priority values to windows values */
    /*
     0 - Idle
     1-6 - Lowest
     7-12 - Below Normal
     13-18 - Normal
     19-24 - Above Normal
     25-30 - Highest
     31 - Time Critical
     */
    if (prio <= 0) { winprio = THREAD_PRIORITY_IDLE; }
    else if (prio <= 6) { winprio = THREAD_PRIORITY_LOWEST; }
    else if (prio <= 12) { winprio = THREAD_PRIORITY_BELOW_NORMAL; }
    else if (prio <= 18) { winprio = THREAD_PRIORITY_NORMAL; }
    else if (prio <= 24) { winprio = THREAD_PRIORITY_ABOVE_NORMAL; }
    else if (prio <= 30) { winprio = THREAD_PRIORITY_HIGHEST; }
    else { winprio = THREAD_PRIORITY_TIME_CRITICAL; }
    
    return SetThreadPriority(t->h, winprio) == TRUE ? 0 : EINVAL;
}

int pthread_setschedparam(pthread_t t, int policy, const struct sched_param *param)
{
    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);

    RETURN_IF(policy != SCHED_RR, EINVAL);

    return pthread_setschedprio(t, param->sched_priority);
}

int pthread_getschedparam(pthread_t t, int *policy, struct sched_param *param)
{
    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);
    
    if (policy) *policy = SCHED_RR;

    if (param)
    {
        int winprio = GetThreadPriority(t->h);
        RETURN_IF(winprio == THREAD_PRIORITY_ERROR_RETURN, EPERM);
        if (winprio <= THREAD_PRIORITY_IDLE)                { param->sched_priority = SCHED_PRIORITY_MIN; }
        else if (winprio <= THREAD_PRIORITY_LOWEST)         { param->sched_priority = 3; }
        else if (winprio <= THREAD_PRIORITY_BELOW_NORMAL)   { param->sched_priority = 9; }
        else if (winprio <= THREAD_PRIORITY_NORMAL)         { param->sched_priority = SCHED_PRIORITY_DEFAULT; }
        else if (winprio <= THREAD_PRIORITY_ABOVE_NORMAL)   { param->sched_priority = 21; }
        else if (winprio <= THREAD_PRIORITY_HIGHEST)        { param->sched_priority = 27; }
        else                                                { param->sched_priority = SCHED_PRIORITY_MAX; }
    }

    return 0;
}

int pthread_setaffinity_np(pthread_t t, const cpu_set_t *cpuset)
{
    HANDLE h;

    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);
    h = t->h;
    RETURN_IF(!h, ESRCH);

    RETURN_IF(SetThreadAffinityMask(h, (DWORD_PTR)*cpuset) != TRUE, EINVAL);

    t->affinity = *cpuset;
    return 0;
}

int pthread_getaffinity_np(pthread_t t, cpu_set_t *cpuset)
{
    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);

    *cpuset = t->affinity;
    return 0;
}

int pthread_enumerate_threads_np(void(*func)(pthread_t, void*), void *user)
{
    pthread_t p, n;
    int res;

    RETURN_IF(!func, EINVAL);

    ABORT_IF((res = pthread_mutex_lock(&pthread_list_mutex)) != 0);

    /* call for each thread in the list */
    LIST_FOREACH_SAFE(p, &pthread_list, entry, n)
    {
        (*func)(p, user);
    }

    ABORT_IF((res = pthread_mutex_unlock(&pthread_list_mutex)) != 0);

    return 0;
}

int pthread_os_handle_np(pthread_t t, void **h)
{
    RETURN_IF(!h, EINVAL);
    RETURN_IF(!t || t->magic != PTHREAD_MAGIC_PTHREAD, ESRCH);

    *h = t->h;
    RETURN_IF(!*h, ESRCH); /* Detached; handle already closed */

    return 0;
}

int pthread_key_create(pthread_key_t *key, void (*dest)(void *))
{
    int i, mkey, res;

    RETURN_IF(!key, EINVAL);

    if (!dest) dest = ALLOCATED_KEY;

    for (i = 0; i < PTHREAD_KEYS_MAX; ++i)
    {
        if (ATOMIC_CMPXCHG_PTR(&destructors[i], dest, NULL) == NULL)
        {
            *key = i;

set_maxkey_retry:
            mkey = maxkey;
            if (mkey < i)
            {
                if (ATOMIC_CMPXCHG(&maxkey, i, mkey) != mkey)
                {
                    goto set_maxkey_retry;
                }
            }
            else
            {
                /* re-using a deleted key. clear the slot in all threads */
                pthread_t p;
                ABORT_IF((res = pthread_mutex_lock(&pthread_list_mutex)) != 0);
                LIST_FOREACH(p, &pthread_list, entry)
                {
                    p->keys[i] = NULL;
                }
                ABORT_IF((res = pthread_mutex_unlock(&pthread_list_mutex)) != 0);
            }

            return 0;
        }
    }

    return EAGAIN;
}

int pthread_key_delete(pthread_key_t key)
{
    /* check for valid key */
    RETURN_IF(key < 0 || key >= PTHREAD_KEYS_MAX || destructors[key] == NULL, EINVAL);

    destructors[key] = NULL;

    /* POSIX states that we don't have to run any destructors when the keys are deleted */

    return 0;
}

void *pthread_getspecific(pthread_key_t key)
{
    RETURN_IF(key < 0 || key >= PTHREAD_KEYS_MAX, NULL);

    return (void*)pthread_self()->keys[key];
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
    RETURN_IF(key < 0 || key >= PTHREAD_KEYS_MAX, EINVAL);

    pthread_self()->keys[key] = value;
    return 0;
}

static HANDLE _pthread_create_sem(void* volatile *psem, int count, int max)
{
    /* Always create a semaphore. If we don't manage to assign it, then we'll destroy it. */
    HANDLE h, local = WinCreateSemaphore(NULL, count, max, NULL, 0, SEMAPHORE_ALL_ACCESS);
    ABORT_IF(!local); /* Couldn't create a semaphore */

    if ((h = ATOMIC_CMPXCHG_PTR(psem, local, NULL)) == NULL)
    {
        return local;
    }
    else
    {
        /* Another thread won the creation race. Destroy our Semaphore */
        CloseHandle(local);
        return h;
    }
}

static HANDLE _pthread_create_event(void* volatile *pevt)
{
    HANDLE h, local = CreateEventW(NULL, FALSE, FALSE, NULL);
    ABORT_IF(!local); /* Couldn't create the event */

    if ((h = ATOMIC_CMPXCHG_PTR(pevt, local, NULL)) == NULL)
    {
        return local;
    }
    else
    {
        /* Another thread won the creation race. Destroy our local copy */
        CloseHandle(local);
        return h;
    }
}

int pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
    RETURN_IF(!attr, EINVAL);
    attr->type = PTHREAD_MUTEX_DEFAULT;
    return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
    RETURN_IF(!attr, EINVAL);
    return 0;
}

int pthread_mutexattr_getpshared(pthread_mutexattr_t *attr, int *pshared)
{
    RETURN_IF(!attr || !pshared, EINVAL);
    *pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared)
{
    RETURN_IF(!attr, EINVAL);
    RETURN_IF(pshared != PTHREAD_PROCESS_PRIVATE, EINVAL); /* not supported, but ENOTSUP is not a proper return value */
    return 0;
}

int pthread_mutexattr_gettype(pthread_mutexattr_t *attr, int *type)
{
    RETURN_IF(!attr || !type, EINVAL);
    *type = attr->type;
    return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type)
{
    RETURN_IF(!attr, EINVAL);
    RETURN_IF(type < 0 || type >= PTHREAD_MUTEX_DEFAULT, EINVAL);
    attr->type = type; /* save, but don't use. Our default mutex fits all types */
    return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr)
{
    RETURN_IF(!mutex, EINVAL);

    mutex->magic = PTHREAD_MAGIC_MUTEX;
    mutex->recursion = 0;
    mutex->u.flags = 0;
    mutex->owner = 0;
    mutex->sem = NULL; /* Lazy initialization */

    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    RETURN_IF(!mutex || mutex->magic != PTHREAD_MAGIC_MUTEX, EINVAL);
    RETURN_IF(!!mutex->owner, EBUSY);

    /* clear the magic value first */
    RETURN_IF(ATOMIC_XCHG(&mutex->magic, 0) != PTHREAD_MAGIC_MUTEX, EINVAL);
    if (mutex->sem) { CloseHandle(mutex->sem); }
    mutex->sem = NULL;

    return 0;
};

FORCEINLINE static int _pthread_mutex_lock(pthread_mutex_t *mutex, _pthread_waittype wt, const struct timespec *abstime)
{
    HANDLE h;
    long oldval, newval, temp;
    DWORD tid = GetCurrentThreadId();
    FILETIME ft;

    RETURN_IF(!mutex || mutex->magic != PTHREAD_MAGIC_MUTEX, EINVAL);

    if (!InterlockedBitTestAndSet(&mutex->u.flags, 0))
    {
        /* The locked flag was previously clear and is now set, so we acquired the mutex */
        mutex->owner = tid;
        mutex->recursion = 1;
        return 0;
    }

    if (mutex->owner == tid)
    {
        /* we already own the lock */
        ++mutex->recursion;
        return 0;
    }

    if (wt == wt_immediate)
    {
        /* mutex is busy; can't lock right now */
        return EBUSY;
    }

    if (wt == wt_timed)
    {
        /* abstime validity check */
        RETURN_IF(!abstime, EINVAL);
        RETURN_IF(abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000, EINVAL);
        _pthread_convert_timespec(abstime, &ft);
    }

    /* TODO: Spin a bit?? CRITICAL_SECTION supports this... */

    /* Need to wait; mark ourself as a waiter */
    temp = mutex->u.flags;
    do 
    {
        ATOMIC_READ_WRITE_BARRIER();
        oldval = temp;
        newval = (oldval + (1 << 2)); /* skip the two flag bits */
    } while ((temp = ATOMIC_CMPXCHG(&mutex->u.flags, newval, oldval)) != oldval);

    /* at this point, check once more to avoid a race condition with unlock where 
       we weren't yet marked as a waiter and it finished unlocking */
    if (!InterlockedBitTestAndSet(&mutex->u.flags, 0))
    {
        /* got it; remove ourselves as a waiter */
        temp = mutex->u.flags;
        do 
        {
            ATOMIC_READ_WRITE_BARRIER();
            oldval = temp;
            newval = (oldval - (1 << 2)); /* skip the two flag bits */
            assert((oldval >> 2) >= 1); /* there should be at least a count for us to remove */
        } while ((temp = ATOMIC_CMPXCHG(&mutex->u.flags, newval, oldval)) != oldval);

        /* inside the lock */
        mutex->owner = tid;
        mutex->recursion = 1;

        return 0;
    }

    /* create the event if it hasn't been created yet */
    h = mutex->sem;
    if (!h)
    {
        h = _pthread_create_event(&mutex->sem);
    }

    /* loop and wait until we can acquire the mutex */
    for (;;)
    {
        /* the mutex wait functions are not cancellation points */
        switch (WaitForSingleObject(h, wt == wt_timed ? _pthread_ms_from_now(&ft) : INFINITE))
        {
        case WAIT_OBJECT_0:
            /* consumed the signal; clear the signaled flag */
            /* do this before trying to lock the bit so that we don't race with another thread calling unlock */
            temp = mutex->u.flags;
            do 
            {
                ATOMIC_READ_WRITE_BARRIER();
                oldval = temp;
                newval = oldval & ~2;
                assert(oldval != newval); /* something else already cleared the flag? shouldn't be possible */
            } while ((temp = ATOMIC_CMPXCHG(&mutex->u.flags, newval, oldval)) != oldval);

            /* we might be able to acquire the mutex now */
            if (!InterlockedBitTestAndSet(&mutex->u.flags, 0))
            {
                /* got it; clear our waiting status */
                temp = mutex->u.flags;
                do
                {
                    ATOMIC_READ_WRITE_BARRIER();
                    oldval = temp;
                    newval = (oldval - (1 << 2)); /* skip the flag bits */
                    assert((oldval >> 2) >= 1); /* there should be at least a count for us to remove */
                } while ((temp = ATOMIC_CMPXCHG(&mutex->u.flags, newval, oldval)) != oldval);

                mutex->owner = tid;
                mutex->recursion = 1;

                return 0;
            }

            /* didn't acquire the mutex yet, wait some more. */
            break;

        case WAIT_TIMEOUT:
            /* timed out. remove ourself as a waiter */
            if (wt == wt_timed)
            {
                temp = mutex->u.flags;
                do
                {
                    ATOMIC_READ_WRITE_BARRIER();
                    oldval = temp;
                    newval = (oldval - (1 << 2)); /* skip the two flag bits */
                    assert((oldval >> 2) >= 1); /* there should be at least a count for us to remove */
                } while ((temp = ATOMIC_CMPXCHG(&mutex->u.flags, newval, oldval)) != oldval);

                return ETIMEDOUT;
            }
            /* fall through */

        default:
            /* error case */
            abort();
        }
    }
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    return _pthread_mutex_lock(mutex, wt_infinite, NULL);
}

int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abstime)
{
    return _pthread_mutex_lock(mutex, wt_timed, abstime);
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
    return _pthread_mutex_lock(mutex, wt_immediate, NULL);
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    HANDLE h;
    DWORD tid = GetCurrentThreadId();
    long oldval, newval, temp;
    int signal_thread;

    RETURN_IF(!mutex || mutex->magic != PTHREAD_MAGIC_MUTEX, EINVAL);

    /* make sure we're the owner */
    RETURN_IF(tid != mutex->owner, EPERM);

    if (--mutex->recursion == 0)
    {
        /* unlocking */
        mutex->owner = 0;
        
        temp = mutex->u.flags;
        do
        {
            ATOMIC_READ_WRITE_BARRIER();
            oldval = temp;
            newval = oldval & ~1; /* clear locked flag */
            signal_thread = ((oldval >> 2) > 0) && !(oldval & 2); 
            if (signal_thread)
            {
                newval |= 2; /* set signaled flag */
            }
        } while ((temp = ATOMIC_CMPXCHG(&mutex->u.flags, newval, oldval)) != oldval);

        /* release a waiter */
        if (signal_thread)
        {
            h = mutex->sem;
            if (!h)
            {
                h = _pthread_create_event(&mutex->sem);
            }
            SetEvent(h);
        }
    }

    /* now free of the lock */
    return 0;
}

int pthread_spin_init(pthread_spinlock_t *lock, int pshared)
{
    RETURN_IF(!lock, EINVAL);
    RETURN_IF(pshared != PTHREAD_PROCESS_PRIVATE, ENOTSUP);

    lock->flags = 0;
    return 0;
}

int pthread_spin_destroy(pthread_spinlock_t *lock)
{
    RETURN_IF(!lock, EINVAL);
    RETURN_IF(!!lock->flags, EBUSY); /* destroy while locked */
    return 0;
}

int pthread_spin_lock(pthread_spinlock_t *lock)
{
    unsigned tid = (unsigned)GetCurrentThreadId();

    RETURN_IF(!lock, EINVAL);
    RETURN_IF(lock->debug_info.tid == tid, EDEADLK); /* no recursive locking */
    assert((LONG)tid > 0); /* assumptions break if the high bit is set */

    /* attempt to atomically set the least significant bit */
    while (!!InterlockedBitTestAndSet(&lock->flags, 0))
    {
        /* was already set; pause */
        PROC_YIELD();
    }

    /* now inside the lock */
    assert(lock->debug_info.tid == 0);
    assert(!!lock->debug_info.locked);
    lock->debug_info.tid = tid;

    return 0;
}

int pthread_spin_trylock(pthread_spinlock_t *lock)
{
    unsigned tid = (unsigned)GetCurrentThreadId();

    RETURN_IF(!lock, EINVAL);
    RETURN_IF(lock->debug_info.tid == tid, EDEADLK);

    if (!InterlockedBitTestAndSet(&lock->flags, 0))
    {
        /* got the lock */
        assert(lock->debug_info.tid == 0);
        assert(!!lock->debug_info.locked);
        lock->debug_info.tid = tid;
        return 0;
    }

    return EBUSY;
}

int pthread_spin_unlock(pthread_spinlock_t *lock)
{
    unsigned tid = (unsigned)GetCurrentThreadId();

    RETURN_IF(!lock, EINVAL);
    RETURN_IF(lock->debug_info.tid != tid, EPERM);

    assert(!!lock->debug_info.locked);

    lock->flags = 0; /* unlock */

    return 0;
}

int pthread_condattr_init(pthread_condattr_t *attr)
{
    RETURN_IF(!attr, EINVAL);
    return 0;
}

int pthread_condattr_destroy(pthread_condattr_t *attr)
{
    RETURN_IF(!attr, EINVAL);
    return 0;
}

int pthread_condattr_getpshared(pthread_condattr_t *attr, int *pshared)
{
    RETURN_IF(!attr || !pshared, EINVAL);
    *pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared)
{
    RETURN_IF(!attr, EINVAL);
    RETURN_IF(pshared != PTHREAD_PROCESS_PRIVATE, EINVAL); /* not supported, but ENOTSUP is not a proper return value */
    return 0;
}

int pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr)
{
    RETURN_IF(!cond, EINVAL);
    (void)attr; /* ignore */

    /* the waiters member always gets incremented by a thread waiting
       and decremented by a signal (or if a thread times out)
       it can go negative in the case where the condvar is signaled
       but a waiting thread times out instead of finishing waiting. */
    cond->waiters = 0;
    cond->sem = NULL;
    cond->mutex = NULL;
    cond->magic = PTHREAD_MAGIC_COND;
    
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond)
{
    RETURN_IF(!cond || cond->magic != PTHREAD_MAGIC_COND, EINVAL);
    RETURN_IF(cond->waiters > 0, EBUSY);

    /* clear the magic value first */
    RETURN_IF(ATOMIC_XCHG(&cond->magic, 0) != PTHREAD_MAGIC_COND, EINVAL);

    if (cond->sem)
    {
        CloseHandle(cond->sem);
        cond->sem = NULL;
    }

    return 0;
}

int pthread_cond_signal(pthread_cond_t *cond)
{
    HANDLE h;
    long old, temp;
    RETURN_IF(!cond || cond->magic != PTHREAD_MAGIC_COND, EINVAL);

    /* decrement the waiters if any are available for a signal */
    temp = cond->waiters;
    do 
    {
        ATOMIC_READ_WRITE_BARRIER();
        old = temp;
        if (old <= 0)
        {
            /* no waiters. It's possible for this value to be negative if
               a wait timed out. See _wait() for more information */
            return 0;
        }
    } while ((temp = ATOMIC_CMPXCHG(&cond->waiters, old - 1, old)) != old);

    /* notify a thread waiting. the semaphore should already be created,
       but if it isn't, try to create it ourselves. This should be very rare. */
    h = cond->sem;
    if (!h)
    {
        h = _pthread_create_sem(&cond->sem, 0, INT_MAX);
    }
    return (ReleaseSemaphore(h, 1, NULL) == TRUE) ? 0 : EINVAL;
}

int pthread_cond_broadcast(pthread_cond_t *cond)
{
    HANDLE h;
    long signals, temp;

    RETURN_IF(!cond || cond->magic != PTHREAD_MAGIC_COND, EINVAL);

    /* atomically set waiters to zero */
    temp = cond->waiters;
    do 
    {
        ATOMIC_READ_WRITE_BARRIER();
        signals = temp;
        if (signals <= 0)
        {
            /* no waiters. it's possible for this value to be negative if
               a wait timed out. See _wait() for more information */
            return 0;
        }
    } while ((temp = ATOMIC_CMPXCHG(&cond->waiters, 0, signals)) != signals);

    /* notify all threads waiting on the semaphore. the semaphore should
       already be created, but if it isn't, try to create it ourselves. This
       should be very rare. */
    h = cond->sem;
    if (!h)
    {
        h = _pthread_create_sem(&cond->sem, 0, INT_MAX);
    }
    return (ReleaseSemaphore(h, signals, NULL) == TRUE) ? 0 : EINVAL;
}

/* cancellation cleanup function for condition variables */
static void _pthread_cond_wait_cancel(void* p)
{
    pthread_cond_t* cond = (pthread_cond_t*)p;

    /* not waiting any more because canceled */
    ATOMIC_DEC(&cond->waiters);
}

FORCEINLINE static int _pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex, _pthread_waittype wt, const struct timespec *abstime)
{
    int res;
    int retval = 0;
    HANDLE h;
    FILETIME ft;

    /* error check */
    RETURN_IF(
        !cond || 
        !mutex || 
        cond->magic != PTHREAD_MAGIC_COND || 
        mutex->magic != PTHREAD_MAGIC_MUTEX ||
        mutex->owner != GetCurrentThreadId(), EINVAL);

    if (cond->mutex)
    {
        /* check if different mutex specified */
        RETURN_IF(cond->mutex != mutex, EINVAL);
    }
    else
    {
        cond->mutex = mutex;
    }

    if (wt == wt_timed)
    {
        /* abstime validity check */
        RETURN_IF(!abstime, EINVAL);
        RETURN_IF(abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000, EINVAL);
        _pthread_convert_timespec(abstime, &ft);
    }

    /* unlock the mutex */
    ABORT_IF((res = pthread_mutex_unlock(mutex)) != 0);

    /* notify that we're about to wait */
    ATOMIC_INC(&cond->waiters);

    /* typically this is where the semaphore is created, though any threads
       that broadcast may try to create it too. */
    h = cond->sem;
    if (!h)
    {
        h = _pthread_create_sem(&cond->sem, 0, INT_MAX);
    }

    /* push our cleanup function so that if we're canceled while waiting we get unmarked as a waiter */
    pthread_cleanup_push(_pthread_cond_wait_cancel, cond);

    /* wait on the semaphore. also, since pthread_cond_wait() and pthread_cond_timedwait() are
       cancellation points, we need to be alertable as well. */
again:
    switch (WaitForSingleObjectEx(h, wt == wt_timed ? _pthread_ms_from_now(&ft) : INFINITE, TRUE))
    {
    case WAIT_OBJECT_0:
        /* expected */
        break;

    case WAIT_IO_COMPLETION:
        goto again;

    case WAIT_TIMEOUT:
        if (wt == wt_timed)
        {
            retval = ETIMEDOUT;

            /* We're no longer waiting and didn't consume a signal, so decrement the waiting count.
               Note that there is a potential race condition here because _signal() and _broadcast() alter
               the wait count shortly before signaling the semaphore. If we time out during that window and
               decrement the wait count, then the wait count can go negative and a spurious wakeup could occur
               in the future. This is acceptable given the requirements of condition variables.
               */
            ATOMIC_DEC(&cond->waiters);
            break;
        }
        /* fall through intended */

    default:
        /* bad news */
        ABORT_IF(1);
    }

    pthread_cleanup_pop(0);

    /* lock the mutex before returning to the caller */
    ABORT_IF((res = pthread_mutex_lock(mutex)) != 0);

    return retval;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    return _pthread_cond_wait(cond, mutex, wt_infinite, NULL);
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime)
{
    return _pthread_cond_wait(cond, mutex, wt_timed, abstime);
}

int pthread_rwlockattr_init(pthread_rwlock_attr_t *attr)
{
    RETURN_IF(!attr, EINVAL);
    return 0;
}

int pthread_rwlockattr_destroy(pthread_rwlock_attr_t *attr)
{
    RETURN_IF(!attr, EINVAL);
    return 0;
}

int pthread_rwlockattr_getpshared(pthread_rwlock_attr_t *attr, int *pshared)
{
    RETURN_IF(!attr || !pshared, EINVAL);
    *pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

int pthread_rwlockattr_setpshared(pthread_rwlock_attr_t *attr, int pshared)
{
    RETURN_IF(!attr, EINVAL);
    RETURN_IF(pshared != PTHREAD_PROCESS_PRIVATE, EINVAL); /* not supported, but ENOTSUP is not a proper return value */
    return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *rw_, const pthread_rwlock_attr_t *attr)
{
    struct pthread_rwlock_s* rw;
    int ret;

    RETURN_IF(!rw_, EINVAL);
    (void)attr; /* ignore for now */

    *rw_ = NULL;
    rw = (struct pthread_rwlock_s*)libpthread_calloc(1, sizeof(struct pthread_rwlock_s));
    RETURN_IF(!rw, ENOMEM);

    if ((ret = pthread_mutex_init(&rw->lock, NULL)) != 0 ||
        (ret = pthread_cond_init(&rw->readcond, NULL)) != 0 ||
        (ret = pthread_cond_init(&rw->writecond, NULL)) != 0)
    {
        /* failed at least one. we're half-initialized, but since everything
           is zero-init (due to calloc) then it should be safe to call destroy
           on things that aren't fully created yet. */
        pthread_cond_destroy(&rw->writecond);
        pthread_cond_destroy(&rw->readcond);
        pthread_mutex_destroy(&rw->lock);
        libpthread_free(rw);

        return ret;
    }

    rw->state = 0;
    rw->blocked_writers = 0;
    rw->magic = PTHREAD_MAGIC_RWLOCK;

    *rw_ = rw;

    return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rw_)
{
    int res;
    struct pthread_rwlock_s *rw;
    struct pthread_rwlock_entry *e, *n;
    
    RETURN_IF(!rw_ || !*rw_ || (rw = *rw_)->magic != PTHREAD_MAGIC_RWLOCK, EINVAL);
    RETURN_IF(rw->state != 0 || rw->blocked_writers != 0, EBUSY);
    RETURN_IF(LIST_FIRST(&rw->locklist) != NULL, EBUSY);

    /* clear the magic value first */
    RETURN_IF(ATOMIC_XCHG(&rw->magic, 0) != PTHREAD_MAGIC_RWLOCK, EINVAL);
    *rw_ = NULL;

    /* destroy the free list */
    LIST_FOREACH_SAFE(e, &rw->freelist, entry, n)
    {
        libpthread_free(e);
    }

    /* if any of these fail, we're in a bad state. */
    ABORT_IF((res = pthread_mutex_destroy(&rw->lock)) != 0);
    ABORT_IF((res = pthread_cond_destroy(&rw->readcond)) != 0);
    ABORT_IF((res = pthread_cond_destroy(&rw->writecond)) != 0);

    libpthread_free(rw);

    return 0;
}

void _pthread_rwlock_add_lock_record(struct pthread_rwlock_s *rw, pthread_t thr)
{
    /* mutex must be locked */
    struct pthread_rwlock_entry *e = LIST_FIRST(&rw->freelist);
    if (e)
    {
        LIST_REMOVE(e, entry);
    }
    else
    {
        e = (struct pthread_rwlock_entry *)libpthread_calloc(1, sizeof(*e));
    }

    e->thr = thr;
    LIST_INSERT_HEAD(&rw->locklist, e, entry);
}

struct pthread_rwlock_entry *_pthread_rwlock_find_lock_record(struct pthread_rwlock_s *rw, pthread_t thr)
{
    /* mutex must be locked */
    struct pthread_rwlock_entry *e;
    LIST_FOREACH(e, &rw->locklist, entry)
    {
        if (e->thr == thr)
        {
            return e;
        }
    }
    return NULL;
}

bool _pthread_rwlock_remove_lock_record(struct pthread_rwlock_s *rw, pthread_t thr)
{
    struct pthread_rwlock_entry *e;
    LIST_FOREACH(e, &rw->locklist, entry)
    {
        if (e->thr == thr)
        {
            LIST_REMOVE(e, entry);
            LIST_INSERT_HEAD(&rw->freelist, e, entry);
            return true;
        }
    }
    return false;
}

FORCEINLINE static int _pthread_rwlock_rdlock(pthread_rwlock_t *rw_, _pthread_waittype wt, const struct timespec *abstime)
{
    int res, retval = 0;
    struct pthread_rwlock_s *rw;
    pthread_t self = pthread_self();

    RETURN_IF(!rw_ || !*rw_ || (rw = *rw_)->magic != PTHREAD_MAGIC_RWLOCK, EINVAL);

    /* acquire mutex */
    ABORT_IF((res = pthread_mutex_lock(&rw->lock)) != 0);

    /* avoid deadlock */
    if (_pthread_rwlock_find_lock_record(rw, self)) { retval = EDEADLK; goto done; }

    /* try */
again:
    if (!rw->blocked_writers && rw->state >= 0)
    {
        assert(retval == 0);
        if (rw->state < MAX_READ_LOCKS)
        {
            ++rw->state;
            _pthread_rwlock_add_lock_record(rw, self);
        }
        else
        {
            retval = EAGAIN;
        }
        goto done;
    }

    /* failed; wait if necessary */
    switch (wt)
    {
    case wt_immediate:
        retval = EBUSY;
        break;
    
    case wt_infinite:
        ABORT_IF((res = pthread_cond_wait(&rw->readcond, &rw->lock)) != 0);
        goto again;
    
    case wt_timed:
        retval = pthread_cond_timedwait(&rw->readcond, &rw->lock, abstime);
        if (retval == 0) goto again;
        break; /* error or timed out */
    }

done:
    /* release mutex */
    ABORT_IF((res = pthread_mutex_unlock(&rw->lock)) != 0);

    return retval;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rw_)
{
    return _pthread_rwlock_rdlock(rw_, wt_infinite, NULL);
}

int pthread_rwlock_timedrdlock(pthread_rwlock_t *rw_, const struct timespec *abstime)
{
    return _pthread_rwlock_rdlock(rw_, wt_timed, abstime);
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rw_)
{
    return _pthread_rwlock_rdlock(rw_, wt_immediate, NULL);
}

static void _pthread_rwlock_wrlock_cancel(void *rw_)
{
    --((struct pthread_rwlock_s *)rw_)->blocked_writers;
}

FORCEINLINE static int _pthread_rwlock_wrlock(pthread_rwlock_t *rw_, _pthread_waittype wt, const struct timespec *abstime)
{
    int res, retval = 0;
    struct pthread_rwlock_s *rw;
    pthread_t self = pthread_self();

    RETURN_IF(!rw_ || !*rw_ || (rw = *rw_)->magic != PTHREAD_MAGIC_RWLOCK, EINVAL);

    /* acquire the mutex */
    ABORT_IF((res = pthread_mutex_lock(&rw->lock)) != 0);

    /* avoid deadlock */
    if (_pthread_rwlock_find_lock_record(rw, self)) { retval = EDEADLK; goto done; }

    /* try */
again:
    if (rw->state == 0)
    {
        assert(retval == 0);
        rw->state = -1;
        _pthread_rwlock_add_lock_record(rw, self);
        goto done;
    }

    switch (wt)
    {
    case wt_immediate:
        retval = EBUSY;
        break;

    case wt_infinite:
        ++rw->blocked_writers;
        pthread_cleanup_push(_pthread_rwlock_wrlock_cancel, rw);
        ABORT_IF((res = pthread_cond_wait(&rw->writecond, &rw->lock)) != 0);
        pthread_cleanup_pop(1); /* always decrement the blocked_writers */
        goto again;

    case wt_timed:
        ++rw->blocked_writers;
        pthread_cleanup_push(_pthread_rwlock_wrlock_cancel, rw);
        retval = pthread_cond_timedwait(&rw->writecond, &rw->lock, abstime);
        pthread_cleanup_pop(1); /* always decrement the blocked_writers */
        if (retval == 0) goto again;
        break; /* timed out or error */
    }

done:
    /* release the mutex */
    ABORT_IF((res = pthread_mutex_unlock(&rw->lock)) != 0);
    return retval;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rw_)
{
    return _pthread_rwlock_wrlock(rw_, wt_infinite, NULL);
}

int pthread_rwlock_timedwrlock(pthread_rwlock_t *rw_, const struct timespec *tp)
{
    return _pthread_rwlock_wrlock(rw_, wt_timed, tp);
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *rw_)
{
    return _pthread_rwlock_wrlock(rw_, wt_immediate, NULL);
}

int pthread_rwlock_unlock(pthread_rwlock_t *rw_)
{
    int res, retval = 0;
    struct pthread_rwlock_s *rw;
    pthread_t self = pthread_self();

    RETURN_IF(!rw_ || !*rw_ || (rw = *rw_)->magic != PTHREAD_MAGIC_RWLOCK, EINVAL);

    /* acquire the mutex */
    ABORT_IF((res = pthread_mutex_lock(&rw->lock)) != 0);

    if (rw->state == 0)
    {
        /* not locked! */
        retval = EPERM;
        goto done;
    }

    if (!_pthread_rwlock_remove_lock_record(rw, self))
    {
        /* current thread didn't have a lock record */
        retval = EPERM;
        goto done;
    }

    if (rw->state > 0)
    {
        /* we were a reader */
        --rw->state;
    }
    else
    {
        /* we were the writer */
        assert(rw->state < 0);
        rw->state = 0;
    }

    if (rw->state == 0)
    {
        /* all locks clear now. if we have waiting writers, release one. otherwise release all readers */
        if (rw->blocked_writers)
        {
            ABORT_IF((res = pthread_cond_signal(&rw->writecond)) != 0);
        }
        else
        {
            ABORT_IF((res = pthread_cond_broadcast(&rw->readcond)) != 0);
        }
    }

done:
    /* release the mutex */
    ABORT_IF((res = pthread_mutex_unlock(&rw->lock)) != 0);

    return retval;
}

int pthread_barrier_init(pthread_barrier_t *pbar, const pthread_barrierattr_t *attr, unsigned count)
{
    HANDLE h = NULL;
    struct pthread_barrier_s *bar;
    int res;

    RETURN_IF(!pbar, EINVAL);
    RETURN_IF(count == 0 || count > INT_MAX, EINVAL);
    (void)attr; /* ignore */

    /* try to allocate handle */
    if (count > 1)
    {
        h = WinCreateSemaphore(NULL, 0, (LONG)(count - 1), NULL, 0, SEMAPHORE_ALL_ACCESS);
        RETURN_IF(!h, ENOMEM);
    }

    /* try to allocate memory */
    *pbar = bar = (struct pthread_barrier_s *)libpthread_calloc(1, sizeof(struct pthread_barrier_s));
    if (!bar)
    {
        if (h) CloseHandle(h);
        return ENOMEM;
    }

    RETURN_IF((res = pthread_spin_init(&bar->spin, 0)) != 0, res);
    bar->count = count;
    bar->waiting = 0;
    bar->sem = h;
    bar->magic = PTHREAD_MAGIC_BARRIER;

    return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *pbar)
{
    struct pthread_barrier_s *bar;
    RETURN_IF(!pbar || !*pbar || (bar = *pbar)->magic != PTHREAD_MAGIC_BARRIER, EINVAL);
    RETURN_IF(bar->waiting, EBUSY);

    /* clear the magic value first */
    RETURN_IF(ATOMIC_XCHG(&(*pbar)->magic, 0) != PTHREAD_MAGIC_BARRIER, EINVAL);
    *pbar = NULL;

    if (bar->sem)
    {
        CloseHandle(bar->sem);
        bar->sem = NULL;
    }

    pthread_spin_destroy(&bar->spin);

    libpthread_free(bar);

    return 0;
}

int pthread_barrier_wait(pthread_barrier_t *bar_)
{
    struct pthread_barrier_s *bar;

    RETURN_IF(!bar_ || !*bar_ || (bar = *bar_)->magic != PTHREAD_MAGIC_BARRIER, EINVAL);

    ABORT_IF(pthread_spin_lock(&bar->spin) != 0);

    if (++bar->waiting == bar->count)
    {
        /* we are the releaser */

        bar->waiting = 0; /* reset the waiting count */
        ++bar->generation;

        /* unlock the spin lock and release the waiting threads */
        ABORT_IF(pthread_spin_unlock(&bar->spin) != 0);

        if (bar->sem)
        {
            ABORT_IF(ReleaseSemaphore(bar->sem, (LONG)(bar->count - 1), NULL) != TRUE);
        }

        return PTHREAD_BARRIER_SERIAL_THREAD;
    }
    else
    {
        /* must wait */
        unsigned generation = bar->generation;

        /* unlock the spin lock */
        ABORT_IF(pthread_spin_unlock(&bar->spin) != 0);

waitagain:
        ABORT_IF(WaitForSingleObject(bar->sem, INFINITE) != WAIT_OBJECT_0);
        if (bar->generation == generation)
        {
            /*
            The generation hasn't changed, so we were spuriously woken. This should be rare.
            We need to wake a different thread and then wait again.
            */
            ABORT_IF(ReleaseSemaphore(bar->sem, 1, NULL) != TRUE);
            Sleep(0); /* Wake another thread if we can, otherwise we could get woken again */
            goto waitagain;
        }

        return 0;
    }
}

int sched_yield(void)
{
    /* sched_yield is not listed as a cancellation point but
       we will 'sleep' in an alertable state in case an async cancel happens */
    SleepEx(0, TRUE);
    return 0;
}


/* 1/1/1970 - 1/1/1601 in 100 nanosecond increments */
#define HNS_DELTA_EPOCH ((unsigned long long)116444736000000000ull)

/* Conversion between 100ns units (Windows FILETIME) and normal time scales */
/* 100ns units are abbreviated HNS (hundred nano-seconds) because symbols cannot start with a number */
#define HNS_IN_SEC 10000000ull
#define HNS_IN_MSEC 10000ull
#define NSEC_IN_HNS 100ull
#define MSEC_TO_HNS(a) (HNS_IN_MSEC * ((unsigned long long)(a)))
#define HNS_TO_MSEC(a) (((unsigned long long)(a)) / HNS_IN_MSEC)
#define HNS_TO_TIMESPEC(hns, ts) do { (ts)->tv_sec = (time_t)((hns) / HNS_IN_SEC); (ts)->tv_nsec = (long)(((hns) % HNS_IN_SEC) * NSEC_IN_HNS); } while (0)
#define TIMESPEC_TO_HNS(ts) ((((unsigned long long)(ts)->tv_sec) * HNS_IN_SEC) + (((unsigned long long)(ts)->tv_nsec) / NSEC_IN_HNS) + HNS_DELTA_EPOCH)
typedef union _pthread_time_u {
    FILETIME ft;
    ULARGE_INTEGER ul;
} _pthread_time_u;

#if NEED_TIME
static pthread_once_t _clock_uptime_init = PTHREAD_ONCE_INIT;
static _pthread_time_u startup_time;

static void _clock_init_uptime()
{
    typedef ULONGLONG (WINAPI *TGetTickCount64)(void);
    TGetTickCount64 pGetTickCount64;
    ULONGLONG msSinceStartup;

    /* Vista+ has GetTickCount64 which is more accurate */
    HMODULE hKernel32 = GetModuleHandleW(L"Kernel32.dll");
    pGetTickCount64 = hKernel32 ? (TGetTickCount64)GetProcAddress(hKernel32, "GetTickCount64") : NULL;
    msSinceStartup = pGetTickCount64 ? (*pGetTickCount64)() : (ULONGLONG)GetTickCount();

    GetSystemTimeAsFileTime(&startup_time.ft);
    startup_time.ul.QuadPart -= MSEC_TO_HNS(msSinceStartup);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    _pthread_time_u tu;

    if (!tp) { return EINVAL; }

    if (clk_id == CLOCK_REALTIME || clk_id == CLOCK_MONOTONIC)
    {
        GetSystemTimeAsFileTime(&tu.ft);

        /* unix time is based off of Jan 1, 1970 midnight GMT */
        tu.ul.QuadPart -= HNS_DELTA_EPOCH; /* convert to unix time in 100ns units */
        HNS_TO_TIMESPEC(tu.ul.QuadPart, tp);
    }
    else if (clk_id == CLOCK_UPTIME)
    {
        /* initialize the system startup time */
        pthread_once(&_clock_uptime_init, _clock_init_uptime);

        /* system time */
        GetSystemTimeAsFileTime(&tu.ft);

        /* subtract startup time */
        tu.ul.QuadPart -= startup_time.ul.QuadPart;

        /* convert 100ns units to sec/ns */
        HNS_TO_TIMESPEC(tu.ul.QuadPart, tp);
    }
    else
    {
        /* not supported */
        return EINVAL;
    }

    return 0;
}
#endif

static void _pthread_convert_timespec(const struct timespec *tp, FILETIME *ft)
{
    _pthread_time_u* tu = (_pthread_time_u*)ft;
    assert(offsetof(_pthread_time_u, ft) == 0);
    tu->ul.QuadPart = TIMESPEC_TO_HNS(tp);
}

static DWORD _pthread_ms_from_now(const FILETIME *ft)
{
    _pthread_time_u now, then;
    unsigned long long delta = 0;

    assert(ft); /* should always be provided */

    then.ft = *ft;
    GetSystemTimeAsFileTime(&now.ft);
    
    if (then.ul.QuadPart <= now.ul.QuadPart)
    {
        /* 'then' is in the past. */
        return 0;
    }

    delta = HNS_TO_MSEC(then.ul.QuadPart - now.ul.QuadPart);
    if (delta > INFINITE)
    {
        delta = INFINITE;
    }

    return (DWORD)delta;
}

/************************************************************************/

int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    HANDLE h;
    RETURN_IF(!sem, (errno = EINVAL, -1));
    RETURN_IF(value > SEM_VALUE_MAX, (errno = EINVAL, -1));

    /* not supported yet in this implementation */
    RETURN_IF(pshared, (errno = ENOSYS, -1));

    /* allocate the handle first before heap memory */
    h = WinCreateSemaphore(NULL, (LONG)value, (LONG)SEM_VALUE_MAX, NULL, 0, SEMAPHORE_ALL_ACCESS);
    RETURN_IF(!h, (errno = ENOMEM, -1));

    *sem = (struct sem_s*)(*libpthread_calloc)(1, sizeof(struct sem_s));
    if (!*sem)
    {
        CloseHandle(h);
        return (errno = ENOMEM, -1);
    }

    (*sem)->value = value;
    (*sem)->handle = h;
    (*sem)->waiting = 0;

    (*sem)->magic = PTHREAD_MAGIC_SEM;

    errno = 0;
    return 0;
}

int sem_destroy(sem_t *sem)
{
    RETURN_IF(!sem || !*sem || (*sem)->magic != PTHREAD_MAGIC_SEM, (errno = EINVAL, -1));
    RETURN_IF((*sem)->waiting != 0, (errno = EBUSY, -1));

    /* clear the magic value first */
    RETURN_IF(ATOMIC_XCHG(&(*sem)->magic, 0) != PTHREAD_MAGIC_SEM, (errno = EINVAL, -1));
    
    CloseHandle((*sem)->handle);
    (*sem)->handle = NULL;
    (*libpthread_free)(*sem);
    *sem = NULL;

    return (errno = 0, 0);
}

int sem_post(sem_t *sem)
{
    RETURN_IF(!sem || !*sem || (*sem)->magic != PTHREAD_MAGIC_SEM, (errno = EINVAL, -1));

    RETURN_IF(ReleaseSemaphore((*sem)->handle, 1, NULL) != TRUE, (errno = EOVERFLOW, -1));
    ATOMIC_INC(&(*sem)->value);

    errno = 0;
    return 0;
}

static void _sem_wait_cancel(void *psem)
{
    struct sem_s *sem = (struct sem_s *)psem;
    ATOMIC_DEC(&sem->waiting);
}

FORCEINLINE static int _sem_wait(sem_t *sem_, _pthread_waittype wt, const struct timespec *abs_timeout)
{
    DWORD res;
    HANDLE h;
    FILETIME ft;
    struct sem_s *sem;

    RETURN_IF(!sem_ || !*sem_ || (sem = *sem_)->magic != PTHREAD_MAGIC_SEM, (errno = EINVAL, -1));

    /* sem_wait and sem_timedwait are cancellation points, so listen
       for the cancellation by waiting in an alertable state. */

    h = sem->handle;

    if (wt == wt_timed)
    {
        /* may not time-out if able to be locked immediately. validity of abs_timeout need not be checked in this case. */
again1:
        res = WaitForSingleObjectEx(h, 0, TRUE);
        if (res == WAIT_OBJECT_0)
        {
            ATOMIC_DEC(&sem->value);
            return (errno = 0, 0);
        }
        if (res == WAIT_IO_COMPLETION) goto again1;
        ABORT_IF(res != WAIT_TIMEOUT);

        /* docs specify that nanosecond values less that zero or greater than or equal to 1000 million are in error */
        RETURN_IF(!abs_timeout, (errno = EINVAL, -1));
        RETURN_IF(abs_timeout->tv_nsec < 0 || abs_timeout->tv_nsec >= 1000000000, (errno = EINVAL, -1));
        _pthread_convert_timespec(abs_timeout, &ft);
    }

again:
    if (wt == wt_immediate)
    {
        /* don't alter the waiting count for immediate checks */
        res = WaitForSingleObjectEx(h, 0, TRUE);
    }
    else
    {
        ATOMIC_INC(&sem->waiting);
        pthread_cleanup_push(_sem_wait_cancel, sem);
        res = WaitForSingleObjectEx(h, wt == wt_timed ? _pthread_ms_from_now(&ft) : INFINITE, TRUE);
        pthread_cleanup_pop(1); /* always decrement the waiting count */
    }

    switch (res)
    {
    case WAIT_OBJECT_0:
        /* expected */
        ATOMIC_DEC(&sem->value);
        return (errno = 0, 0);

    default:
        abort();
        break;

    case WAIT_IO_COMPLETION:
        goto again;

    case WAIT_TIMEOUT:
        RETURN_IF(wt == wt_immediate, (errno = EAGAIN, -1));
        RETURN_IF(wt == wt_timed, (errno = ETIMEDOUT, -1));
        abort();
        break;
    }
}

int sem_wait(sem_t *sem)
{
    return _sem_wait(sem, wt_infinite, NULL);
}

int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout)
{
    return _sem_wait(sem, wt_timed, abs_timeout);
}

int sem_trywait(sem_t *sem)
{
    return _sem_wait(sem, wt_immediate, NULL);
}

int sem_getvalue(sem_t *sem_, int *sval)
{
    struct sem_s *sem;
    RETURN_IF(!sem_ || !*sem_ || !sval || (sem = *sem_)->magic != PTHREAD_MAGIC_SEM, (errno = EINVAL, -1));

    /* the POSIX.1-2001 spec allows us to report the number of waiters as a negative number */
    *sval = sem->value ? (int)sem->value : -(int)sem->waiting;
    return 0;
}

/************************************************************************/

static int _pthread_init();
static void NTAPI _pthread_tls_callback(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved);
static int _pthread_cleanup();

#if defined(MAKE_STATIC)
typedef void (NTAPI* _TLSCB)(HINSTANCE, DWORD, PVOID);

__BEGIN_DECLS
extern DWORD _tls_used; /* TLS directory in .rdata */
extern _TLSCB __xl_a[], __xl_z[]; /* TLS initializers */
__END_DECLS

static inline void _force_inclusion()
{
    DWORD volatile dw = _tls_used;
    (void)dw;
}

/* Not a DLL; hook process creation in the MSVC CRT */
/* http://shimpossible.blogspot.com/2013/07/microsoft-visual-c-memory-segments.html */
#pragma section(".CRT$XCU",long,read)
__declspec(allocate(".CRT$XCU")) _PIFV __pthread_process_init = (_PIFV)_pthread_init;
#pragma section(".CRT$XTU",long,read)
__declspec(allocate(".CRT$XTU")) _PIFV __pthread_process_exit = (_PIFV)_pthread_cleanup;
#pragma section(".CRT$XDU",long,read)
__declspec(allocate(".CRT$XDU")) _TLSCB __pthread_thread_callback = (_TLSCB)_pthread_tls_callback;

#else

static inline void _force_inclusion() {}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        _pthread_init();
        break;

    case DLL_PROCESS_DETACH:
        _pthread_cleanup();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        _pthread_tls_callback(hinstDll, fdwReason, lpReserved);
        break;
    }
    return TRUE;
}


#endif

static int _pthread_init()
{
    _force_inclusion();
    if (_main_thread.tid == 0)
    {
        _pthread_create_external(1);
    }

    return 0;
}

static void NTAPI _pthread_tls_callback(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
}

static int _pthread_cleanup()
{
    return 0;
}
