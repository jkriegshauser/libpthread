#ifndef _PTHREAD_H_
#define _PTHREAD_H_

#include <errno.h>
#include <time.h>
#include <sys/cdefs.h>

/* Define this if clock_gettime and struct timespec aren't defined */
#if !defined(CLOCK_REALTIME)
#define NEED_TIME 1
#endif

/* scheduling items normally from unistd.h */
#if !defined(_POSIX_PRIORITY_SCHEDULING)
#define NEED_SCHED 1
#endif

/* defines */
#define PTHREAD_MASK_CANCELABLE_NP          0x1
#define PTHREAD_CANCEL_ENABLE		        0x0
#define PTHREAD_CANCEL_DISABLE		        PTHREAD_MASK_CANCELABLE_NP

#define PTHREAD_MASK_CANCELTYPE_NP          0x2
#define PTHREAD_CANCEL_DEFERRED		        0x0
#define PTHREAD_CANCEL_ASYNCHRONOUS	        PTHREAD_MASK_CANCELTYPE_NP
#define PTHREAD_CANCELED		            ((void *)(size_t)0xfefef0f0)

#define PTHREAD_MASK_JOINABLE_NP            0x4
#define PTHREAD_CREATE_JOINABLE             0x0
#define PTHREAD_DETACHED                    PTHREAD_MASK_JOINABLE_NP
#define PTHREAD_CREATE_DETACHED             PTHREAD_DETACHED

#define PTHREAD_MASK_SCHED_NP               0x8
#define PTHREAD_EXPLICIT_SCHED              0x0
#define PTHREAD_INHERIT_SCHED               PTHREAD_MASK_SCHED_NP

#define PTHREAD_MASK_SCOPE_NP               0x10
#define PTHREAD_SCOPE_PROCESS               0x0
#define PTHREAD_SCOPE_SYSTEM                PTHREAD_MASK_SCOPE_NP

#define PTHREAD_KEYS_MAX                    256
#define PTHREAD_DESTRUCTOR_ITERATIONS       256

#define PTHREAD_PROCESS_PRIVATE             0
#define PTHREAD_PROCESS_SHARED              1

#define PTHREAD_DEFAULT_ATTR                (PTHREAD_CANCEL_ENABLE|PTHREAD_CREATE_JOINABLE|PTHREAD_EXPLICIT_SCHED|PTHREAD_SCOPE_PROCESS)

#define PTHREAD_BARRIER_SERIAL_THREAD       1

enum pthread_mutextype {
    PTHREAD_MUTEX_ERRORCHECK = 1,           /* Default POSIX mutex */
    PTHREAD_MUTEX_RECURSIVE = 2,            /* Recursive mutex */
    PTHREAD_MUTEX_NORMAL = 3,               /* No error checking */
    PTHREAD_MUTEX_TYPE_MAX
};

#define PTHREAD_MUTEX_DEFAULT		        PTHREAD_MUTEX_RECURSIVE

/* magic values */
#define PTHREAD_MAGIC_PTHREAD               (0x64726874)
#define PTHREAD_MAGIC_MUTEX                 (0x7874754d)
#define PTHREAD_MAGIC_COND                  (0x646e6f63)
#define PTHREAD_MAGIC_RWLOCK                (0x6b6c7772)
#define PTHREAD_MAGIC_BARRIER               (0x72726162)
#define PTHREAD_MAGIC_SEM                   (0x5f6d6573)

#define PTHREAD_MUTEX_INITIALIZER           {PTHREAD_MAGIC_MUTEX, 0, { 0 }, 0, NULL}
#define PTHREAD_ONCE_INIT                   0
#define PTHREAD_COND_INITIALIZER            {PTHREAD_MAGIC_COND, 0, 0, 0, NULL, NULL}

/* normally this lives in time.h, but doesn't exist on windows */
#if NEED_TIME

#if defined(_MSC_VER) && _MSC_VER < 1900 /* VS2015 */
struct timespec {
    time_t	tv_sec;		/* seconds */
    long	tv_nsec;	/* and nanoseconds */
};
#endif /* VS2015 */

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 4
#define CLOCK_UPTIME 5

typedef int clockid_t;
#endif /* NEED_TIME */

/* normally these live in sched.h */
#if NEED_SCHED
/* these are just provided for completeness. Windows doesn't allow changing the scheduling policy. */
#define SCHED_FIFO      1
#define SCHED_OTHER     2
#define SCHED_RR        3

/* POSIX.1-2001 requires a spread of at least 32 */
#define SCHED_PRIORITY_MIN      0
#define SCHED_PRIORITY_DEFAULT  15
#define SCHED_PRIORITY_MAX      31

struct sched_param
{
    int sched_priority;
};

typedef unsigned long long cpu_set_t;
#define CPU_ALLOC(n) (0)
#define CPU_FREE(n) ((void)n)

#define CPU_ZERO(s) (s) = 0ull
#define CPU_SET(n,s) (s) |= (1ull<<(n))
#define CPU_CLR(n,s) (s) &= ~(1ull<<(n))
#define CPU_ISSET(n,s) (!!((s)&(1ull<<(n))))
#define CPU_AND(o,i1,i2) (o) = (i1)&(i2)
#define CPU_OR(o,i1,i2) (o)=(i1)|(i2)
#define CPU_XOR(o,i1,i2) (o)=(i1)^(i2)
#define CPU_EQUAL(i1,i2) ((i1)==(i2))
#endif

/* (semi-)opaque types */
typedef struct pthread_s *pthread_t;
typedef int pthread_key_t;
typedef long volatile pthread_once_t;
typedef union pthread_spinlock_u
{
    long volatile flags;
    struct
    {
        unsigned locked : 1;
        unsigned tid : 31;
    } debug_info;
} pthread_spinlock_t;
typedef struct pthread_mutex_s
{
    int magic;
    long recursion;
    union {
        long volatile flags;
        struct
        {
            unsigned locked : 1; /* locked if 1; available if 0 */
            unsigned signaled : 1; /* event signaled if 1; not signaled if 0 */
            unsigned waiters : 30;
        } debug_info;
    } u;
    unsigned owner;
    void* volatile sem;
} pthread_mutex_t;
typedef struct pthread_mutexattr_s
{
    int type;
} pthread_mutexattr_t;
typedef struct pthread_cond_s
{
    int magic;
    long volatile waiters;
    void* volatile sem;
    pthread_mutex_t* mutex;
} pthread_cond_t;
typedef struct pthread_rwlock_attr_s
{
    unsigned __dummy;
} pthread_rwlock_attr_t;
typedef struct pthread_rwlock_s *pthread_rwlock_t;
typedef struct pthread_barrierattr_s
{
    unsigned __dummy;
} pthread_barrierattr_t;
typedef struct pthread_barrier_s *pthread_barrier_t;
typedef struct pthread_condattr_s
{
    unsigned __dummy;
} pthread_condattr_t;
typedef struct pthread_attr_s
{ 
    unsigned p_state;
    size_t s_size;
    cpu_set_t cpuset;
} pthread_attr_t;
struct pthread_cleanup_s
{
    struct pthread_cleanup_s *next;
    void (* func)(void *);
    void *arg;
};

/* Functions */
__BEGIN_DECLS
/* private */
void _pthread_push_cfn(struct pthread_cleanup_s *cfn, void (* func)(void *), void *arg);
void _pthread_pop_cfn(int execute);

/* cleanup */
#define pthread_cleanup_push(fn, a) \
    do { struct pthread_cleanup_s _cfn; _pthread_push_cfn(&_cfn, (fn), (void*)(a))
#define pthread_cleanup_pop(exec) \
    _pthread_pop_cfn(exec); } while (0)

/* pthread_attr_t functions */
int     pthread_attr_init(pthread_attr_t *attr);
#define pthread_attr_destroy(attr) (0)
int     pthread_attr_setdetachstate(pthread_attr_t *attr, int flag);
int     pthread_attr_getdetachstate(pthread_attr_t *attr, int *flag);
int     pthread_attr_setinheritsched(pthread_attr_t *attr, int flag);
int     pthread_attr_getinheritsched(pthread_attr_t *attr, int *flag);
int     pthread_attr_setscope(pthread_attr_t *attr, int flag);
int     pthread_attr_getscope(pthread_attr_t *attr, int *flag);
int     pthread_attr_setstacksize(pthread_attr_t *attr, int size);
int     pthread_attr_getstacksize(pthread_attr_t *attr, int *size);
#define pthread_attr_setstackaddr(attr, flag)   (ENOTSUP)
#define pthread_attr_getstackaddr(attr, flag)   (ENOTSUP)
#define pthread_attr_setguardsize(attr, flag)   (ENOTSUP)
#define pthread_attr_getguardsize(attr, flag)   (ENOTSUP)
#define pthread_attr_setschedparam(attr, flag)  (ENOTSUP)
#define pthread_attr_getschedparam(attr, flag)  (ENOTSUP)
#define pthread_attr_setschedpolicy(attr, flag) (ENOTSUP)
#define pthread_attr_getschedpolicy(attr, flag) (ENOTSUP)
int     pthread_attr_setaffinity_np(pthread_attr_t *attr, const cpu_set_t *cpuset);
int     pthread_attr_getaffinity_np(pthread_attr_t *attr, cpu_set_t *cpuset);

/* pthread functions */
pthread_t pthread_self(void);
int     pthread_create(pthread_t *th, pthread_attr_t *attr, void *(*) (void *), void *arg);
int     pthread_join(pthread_t t, void **res);
int     pthread_detach(pthread_t t);
int     pthread_kill(pthread_t t, int sig); /* only sig=0 is supported */
void    pthread_exit(void *result);
#define pthread_equal(a,b) ((a)==(b)) /*pointer compare*/
int     pthread_main_np(void);
int     pthread_setname_np(pthread_t thread, const char *name);
int     pthread_getname_np(pthread_t thread, char *name, size_t len);
int     pthread_once(pthread_once_t *control, void (*fn)());
int     pthread_cancel(pthread_t thread);
void    pthread_testcancel(void);
int     pthread_setcancelstate(int state, int *oldstate);
int     pthread_setcanceltype(int state, int *oldstate);
int     pthread_setschedprio(pthread_t thread, int prio);
#define pthread_setprio pthread_setschedprio /*alias*/
int     pthread_setschedparam(pthread_t thread, int policy, const struct sched_param *param);
int     pthread_getschedparam(pthread_t thread, int *policy, struct sched_param *param);
int     pthread_setaffinity_np(pthread_t thread, const cpu_set_t *cpuset);
int     pthread_getaffinity_np(pthread_t thread, cpu_set_t *cpuset);

/* pthread_mutex functions */
int     pthread_mutexattr_init(pthread_mutexattr_t *attr);
int     pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
int     pthread_mutexattr_getpshared(pthread_mutexattr_t *attr, int *pshared);
int     pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared);
int		pthread_mutexattr_gettype(pthread_mutexattr_t *, int *type);
int		pthread_mutexattr_settype(pthread_mutexattr_t *, int type);
int     pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr);
int     pthread_mutex_destroy(pthread_mutex_t *mutex);
int     pthread_mutex_lock(pthread_mutex_t *mutex);
int     pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abstime);
int     pthread_mutex_trylock(pthread_mutex_t *mutex);
int     pthread_mutex_unlock(pthread_mutex_t *mutex);

/* pthread_spinlock functions */
int     pthread_spin_init(pthread_spinlock_t *lock, int pshared);
int     pthread_spin_destroy(pthread_spinlock_t *lock);
int     pthread_spin_lock(pthread_spinlock_t *lock);
int     pthread_spin_trylock(pthread_spinlock_t *lock);
int     pthread_spin_unlock(pthread_spinlock_t *lock);

/* condition variables */
int     pthread_condattr_init(pthread_condattr_t *attr);
int     pthread_condattr_destroy(pthread_condattr_t *attr);
int     pthread_condattr_getpshared(pthread_condattr_t *attr, int *pshared);
int     pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared);
int     pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr);
int     pthread_cond_signal(pthread_cond_t *cond);
int     pthread_cond_broadcast(pthread_cond_t *cond);
int     pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int     pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime);
int     pthread_cond_destroy(pthread_cond_t *cond);

/* read/write lock */
int     pthread_rwlockattr_init(pthread_rwlock_attr_t *attr);
int     pthread_rwlockattr_destroy(pthread_rwlock_attr_t *attr);
int     pthread_rwlockattr_getpshared(pthread_rwlock_attr_t *attr, int *pshared);
int     pthread_rwlockattr_setpshared(pthread_rwlock_attr_t *attr, int pshared);
int     pthread_rwlock_init(pthread_rwlock_t *rw, const pthread_rwlock_attr_t *attr);
int     pthread_rwlock_destroy(pthread_rwlock_t *rw);
int     pthread_rwlock_rdlock(pthread_rwlock_t *rw);
int     pthread_rwlock_tryrdlock(pthread_rwlock_t *rw);
int     pthread_rwlock_timedrdlock(pthread_rwlock_t *rw, const struct timespec *tp);
int     pthread_rwlock_wrlock(pthread_rwlock_t *rw);
int     pthread_rwlock_trywrlock(pthread_rwlock_t *rw);
int     pthread_rwlock_timedwrlock(pthread_rwlock_t *rw, const struct timespec *tp);
int     pthread_rwlock_unlock(pthread_rwlock_t *rw);

/* keys */
int     pthread_key_create(pthread_key_t *key, void (*dest)(void *));
int     pthread_key_delete(pthread_key_t key);
void   *pthread_getspecific(pthread_key_t key);
int     pthread_setspecific(pthread_key_t, const void *value);

/* barrier */
int     pthread_barrier_init(pthread_barrier_t *bar, const pthread_barrierattr_t *attr, unsigned count);
int     pthread_barrier_destroy(pthread_barrier_t *bar);
int     pthread_barrier_wait(pthread_barrier_t *bar);

#if NEED_TIME
/* clock */
int     clock_gettime(clockid_t clk_id, struct timespec *tp);
#endif

#if NEED_SCHED
#define sched_get_priority_max(__ignore) (SCHED_PRIORITY_MAX)
#define sched_get_priority_min(__ignore) (SCHED_PRIORITY_MIN)
int     sched_yield(void);
#endif

/* non-portable extensions */
int     pthread_enumerate_threads_np(void(*func)(pthread_t, void*), void *user);
int     pthread_os_handle_np(pthread_t t, void **h); // For Windows, h is a pointer that receives a HANDLE

__END_DECLS

#endif /*_PTHREAD_H_*/