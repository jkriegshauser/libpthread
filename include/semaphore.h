#ifndef _SEMAPHORE_H_
#define _SEMAPHORE_H_

#include <errno.h>
#include <limits.h>
#include <sys/cdefs.h>

/* defines */
#define SEM_VALUE_MAX           INT_MAX

/* structures */
struct sem_s;
typedef struct sem_s *sem_t;
struct timespec;

__BEGIN_DECLS
int     sem_init(sem_t *sem, int pshared, unsigned int value);
int     sem_destroy(sem_t *sem);
int     sem_post(sem_t *sem);
int     sem_wait(sem_t *sem);
int     sem_trywait(sem_t *sem);
int     sem_timedwait(sem_t *sem, const struct timespec *abs_timeout);
int     sem_getvalue(sem_t *sem, int *sval);
__END_DECLS


#endif