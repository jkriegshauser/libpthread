#include <pthread.h>
#include <semaphore.h>

#include <stdio.h>
#include <assert.h>

#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#include <intrin.h>
#pragma intrinsic(_InterlockedIncrement)

#define USE_SPINLOCKS 1
#define THREADCOUNT 4

#if USE_SPINLOCKS
pthread_spinlock_t mutex;
#define pthread_mutex_init(a,b) pthread_spin_init(a,0)
#define pthread_mutex_destroy pthread_spin_destroy
#define pthread_mutex_lock pthread_spin_lock
#define pthread_mutex_unlock pthread_spin_unlock
#else
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
sem_t sem;
pthread_key_t dummy;
pthread_key_t key;
pthread_once_t once = PTHREAD_ONCE_INIT;
pthread_barrier_t barrier;

pthread_rwlock_t rwlock;

void* simple_test(void* arg)
{
    pthread_setname_np(pthread_self(), "simple-test");
    pthread_setspecific(key, (void*)GetCurrentThreadId());
    printf("Hello world threaded! (%p)\n", arg);

    pthread_exit((void*)0xc0de2bad);
    return (void*)1;
}

void do_only_once()
{
    static long i = 0;
    _InterlockedIncrement(&i);
    Sleep(1000);
    assert(i == 1);
}

void* mutex_test(void* arg)
{
    pthread_setname_np(pthread_self(), "mutex-test");
    int* val = (int*)arg;

    sem_wait(&sem);

    pthread_once(&once, do_only_once);

    for (int i = 0; i < 1000000; ++i)
    {
        pthread_mutex_lock(&mutex);
        ++*val;
        pthread_mutex_unlock(&mutex);
    }

    return 0;
}

void destructor(void* val)
{
    printf("Destructor! Thread(%p) val(%p) tls(%p)\n", pthread_self(), val, pthread_getspecific(key));
}

void* rwtest_read(void* val_)
{
    pthread_barrier_wait(&barrier);

    int& val = *(int*)val_;

    int expect = 1;

    while (expect < 3)
    {
        if (pthread_rwlock_tryrdlock(&rwlock) != 0)
        {
            // Write lock; change expect
            ++expect;
            pthread_rwlock_rdlock(&rwlock);
        }

        assert(expect == val);
        pthread_rwlock_unlock(&rwlock);
    }

    return 0;
}

int main(int argc, char** argv)
{
    pthread_setname_np(pthread_self(), "main-thread");

    pthread_key_create(&dummy, NULL);
    pthread_key_create(&key, &destructor);

    pthread_barrier_init(&barrier, NULL, THREADCOUNT);

    pthread_setspecific(key, (void*)GetCurrentThreadId());

    pthread_t t;
    pthread_create(&t, nullptr, simple_test, (void*)0xbaadc0de);
    void* output;
    pthread_join(t, &output);

    printf("Thread returned: %p\n", output);

    //////////////////////////////////////////////////////////////////////////

    pthread_mutex_init(&mutex, nullptr);

    sem_init(&sem, 0, 0);

    pthread_t threads[THREADCOUNT];
    int val = 0;
    for (int i = 0; i < THREADCOUNT; ++i)
    {
        pthread_create(&threads[i], nullptr, mutex_test, &val);
    }

    // Wait for the threads to all be waiting.
    int semval;
    while (sem_getvalue(&sem, &semval) == 0 && semval != -4)
    {
        Sleep(1);
    }

    // Let 'er rip!
    for (int i = 0; i < THREADCOUNT; ++i)
    {
        sem_post(&sem);
    }

    for (int i = 0; i < THREADCOUNT; ++i)
    {
        pthread_join(threads[i], nullptr);
    }

    pthread_once(&once, do_only_once);
    pthread_once(&once, do_only_once);
    pthread_once(&once, do_only_once);
    pthread_once(&once, do_only_once);

    pthread_rwlock_init(&rwlock, nullptr);

    assert(pthread_rwlock_tryrdlock(&rwlock) == 0);
    assert(pthread_rwlock_unlock(&rwlock) == 0);
    assert(pthread_rwlock_rdlock(&rwlock) == 0);
    assert(pthread_rwlock_unlock(&rwlock) == 0);
    assert(pthread_rwlock_trywrlock(&rwlock) == 0);
    assert(pthread_rwlock_unlock(&rwlock) == 0);
    assert(pthread_rwlock_wrlock(&rwlock) == 0);
    assert(pthread_rwlock_unlock(&rwlock) == 0);

    val = 1;
    for (int i = 0; i < THREADCOUNT; ++i)
    {
        pthread_create(&threads[i], nullptr, rwtest_read, &val);
    }

    Sleep(1000); // Wait for all readers
    pthread_rwlock_wrlock(&rwlock);
    val = 2;
    Sleep(100);
    pthread_rwlock_unlock(&rwlock);
    Sleep(1000);
    if (pthread_rwlock_trywrlock(&rwlock) != 0) pthread_rwlock_wrlock(&rwlock);
    val = 3;
    Sleep(100);
    pthread_rwlock_unlock(&rwlock);
    Sleep(1000);

    for (int i = 0; i < THREADCOUNT; ++i)
    {
        pthread_join(threads[i], nullptr);
    }

    pthread_barrier_destroy(&barrier);

    pthread_rwlock_destroy(&rwlock);
    pthread_mutex_destroy(&mutex);
    sem_destroy(&sem);
    pthread_key_delete(key);

    return 0;
}