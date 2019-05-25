#ifndef _PRIVATE_H_
#define _PRIVATE_H_

#include <assert.h>

//#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>

#define ABORT_IF(test) do { if ((test)) { abort(); } } while (0)
#define RETURN_IF(test, val) do { if ((test)) { return (val); } } while (0)

#if _DURANGO
#define WinCreateSemaphore(a,b,c,d,e,f) CreateSemaphoreExW((a),(b),(c),(d),(e),(f))
#elif _WIN32 /* CreateSemaphoreExW isn't available prior to Vista */
#define WinCreateSemaphore(a,b,c,d,e,f) CreateSemaphoreW((a),(b),(c),(d))
#endif

#if !defined(__GNUC__)
# include <intrin.h>
# define PROC_YIELD() YieldProcessor()
# define FORCEINLINE __forceinline
# define NOINLINE __declspec(noinline)
# define ATOMIC_READ_WRITE_BARRIER _ReadWriteBarrier
# define ATOMIC_CMPXCHG(dest,n,cond) _InterlockedCompareExchange((long volatile *)(dest),(LONG)(n),(LONG)(cond))
# define ATOMIC_XCHG(dest,n) _InterlockedExchange((long volatile *)(dest),(LONG)(n))
# define ATOMIC_OR(dest,n) _InterlockedOr((long volatile *)(dest), (LONG)(n))
# if _M_IX86 /* 32-bit */
#  define ATOMIC_CMPXCHG_PTR(dest,n,cond) ((void*)ATOMIC_CMPXCHG((long volatile*)(dest),(LONG)(n),(LONG)(cond)))
#  define ATOMIC_XCHG_PTR(dest,n) ((void*)ATOMIC_XCHG((long volatile*)(dest), (LONG)(n)))
# elif _M_X64 || _M_IA64 /* 64-bit */
#  define ATOMIC_CMPXCHG_PTR(dest,n,cond) ((void*)_InterlockedCompareExchange64((__int64 volatile *)(dest),(__int64)(n),(__int64)(cond)))
#  define ATOMIC_XCHG_PTR(dest,n) ((void*)_InterlockedExchange64((__int64 volatile *)(dest), (__int64)(n)))
# else
#  error Unknown pointer size!
# endif
# define ATOMIC_DEC(p) _InterlockedDecrement((long volatile *)(p))
# define ATOMIC_INC(p) _InterlockedIncrement((long volatile *)(p))
# if _DURANGO
#  include <synchapi.h>
# endif
#else
# define PROC_YIELD() asm("pause")
# define FORCEINLINE inline __attribute__((always_inline))
# define NOINLINE __attribute__((noinline))
# define ATOMIC_READ_WRITE_BARRIER __sync_synchronize
# define ATOMIC_CMPXCHG(dest,n,cond) __sync_val_compare_and_swap((dest),(cond),(n))
# define ATOMIC_CMPXCHG_PTR(dest,n,cond) ATOMIC_CMPXCHG(dest,n,cond)
# define ATOMIC_XCHG(dest,n) __sync_lock_test_and_set((dest),(n))
# define ATOMIX_XCHG_PTR(dest, n) ATOMIC_XCHG((dest),(n))
# define ATOMIC_OR(dest, n) __sync_fetch_and_or((p), (n))
# define ATOMIC_DEC(p) __sync_sub_and_fetch((p), 1)
# define ATOMIC_INC(p) __sync_add_and_fetch((p), 1)
#endif

#endif