libpthread
==========

by Joshua M. Kriegshauser (jkriegshauser -at- gmail -dot- com)

A (mostly-)lockless pthread implementation for x86/64 Windows (PC and Xbox One). POSIX.1 standards compliant.

Non-portable extension functions are suffixed with _np

Getting Started
===============

A simple example:
	#include <Windows.h>
	#include <pthread.h>
	#include <stdio.h>
	
	pthread_key_t key;

	void* simple_test(void* arg)
	{
		pthread_setname_np(pthread_self(), "simple-test");
		pthread_setspecific(key, (void*)GetCurrentThreadId());
		printf("Hello world threaded! (%p)\n", arg);

		pthread_exit((void*)0xc0de2bad);
		return (void*)1;
	}

	void destructor(void* val)
	{
		printf("Destructor! Thread(%p) val(%p) tls(%p)\n", pthread_self(), val, pthread_getspecific(key));
	}

	int main(int argc, char** argv)
	{
		pthread_setname_np(pthread_self(), "main-thread");

		pthread_key_create(&key, &destructor);
		pthread_setspecific(key, (void*)GetCurrentThreadId());

		pthread_t t;
		pthread_create(&t, nullptr, simple_test, (void*)0xbaadc0de);
		void* output;
		pthread_join(t, &output);

		printf("Thread returned: %p\n", output);
		return 0;
	}
