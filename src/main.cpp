#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

#include "TacoDbg.h"
#include "util.h"

int main(int argc, char **argv)
{
	if(argc < 2)
	{
		printf("Usage: %s <program>", argv[0]);
		return (-1);
	}

	pid_t childPid = fork();

	if(childPid == 0)
	{
		run_target(argv[1]);
	}
	else if(childPid > 0)
	{
		TacoDbg *dbg = new TacoDbg();
		dbg->attachToProcess(childPid);
		dbg->startCommandLoop();
	}
	else
	{
		return (-1);
	}

	return 0;
}
