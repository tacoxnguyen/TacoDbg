#include "TacoDbg.h"

#include <stdlib.h>
#include <iostream>
#include <string>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "Constant.h"
#include "util.h"

void TacoDbg::attachToProcess(pid_t childPid)
{
	_childPid = childPid;

	procmsg("debugger started\n");

	/* Wait for child to stop on its first instruction */
	wait(0);
	procmsg("child now at EIP = 0x%08x\n", get_child_eip(childPid));
}

void TacoDbg::startCommandLoop()
{
	std::string buf;
	std::string command;

	while(command != CMD_QUIT)
	{
		procmsg("$ ");
		std::getline(std::cin, buf);
		std::vector<std::string> tokens = split(buf, ' ');
		if(tokens.size() > 0)
		{
			command = tokens.at(0);
			handleCommand(command.c_str());
		}
		else
		{
			//TODO: raise error
		}
	}
}

void TacoDbg::handleCommand(const char* cmd)
{
	std::string command = std::string(cmd);

	if(command == CMD_NEXT)
	{
		stepOver();
	}
	else if(command == CMD_STEP)
	{
		stepInto();
	}
}

void TacoDbg::stepOver()
{
//	int waitStatus;
//	ptrace(PTRACE_SINGLESTEP, _childPid, 0, 0);
//	wait(&waitStatus);
}

bool TacoDbg::stepInto()
{
	int waitStatus;
	ptrace(PTRACE_SINGLESTEP, _childPid, 0, 0);
	wait(&waitStatus);

	if(WIFEXITED(waitStatus))
	{
		return false;
	}

	return true;
}
