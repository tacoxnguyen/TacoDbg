#ifndef __TACODBG_H__
#define __TACODBG_H__

#include <sys/types.h>

class TacoDbg
{
public:
	void		attachToProcess(pid_t childPid);
	void		startCommandLoop();
private:
	void		handleCommand(const char* cmd);

	void		stepOver();
	bool		stepInto();

private:
	pid_t		_childPid;
};

#endif
