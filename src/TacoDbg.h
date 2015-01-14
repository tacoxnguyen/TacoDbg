#ifndef __TACODBG_H__
#define __TACODBG_H__

#include <sys/types.h>
#include <string>
#include <vector>

#include <capstone.h>

class TacoDbg
{
public:
	TacoDbg();
	void		attachToProcess(pid_t childPid);
	void		startCommandLoop();
protected:
	virtual ~TacoDbg();
private:
	void		handleCommand(const char* cmd, std::vector<std::string> args);

	void		stepOver();
	bool		stepInto();
	void		disassemble(int addr, int numBytes = 10);

private:
	csh			_csHandle;
	pid_t		_childPid;
};

#endif
