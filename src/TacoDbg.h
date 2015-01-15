#ifndef __TACODBG_H__
#define __TACODBG_H__

#include <sys/types.h>
#include <string>
#include <vector>

#include <capstone.h>

#include "DebugStructure.h"

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

	void		continueRun();
	void		stepOver();
	void		stepInto();
	void		disassemble(int addr, int numBytes = 10);
	void		setBreakpoint(int addr);
	void		deleteBreakpoint(int bpNo);
	void		enableBreakpoint(DebugBreakpoint* bp);
	void 		disableBreakpoint(DebugBreakpoint* bp);
	void		clearAllBreakpoints();
	void		dumpMemory(unsigned long addr, int size);

	bool		isBreakpointTraped();
	DebugBreakpoint*	getBreakpointByAddress(int addr);

	unsigned long		getEIP();
private:
	csh			_csHandle;
	pid_t		_childPid;

	std::vector<DebugBreakpoint*> 	_breakpoints;
	DebugBreakpoint*				_trapedBreakpoint;
};

#endif
