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
	void		disassemble(unsigned long addr, int numBytes = 10);
	void		setBreakpoint(unsigned long addr);
	void		deleteBreakpoint(unsigned int bpNo);
	void		enableBreakpoint(DebugBreakpoint* bp);
	void 		disableBreakpoint(DebugBreakpoint* bp);
	void		clearAllBreakpoints();
	void		dumpMemory(unsigned long addr, int size);

	bool		isBreakpointTraped();
	DebugBreakpoint*	getBreakpointByAddress(unsigned long addr);

	unsigned long		getEIP();
	
	void		getCodeSegment(unsigned char* code, int size);
	int			decodeInstruction(unsigned char* code, int size, cs_insn** insn);

	void		printNextInstruction();
private:
	csh			_csHandle;
	pid_t		_childPid;

	std::vector<DebugBreakpoint*> 	_breakpoints;
	DebugBreakpoint*				_trapedBreakpoint;
};

#endif
