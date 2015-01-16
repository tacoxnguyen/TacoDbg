#include "TacoDbg.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "Constant.h"
#include "util.h"

#include "../inttypes.h"

TacoDbg::TacoDbg()
:_childPid(0),
 _trapedBreakpoint(NULL)
{
	cs_open(CS_ARCH_X86, CS_MODE_32, &_csHandle);
	cs_option(_csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

TacoDbg::~TacoDbg()
{
	cs_close(&_csHandle);
}

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

	while(command != CMD_QUIT && command != CMD_S_QUIT)
	{
		log(CMD_PREFIX);
		std::getline(std::cin, buf);
		std::vector<std::string> tokens = split(buf, ' ');

		if(tokens.size() > 0)
		{
			command = tokens.at(0);
			std::vector<std::string> args = std::vector<std::string>(tokens.begin()+1, tokens.end());

			handleCommand(command.c_str(), args);
		}
		else
		{
			//TODO: raise error
		}
	}
}

void TacoDbg::handleCommand(const char* cmd, std::vector<std::string> args)
{
	std::string command = std::string(cmd);

	if(command == CMD_CONTINUE || command == CMD_S_CONTINUE)
	{
		continueRun();
	}
	else if(command == CMD_NEXT || command == CMD_S_NEXT)
	{
		stepOver();
	}
	else if(command == CMD_STEP || command == CMD_S_STEP)
	{
		stepInto();
	}
	else if(command == CMD_INFO || command == CMD_S_INFO)
	{
		std::string infoType = args.at(0);
		if(infoType == INFO_REGISTERS)
		{
			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, _childPid, 0, &regs);
			log(
					"eax: 0x%lx\necx: 0x%lx\nedx: 0x%lx\nebx: 0x%lx\n"
					"esp: 0x%lx\nebp: 0x%lx\nesi: 0x%lx\nedi: 0x%lx\neip: 0x%lx\n"
					"eflags: 0x%lx\ncs: 0x%lx\nss: 0x%lx\nds: 0x%lx\nes: 0x%lx\nfs: 0x%lx\ngs: 0x%lx\n",
					regs.eax, regs.ecx, regs.edx, regs.ebx,
					regs.esp, regs.ebp, regs.esi, regs.edi, regs.eip,
					regs.eflags, regs.xcs, regs.xss, regs.xds, regs.xes, regs.xfs, regs.xgs);
		}
		else if(infoType == INFO_BREAKPOINT)
		{
			log("%s\t%s\n", "Num", "Address");
			for(unsigned int i = 0; i < _breakpoints.size(); i++)
			{
				DebugBreakpoint *bp = _breakpoints.at(i);
				log("%u\t0x%x\n", i+1, bp->addr);
			}
		}
	}
	else if(command == CMD_DISASSEMBLE)
	{
		disassemble(0x0);

	}
	else if(command == CMD_SETBP || command == CMD_S_SETBP)
	{
		std::string saddress = args.at(0);
		unsigned long addr = stringToNumber<unsigned long>(saddress.c_str());
		setBreakpoint(addr);
	}
	else if(command == CMD_DELETEBP || command == CMD_S_DELETEBP)
	{
		unsigned int bpNo = stringToNumber<unsigned int>(args.at(0).c_str());
		deleteBreakpoint(bpNo);
	}
	else if(command == CMD_CLEARBP)
	{
		clearAllBreakpoints();
	}
	else if(command == CMD_DUMP)
	{
		std::string saddress = args.at(0);
		unsigned long addr = stringToNumber<unsigned long>(saddress.c_str());
		dumpMemory(addr, 0x10);
	}
}

void TacoDbg::continueRun()
{
	stepInto();

	int waitStatus;
	ptrace(PTRACE_CONT, _childPid, 0, 0);
	wait(&waitStatus);

	unsigned long eip = getEIP();
	DebugBreakpoint *bp = getBreakpointByAddress(eip - 1);
	if(bp != NULL)
	{
		log("Breakpoint at 0x%x\n", bp->addr);
	}
}

void TacoDbg::stepOver()
{

}

void TacoDbg::stepInto()
{
	// remove breakpoint if exists
	DebugBreakpoint *bp = getBreakpointByAddress(getEIP()-1);

	if(bp)
	{
		struct user_regs_struct regs;
		ptrace(PTRACE_GETREGS, _childPid, 0, &regs);
		regs.eip = bp->addr;
		ptrace(PTRACE_SETREGS, _childPid, 0, &regs);

		disableBreakpoint(bp);
	}

	int waitStatus;
	ptrace(PTRACE_SINGLESTEP, _childPid, 0, 0);
	wait(&waitStatus);

	if(bp)
	{
		enableBreakpoint(bp);
	}

	printNextInstruction();
}

void TacoDbg::disassemble(unsigned long addr, int numBytes)
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, _childPid, 0, &regs);

	unsigned char code[MAX_DISASSEMBLE_CODE_SIZE];
	getCodeSegment(code, MAX_DISASSEMBLE_CODE_SIZE);

	cs_insn *insn;
	int count = decodeInstruction(code, sizeof(code), &insn);

	unsigned long address = 0x1000;

	if(count > 0)
	{
		for (int j = 0; j < count; j++) {
			log("0x%"PRIx64":\t%s\t%s\n", (regs.eip + insn[j].address - address), insn[j].mnemonic, insn[j].op_str);
		}
	}
	else
	{
		//TODO:
		log("ERROR: Can't decode instruction\n");
	}
}

void TacoDbg::setBreakpoint(unsigned long addr)
{
	DebugBreakpoint *bp = new DebugBreakpoint();
	bp->addr = addr;

	log("Set breakpoint at 0x%x\n", addr);

	_breakpoints.push_back(bp);
	enableBreakpoint(bp);
}

void TacoDbg::deleteBreakpoint(unsigned int bpNo)
{
	if(bpNo > _breakpoints.size())
	{
		//TODO: exception
		log("ERROR: breakpoint #%d is out of range\n", bpNo);
	}
	else
	{
		_breakpoints.erase(_breakpoints.begin() + bpNo - 1);
		log("Deleted breakpoint #%d\n", bpNo);
	}
}

void TacoDbg::clearAllBreakpoints()
{
	for(std::vector<DebugBreakpoint*>::iterator it = _breakpoints.begin(); it != _breakpoints.end(); it++)
	{
		DebugBreakpoint *bp = *it;
		delete bp;
	}
	_breakpoints.clear();
	log("Cleared all breakpoints\n");
}

void TacoDbg::dumpMemory(unsigned long addr, int size)
{
	for(int i = 0; i < size; i++)
	{
		long word = ptrace(PTRACE_PEEKTEXT, _childPid, (void *) (addr + 4*i), 0);
		log("%x ", word);
	}
	log("\n");
}

void TacoDbg::enableBreakpoint(DebugBreakpoint* bp)
{
	bp->origData = ptrace(PTRACE_PEEKTEXT, _childPid, (void *) bp->addr, 0);
	ptrace(PTRACE_POKETEXT, _childPid, (void *) bp->addr, (bp->origData & 0xFFFFFF00) | 0xCC);
}

void TacoDbg::disableBreakpoint(DebugBreakpoint* bp)
{
	long data = ptrace(PTRACE_PEEKTEXT, _childPid, (void *) bp->addr, 0);
	ptrace(PTRACE_POKETEXT, _childPid, (void *) bp->addr, (data & 0xFFFFFF00) | (bp->origData & 0xFF));
}

bool TacoDbg::isBreakpointTraped()
{
	unsigned long eip = getEIP();

	return (getBreakpointByAddress(eip - 1) != NULL);
}

DebugBreakpoint* TacoDbg::getBreakpointByAddress(unsigned long addr)
{
	for(std::vector<DebugBreakpoint*>::iterator it = _breakpoints.begin(); it != _breakpoints.end(); it++)
	{
		DebugBreakpoint *bp = *it;
		if(bp->addr == addr)
		{
			return bp;
		}
	}

	return NULL;
}

unsigned long TacoDbg::getEIP()
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, _childPid, 0, &regs);
	return regs.eip;
}

void TacoDbg::getCodeSegment(unsigned char* code, int size)
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, _childPid, 0, &regs);

	for(int i = 0; i < size/4; i++)
	{
		unsigned word =	ptrace(PTRACE_PEEKTEXT, _childPid, regs.eip + 4*i, 0);
		memcpy(code + 4*i, &word, sizeof(word));
	}
}

int TacoDbg::decodeInstruction(unsigned char* code, int size, cs_insn** insn)
{
	return cs_disasm(_csHandle, code, size, ADDR_FIRST_INSN, 0, insn);
}

void TacoDbg::printNextInstruction()
{
	unsigned char code[MAX_INSN_SIZE];
	getCodeSegment(code, MAX_INSN_SIZE);

	cs_insn *insn;
	int count = decodeInstruction(code, MAX_INSN_SIZE, &insn);

	if(count > 0)
	{
		log("Next instruction: %s\t%s\n", insn[0].mnemonic, insn[0].op_str);
	}
}
