#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#define			MAX_INSN_SIZE				8
#define			MAX_DISASSEMBLE_CODE_SIZE	64
#define			ADDR_FIRST_INSN				0x1000

#define 		CMD_PREFIX		"$ "
// commands
#define			CMD_QUIT		"quit"
#define			CMD_CONTINUE	"continue"
#define			CMD_STEP		"step"
#define			CMD_NEXT		"next"
#define 		CMD_SETBP		"break"
#define			CMD_DELETEBP	"delete"
#define			CMD_CLEARBP		"clear"
#define			CMD_PRINT		"print"
#define			CMD_INFO		"info"
#define			CMD_DISASSEMBLE	"disassemble"
#define 		CMD_DUMP		"x"

// command shortcuts
#define			CMD_S_QUIT		"q"
#define			CMD_S_CONTINUE	"c"
#define			CMD_S_STEP		"s"
#define			CMD_S_NEXT		"n"
#define 		CMD_S_SETBP		"b"
#define			CMD_S_DELETEBP	"d"
#define			CMD_S_PRINT		"p"
#define			CMD_S_INFO		"i"

// command-info
#define			INFO_REGISTERS	"registers"
#define			INFO_BREAKPOINT	"breakpoint"

#endif
