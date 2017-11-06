/***************************************************************************************************\
*																									*
*									DIZAHEX DISASSEMBLER ENGINE										*
*																									*
*								(flags, structure and func-prototype)								*
*																									*
\***************************************************************************************************/



																			//pr0mix
																			//?????????? ??? ???? - ????????? ?????



#ifndef DIZAHEX_H
#define DIZAHEX_H



#include <stdint.h>
//#include "stdint.h"



#define DISASM_MODE_32		0x01
#define DISASM_MODE_64		0x02



#define F_MODRM				0x00000001	//byte MODRM present
#define F_SIB				0x00000002	//SIB
#define F_DISP_8			0x00000010	//DISP_8
#define F_DISP_16			0x00000020	//DISP_16
#define F_DISP_32			0x00000040	//DISP_32
#define F_IMM_8				0x00000100	//IMM_8
#define F_IMM_16			0x00000200	//IMM_16
#define F_IMM_32			0x00000400	//IMM_32
#define F_IMM_64			0x00000800	//IMM_64
#define F_REL				0x00001000	//IMM* is a relative address in the command
#define F_COP_IMM_DISP		0x00002000	//change processing order for IMM and DISP
#define F_PFX_66			0x00010000	//0x66
#define F_PFX_67			0x00020000	//0x67
#define F_PFX_SEG			0x00040000	//segment prefix is present
#define F_PFX_REP			0x00080000	//repetition prefix is present
#define F_PFX_LOCK			0x00100000	//LOCK
#define F_PFX_REX			0x00200000	//REX
#define F_PFX_ANY_32		(F_PFX_66 | F_PFX_67 | F_PFX_SEG | F_PFX_REP | F_PFX_LOCK)
#define F_PFX_ANY_64		(F_PFX_66 | F_PFX_67 | F_PFX_SEG | F_PFX_REP | F_PFX_LOCK | F_PFX_REX)
#define F_ERROR				0x01000000



#pragma pack(push, 1)

typedef struct
{
	uint8_t		mode;			//disassembly mode		(DISASM_MODE_32/DISASM_MODE_64)
	uint8_t		len;			//command length
	uint8_t		pfx_66;			//operand size prefix	(0x66)
	uint8_t		pfx_67;			//address size prefix	(0x67)
	uint8_t		pfx_seg;		//segment prefix		(0x26/0x2E/0x36/0x3E/0x64/0x65)
	uint8_t		pfx_rep;		//repetition prefix 	(0xF2/0xF3)
	uint8_t		pfx_lock;		//lock prefix			(0xF0)
	uint8_t		pfx_rex;		//REX prefix			([0x40..0x4F])
	uint8_t		opcode;			//opcode
	uint8_t		opcode_2;		//2nd opcode (if the 1st opcode = 0x0F)
	uint8_t		modrm;			//MODRM byte
	uint8_t		sib;			//SIB
	union
	{
		uint8_t		disp_8;		//DISP_8 	(1-byte displacement)
		uint16_t	disp_16;	//DISP_16	(2-byte displacement)
		uint32_t	disp_32;	//DISP_32	(4-byte displacement)

	}disp;
	union
	{
		uint8_t		imm_8;		//IMM_8		(1-byte immediate value)
		uint16_t	imm_16;		//IMM_16	(2-byte immediate value)
		uint32_t	imm_32;		//IMM_32	(4-byte immediate value)
		uint64_t	imm_64;		//IMM_64	(8-byte immediate value)
	}imm;
	uint32_t	flags;			//flags; 
}DIZAHEX_STRUCT;

#pragma pack(pop)



#ifdef __cplusplus
extern "C" {
#endif


int dizahex_disasm(uint8_t *pcode, DIZAHEX_STRUCT *pdiza); 
int dizahex_asm(uint8_t *pcode, DIZAHEX_STRUCT *pdiza);


#ifdef __cplusplus
}
#endif



#endif /* DIZAHEX_H */

