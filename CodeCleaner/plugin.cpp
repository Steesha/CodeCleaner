#include <Windows.h>
#include "plugin.h"
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <iostream>
#include <string>
#include <sstream>
#include <asmjit/asmjit.h>
#include <asmjit/x86.h>

using namespace std;
using namespace asmjit;
using namespace asmjit::x86;

void cbMenuEntry(CBTYPE cbType, void* info1)
{
	PLUG_CB_MENUENTRY* info = reinterpret_cast<PLUG_CB_MENUENTRY*>(info1);
	if (info->hEntry == 0 || info->hEntry == 1)
	{
		DbgCmdExec(PLUGIN_NAME);
	}
}

Gp cvrtCsRegToGp(x86_reg r)
{
	switch (r)
	{
		//X64
	case X86_REG_RAX:
		return rax;
	case X86_REG_RBX:
		return rbx;
	case X86_REG_RCX:
		return rcx;
	case X86_REG_RDX:
		return rdx;
	case X86_REG_RDI:
		return rdi;
	case X86_REG_RSI:
		return rsi;
	case X86_REG_RSP:
		return rsp;
	case X86_REG_RBP:
		return rbp;

	case X86_REG_R8:
		return r8;
	case X86_REG_R9:
		return r9;
	case X86_REG_R10:
		return r10;
	case X86_REG_R11:
		return r11;
	case X86_REG_R12:
		return r12;
	case X86_REG_R13:
		return r13;
	case X86_REG_R14:
		return r14;
	case X86_REG_R15:
		return r15;

		//X32
	case X86_REG_EAX:
		return eax;
	case X86_REG_EBX:
		return ebx;
	case X86_REG_ECX:
		return ecx;
	case X86_REG_EDX:
		return edx;
	case X86_REG_EDI:
		return edi;
	case X86_REG_ESI:
		return esi;
	case X86_REG_ESP:
		return esp;
	case X86_REG_EBP:
		return ebp;
	case X86_REG_R8D:
		return r8d;
	case X86_REG_R9D:
		return r9d;
	case X86_REG_R10D:
		return r10d;
	case X86_REG_R11D:
		return r11d;
	case X86_REG_R12D:
		return r12d;
	case X86_REG_R13D:
		return r13d;
	case X86_REG_R14D:
		return r14d;
	case X86_REG_R15D:
		return r15d;

		//X16
	case X86_REG_AX:
		return ax;
	case X86_REG_BX:
		return bx;
	case X86_REG_CX:
		return cx;
	case X86_REG_DX:
		return dx;
	case X86_REG_DI:
		return di;
	case X86_REG_SI:
		return si;
	case X86_REG_SP:
		return sp;
	case X86_REG_BP:
		return bp;
	case X86_REG_R8W:
		return r8w;
	case X86_REG_R9W:
		return r9w;
	case X86_REG_R10W:
		return r10w;
	case X86_REG_R11W:
		return r11w;
	case X86_REG_R12W:
		return r12w;
	case X86_REG_R13W:
		return r13w;
	case X86_REG_R14W:
		return r14w;
	case X86_REG_R15W:
		return r15w;
		//X8
	case X86_REG_AH:
		return ah;
	case X86_REG_BH:
		return bh;
	case X86_REG_CH:
		return ch;
	case X86_REG_DH:
		return dh;
	case X86_REG_AL:
		return al;
	case X86_REG_BL:
		return bl;
	case X86_REG_CL:
		return cl;
	case X86_REG_DL:
		return dl;
	case X86_REG_R8B:
		return r8b;
	case X86_REG_R9B:
		return r9b;
	case X86_REG_R10B:
		return r10b;
	case X86_REG_R11B:
		return r11b;
	case X86_REG_R12B:
		return r12b;
	case X86_REG_R13B:
		return r13b;
	case X86_REG_R14B:
		return r14b;
	case X86_REG_R15B:
		return r15b;
	default:
		MessageBoxA(hwndDlg, "[" PLUGIN_NAME "]Failed Converting CsReg to Gp.\n Press OK to quit.", "Fatel Error", MB_OK | MB_ICONERROR);
		throw "ConvertGp";
	}
}

//排除一切nop干扰
int getLastInsIndex(const cs_insn* insn, int now_index)
{
	//故意找茬(如果索引为0也意味着前面没指令)
	if (now_index <= 0) return -1;

	//索引前一个
	int result = now_index - 1;
	for (; result >= -1; result--)
	{

		//检索失败
		if (result < 0)
		{
			return -1;
		}

		if (insn[result].id != X86_INS_NOP)
		{
			break;
		}
	}

	return result;
}

bool cleanCode(const cs_insn* insn, size_t codeCount)
{
	bool modified = false;
	for (size_t i = 0; i < codeCount; i++)
	{
		if (insn[i].id == X86_INS_NOP)
		{
			continue;
		}

		if (insn[i].detail == NULL)
		{
			_plugin_logprintf("[" PLUGIN_NAME "][Cs] failed to get CODE-INSN! \n", insn[i].mnemonic);
			break;
		}

		cs_x86* x86_this = &(insn[i].detail->x86);

		//清理MOV(MOV REG,REG)
		if (insn[i].id == X86_INS_MOV)
		{
			if (x86_this->operands[0].type == X86_OP_REG && x86_this->operands[0].reg == x86_this->operands[1].reg)
			{
				DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
				modified = true;
				break;
			}
		}

		//清理XCHG(XCHG REG,REG)
		if (insn[i].id == X86_INS_XCHG)
		{
			if (x86_this->operands[0].type == X86_OP_REG && x86_this->operands[0].reg == x86_this->operands[1].reg)
			{
				DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
				modified = true;
				break;
			}
		}

		//化简指令 MOV REG,0 / AND REG,0
		if (insn[i].id == X86_INS_MOV || insn[i].id == X86_INS_AND)
		{
			if (x86_this->operands[0].type == X86_OP_REG
				&& x86_this->operands[1].type == X86_OP_IMM
				&& x86_this->operands[1].imm == 0)
			{
				DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
				Environment env;
				env.setArch(Arch::kX64);
				//Asmjit 初始化
				CodeHolder code;
				code.init(env);
				x86::Assembler a(&code);
				a.xor_(cvrtCsRegToGp(x86_this->operands[0].reg), cvrtCsRegToGp(x86_this->operands[0].reg));
				PBYTE tCode = new BYTE[code.codeSize()];
				code.copyFlattenedData(tCode, code.codeSize());
				DbgFunctions()->MemPatch(insn[i].address, tCode, code.codeSize());
				delete[] tCode;
				modified = true;
				code.reset();
				modified = true;
				break;
			}
		}

		//必须int传进传出
		int last = getLastInsIndex(insn, (int)i);

		//如果有上一行指令
		if (last != -1)
		{
			cs_x86* x86_last = &(insn[last].detail->x86);
			//如果上一行指令是PUSH 且本行指令是 MOV [RSP],xxx
			if (insn[last].id == X86_INS_PUSH && insn[i].id == X86_INS_MOV)
			{
				if (x86_this->operands[0].type == X86_OP_MEM
					&& x86_this->operands[0].mem.base == X86_REG_RSP
					&& x86_this->operands[0].mem.disp == 0
					&& x86_this->operands[0].mem.scale == 1
					)
				{

					//替换为PUSH xxx
					if (x86_this->operands[1].type == X86_OP_IMM)
					{
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						Environment env;
						env.setArch(Arch::kX64);
						//Asmjit 初始化
						CodeHolder code;
						code.init(env);
						x86::Assembler a(&code);
						a.push(x86_this->operands[1].imm);
						PBYTE tCode = new BYTE[code.codeSize()];
						code.copyFlattenedData(tCode, code.codeSize());
						DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
						delete[] tCode;
						modified = true;
						code.reset();
						break;
					}
					else if (x86_this->operands[1].type == X86_OP_REG && x86_this->operands[1].reg != X86_REG_RSP) //不对RSP进行处理
					{
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						Environment env;
						env.setArch(Arch::kX64);
						//Asmjit 初始化
						CodeHolder code;
						code.init(env);
						x86::Assembler a(&code);
						a.push(cvrtCsRegToGp(x86_this->operands[1].reg));
						PBYTE tCode = new BYTE[code.codeSize()];
						code.copyFlattenedData(tCode, code.codeSize());
						DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
						delete[] tCode;
						modified = true;
						code.reset();
						break;
					}
				}
			}

			//SUB RSP,0x8; MOV [RSP],REG
			if (insn[last].id == X86_INS_SUB && insn[i].id == X86_INS_MOV)
			{
				if (x86_last->operands[0].type == X86_OP_REG
					&& x86_last->operands[0].reg == X86_REG_RSP
					&& x86_last->operands[1].type == X86_OP_IMM
					&& x86_last->operands[1].imm == 0x8
					&& x86_this->operands[0].type == X86_OP_MEM
					&& x86_this->operands[1].type == X86_OP_REG
					&& x86_this->operands[1].reg != X86_REG_RSP)
				{
					//PUSH REG
					DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
					Environment env;
					env.setArch(Arch::kX64);
					//Asmjit 初始化
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.push(cvrtCsRegToGp(x86_this->operands[1].reg));
					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
					delete[] tCode;
					modified = true;
					code.reset();
					break;
				}
			}

			//MOV + POP 清理
			/*
			MOV R11, xxx
			POP R11
			-> 清除第一个MOV
			*/
			if (insn[last].id == X86_INS_MOV && insn[i].id == X86_INS_POP)
			{
				if (x86_last->operands[0].type == X86_OP_REG
					&& x86_last->operands[0].reg != X86_REG_RSP
					&& x86_this->operands[0].type == X86_OP_REG
					&& x86_this->operands[0].reg == x86_last->operands[0].reg)
				{
					//PUSH REG
					DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
					modified = true;
					break;
				}
			}

			//MOV REG,[RSP]; ADD RSP,0x8
			if (insn[last].id == X86_INS_MOV && insn[i].id == X86_INS_ADD)
			{
				if (x86_last->operands[0].type == X86_OP_REG
					&& x86_last->operands[1].type == X86_OP_MEM
					&& x86_last->operands[1].mem.base == X86_REG_RSP
					&& x86_last->operands[1].mem.scale == 1
					&& x86_last->operands[1].mem.disp == 0
					&& x86_last->operands[0].reg != X86_REG_RSP
					&& x86_this->operands[0].reg == X86_REG_RSP
					&& x86_this->operands[1].imm == 0x8)
				{
					//POP REG
					DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
					Environment env;
					env.setArch(Arch::kX64);
					//Asmjit 初始化
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.pop(cvrtCsRegToGp(x86_last->operands[0].reg));
					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
					delete[] tCode;
					modified = true;
					code.reset();
					break;
				}
			}

			//PUSH [RSP] / REG; POP [xxx] /REG1
			if (insn[last].id == X86_INS_PUSH && insn[i].id == X86_INS_POP)
			{
				/*
				PUSH [RSP+x]
				POP REG
				-->
				MOV REG, [RSP+x]
				*/
				if (x86_last->operands[0].type == X86_OP_MEM
					&& x86_last->operands[0].mem.base == X86_REG_RSP
					&& x86_this->operands[0].type == X86_OP_REG
					)
				{
					//MOV REG, [RSP]
					DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
					Environment env;
					env.setArch(Arch::kX64);
					//Asmjit 初始化
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					if (x86_this->operands[0].mem.index == X86_REG_INVALID)
					{
						a.mov(cvrtCsRegToGp(x86_this->operands[0].reg),
							ptr(cvrtCsRegToGp(x86_last->operands[0].mem.base),
								(int32_t)x86_last->operands[0].mem.disp));
					}
					else
					{
						a.mov(cvrtCsRegToGp(x86_this->operands[0].reg),
							ptr(cvrtCsRegToGp(x86_last->operands[0].mem.base),
								cvrtCsRegToGp(x86_last->operands[0].mem.index),
								x86_last->operands[0].mem.scale / 2,
								(int32_t)x86_last->operands[0].mem.disp));
					}

					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
					delete[] tCode;
					modified = true;
					code.reset();
					break;
				}
				/*
				PUSH REG
				POP [rsp+X]
				-->
				MOV [RSP+x],REG
				*/
				else if (x86_last->operands[0].type == X86_OP_REG
					&& x86_last->operands[0].reg != X86_REG_RSP
					&& x86_this->operands[0].type == X86_OP_MEM
					&& x86_this->operands[0].mem.base == X86_REG_RSP
					)
				{
					DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
					Environment env;
					env.setArch(Arch::kX64);
					//Asmjit 初始化
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					if (x86_this->operands[0].mem.index == X86_REG_INVALID)
					{
						a.mov(ptr(cvrtCsRegToGp(x86_this->operands[0].mem.base),
							(int32_t)x86_this->operands[0].mem.disp), cvrtCsRegToGp(x86_last->operands[0].reg));
					}
					else
					{
						a.mov(ptr(cvrtCsRegToGp(x86_this->operands[0].mem.base),
							cvrtCsRegToGp(x86_this->operands[0].mem.index),
							x86_this->operands[0].mem.scale / 2,
							(int32_t)x86_this->operands[0].mem.disp), cvrtCsRegToGp(x86_last->operands[0].reg));
					}

					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
					delete[] tCode;
					modified = true;
					code.reset();
					break;
				}
				else if (x86_last->operands[0].type == X86_OP_REG
					&& x86_last->operands[0].reg != X86_REG_RSP
					&& x86_this->operands[0].type == X86_OP_MEM
					&& x86_this->operands[0].mem.base != X86_REG_RSP
					&& x86_this->operands[0].mem.index != X86_REG_RSP
					)
				{
					DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
					Environment env;
					env.setArch(Arch::kX64);
					//Asmjit 初始化
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.mov(ptr(
						cvrtCsRegToGp(x86_this->operands[0].mem.base),
						cvrtCsRegToGp(x86_this->operands[0].mem.index),
						x86_this->operands[0].mem.scale / 2,
						(int32_t)x86_this->operands[0].mem.disp), cvrtCsRegToGp(x86_last->operands[0].reg));
					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
					delete[] tCode;
					modified = true;
					code.reset();
					break;
				}
				/*
				PUSH REG1
				POP REG2
				-->
				MOV REG2, REG1
				*/
				else if (x86_last->operands[0].type == X86_OP_REG
					&& x86_this->operands[0].type == X86_OP_REG
					&& x86_this->operands[0].reg != x86_last->operands[0].reg
					)
				{
					/*  暂时不清理!
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						Environment env;
						env.setArch(Arch::kX64);
						//Asmjit 初始化
						CodeHolder code;
						code.init(env);
						x86::Assembler a(&code);
						a.mov(cvrtCsRegToGp(x86_this->operands[0].reg), cvrtCsRegToGp(x86_last->operands[0].reg));
						PBYTE tCode = new BYTE[code.codeSize()];
						code.copyFlattenedData(tCode, code.codeSize());
						DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
						delete[] tCode;
						modified = true;
						code.reset();
						break;
					*/
				}
			}

			//解决ADD [RSP], IMM + POP REG 问题(先pop再操作)
			if (insn[i].id == X86_INS_POP)
			{
				//第一个指令是否为XXX [RSP],IMM 第二个指令是否为POP REG 
				if (x86_this->operands[0].type == X86_OP_REG
					&& x86_this->operands[0].reg != X86_REG_RSP
					&& x86_last->operands[0].type == X86_OP_MEM
					&& x86_last->operands[0].mem.base == X86_REG_RSP
					&& x86_last->operands[0].mem.scale == 1
					&& x86_last->operands[0].mem.disp == 0
					&& x86_last->operands[1].type == X86_OP_IMM)
				{
					bool isValid = true;
					Environment env;
					env.setArch(Arch::kX64);
					//Asmjit 初始化
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);

					switch (insn[last].id)
					{
					case X86_INS_ADD:
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						a.pop(cvrtCsRegToGp(x86_this->operands[0].reg));
						a.add(cvrtCsRegToGp(x86_this->operands[0].reg), x86_last->operands[1].imm);
						break;
					case X86_INS_SUB:
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						a.pop(cvrtCsRegToGp(x86_this->operands[0].reg));
						a.sub(cvrtCsRegToGp(x86_this->operands[0].reg), x86_last->operands[1].imm);
						break;
					case X86_INS_XOR:
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						a.pop(cvrtCsRegToGp(x86_this->operands[0].reg));
						a.xor_(cvrtCsRegToGp(x86_this->operands[0].reg), x86_last->operands[1].imm);
						break;
					case X86_INS_AND:
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						a.pop(cvrtCsRegToGp(x86_this->operands[0].reg));
						a.and_(cvrtCsRegToGp(x86_this->operands[0].reg), x86_last->operands[1].imm);
						break;
					case X86_INS_OR:
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						a.pop(cvrtCsRegToGp(x86_this->operands[0].reg));
						a.or_(cvrtCsRegToGp(x86_this->operands[0].reg), x86_last->operands[1].imm);
						break;
					default:
						isValid = false;
						break;
					}

					if (isValid)
					{
						PBYTE tCode = new BYTE[code.codeSize()];
						code.copyFlattenedData(tCode, code.codeSize());
						DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
						delete[] tCode;
						modified = true;
						code.reset();
						break;
					}

					code.reset();
				}
			}

			//清理PUSH+POP(IMM不可以，如果是IMM，POP必然会修改寄存器或内存)
			if (insn[last].id == X86_INS_PUSH && insn[i].id == X86_INS_POP)
			{
				if (x86_last->operands[0].type == x86_this->operands[0].type)
				{
					if ((x86_this->operands[0].type == X86_OP_MEM
						&& x86_last->operands[0].mem.base == x86_this->operands[0].mem.base
						&& x86_last->operands[0].mem.index == x86_this->operands[0].mem.index
						&& x86_last->operands[0].mem.scale == x86_this->operands[0].mem.scale
						&& x86_last->operands[0].mem.disp == x86_this->operands[0].mem.disp
						&& x86_last->operands[0].mem.segment == x86_this->operands[0].mem.segment)
						||
						(x86_this->operands[0].type == X86_OP_REG
							&& x86_last->operands[0].reg == x86_this->operands[0].reg))
					{
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						modified = true;
						break;
					}
				}
			}

			//清理ADD+SUB
			if ((insn[last].id == X86_INS_ADD && insn[i].id == X86_INS_SUB) || (insn[i].id == X86_INS_ADD && insn[last].id == X86_INS_SUB))
			{
				if (x86_last->operands[0].type == x86_this->operands[0].type)
				{
					if ((x86_this->operands[0].type == X86_OP_MEM
						&& x86_last->operands[0].mem.base == x86_this->operands[0].mem.base
						&& x86_last->operands[0].mem.index == x86_this->operands[0].mem.index
						&& x86_last->operands[0].mem.scale == x86_this->operands[0].mem.scale
						&& x86_last->operands[0].mem.disp == x86_this->operands[0].mem.disp
						&& x86_last->operands[0].mem.segment == x86_this->operands[0].mem.segment
						&& x86_last->operands[1].type == X86_OP_IMM
						&& x86_this->operands[1].type == X86_OP_IMM
						&& x86_this->operands[1].imm == x86_last->operands[1].imm)
						||
						(x86_this->operands[0].type == X86_OP_REG
							&& x86_last->operands[0].reg == x86_this->operands[0].reg
							&& x86_last->operands[1].type == X86_OP_IMM
							&& x86_this->operands[1].type == X86_OP_IMM
							&& x86_this->operands[1].imm == x86_last->operands[1].imm
							))
					{
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						modified = true;
						break;
					}
				}
			}

			//上上一行指令
			int last2 = getLastInsIndex(insn, (int)last);
			//有前两行指令
			if (last2 != -1)
			{
				cs_x86* x86_last2 = &(insn[last2].detail->x86);
				cs_x86* x86_last = &(insn[last].detail->x86);
				cs_x86* x86_this = &(insn[i].detail->x86);
				//PUSH;PUSH;POP [RSP]
				if (insn[i].id == X86_INS_POP && x86_this->operands[0].type == X86_OP_MEM)
				{
					//前两个都是PUSH 第一个可以是SUB RSP,0x8
					if ((insn[last2].id == X86_INS_PUSH
						|| (insn[last2].id == X86_INS_SUB
							&& x86_last2->operands[0].type == X86_OP_REG
							&& x86_last2->operands[0].reg == X86_REG_RSP
							&& x86_last2->operands[1].type == X86_OP_IMM
							&& x86_last2->operands[1].imm == 0x8)
						) && insn[last].id == X86_INS_PUSH)
					{
						//只留第二个PUSH
						DbgFunctions()->AssembleAtEx(insn[last2].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						if (x86_last->operands[0].type == X86_OP_IMM)
						{
							Environment env;
							env.setArch(Arch::kX64);
							//Asmjit 初始化
							CodeHolder code;
							code.init(env);
							x86::Assembler a(&code);
							a.push(x86_last->operands[0].imm);
							PBYTE tCode = new BYTE[code.codeSize()];
							code.copyFlattenedData(tCode, code.codeSize());
							DbgFunctions()->MemPatch(insn[last2].address, tCode, code.codeSize());
							delete[] tCode;
							modified = true;
							code.reset();
							break;
						}
						else if (x86_last->operands[0].type == X86_OP_REG)
						{
							Environment env;
							env.setArch(Arch::kX64);
							//Asmjit 初始化
							CodeHolder code;
							code.init(env);
							x86::Assembler a(&code);
							a.push(cvrtCsRegToGp(x86_last->operands[0].reg));
							PBYTE tCode = new BYTE[code.codeSize()];
							code.copyFlattenedData(tCode, code.codeSize());
							DbgFunctions()->MemPatch(insn[last2].address, tCode, code.codeSize());
							delete[] tCode;
							modified = true;
							code.reset();
							break;
						}
						else
						{
							//暂不处理
						}
					}
				}

			}
		}
	}
	
	return modified;
}

bool cleanCode2(const cs_insn* insn, size_t codeCount)
{
	bool modified = false;

	for (size_t i = 0; i < codeCount; i++)
	{
		if (insn[i].id == X86_INS_NOP)
		{
			continue;
		}

		int lastIndx = getLastInsIndex(insn, (int)i);
		if (lastIndx == -1)
		{
			continue;
		}

	/*
		if (insn[i].detail->regs_write_count == 1
			&& insn[lastIndx].detail->regs_write_count == 1)
		{
			if (insn[i].detail->regs_write[0] == insn[lastIndx].detail->regs_write[0])
			{
				DbgFunctions()->AssembleAtEx(insn[lastIndx].address, "NOP", 0, true);
				modified = true;
				break;
			}
		}
	*/
	}
	return modified;
}

static bool cbCommand(int argc, char* argv[])
{
	if (argc != 1)
	{
		_plugin_logputs("[" PLUGIN_NAME "] Command has no parameters\n");
		return false;
	}

	SELECTIONDATA sel;
	GuiSelectionGet(GUI_DISASSEMBLY, &sel);

	//检测是否为一行指令
	if (sel.end == sel.start)
	{
		_plugin_logprintf("[" PLUGIN_NAME "] Please Select an area (more than 1 insn).\n");
		return false;
	}

	BASIC_INSTRUCTION_INFO info;
	DbgDisasmFastAt(sel.end, &info);
	sel.end += info.size;

	csh handle;
	if (cs_open(cs_arch::CS_ARCH_X86, cs_mode::CS_MODE_64, &handle) != CS_ERR_OK)
	{
		_plugin_logprintf("[" PLUGIN_NAME "] Capstone Init Failed.\n");
		return false;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	int repeats = 0;
	while (true)
	{
		cs_insn* insn;
		BYTE* mem = new BYTE[sel.end - sel.start];
		DbgMemRead(sel.start, mem, sel.end - sel.start);
		size_t codeCount = cs_disasm(handle, (const uint8_t*)mem, sel.end - sel.start, sel.start, 0, &insn);

		//如果没有任何Clean了，退出大循环
		bool exitFlag = !cleanCode(insn, codeCount);
		if (exitFlag)
		{
			exitFlag = !cleanCode2(insn, codeCount);
		}

		GuiUpdateDisassemblyView();

		cs_free(insn, codeCount);
		delete[] mem;
		repeats++;
		if (repeats > 100)
		{
			int res = MessageBoxA(hwndDlg, "当前清理的代码过多，如果继续清理可能会卡死，是否停止？", "警告", MB_YESNO | MB_ICONASTERISK);
			if (res == IDYES)
			{
				break;
			}
			else
			{
				repeats = 0;
			}
		}
		if (exitFlag)
		{
			break;
		}
	}
	_plugin_logprintf("[" PLUGIN_NAME "] CodeCleaned!\n");
	return true;
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	return true;
}

bool pluginStop()
{
	return true;
}

void pluginSetup()
{
	if (!_plugin_registercommand(pluginHandle, PLUGIN_NAME, cbCommand, true))
	{
		_plugin_logputs("[" PLUGIN_NAME "] Error registering the \"" PLUGIN_NAME "\" command!\n");
	}

	if (!_plugin_menuaddentry(hMenu, 0, PLUGIN_NAME))
	{
		_plugin_logputs("[" PLUGIN_NAME "] Error registering the \"" PLUGIN_NAME "\" menu!\n");
	}

	if (!_plugin_menuaddentry(hMenuDisasm, 1, PLUGIN_NAME))
	{
		_plugin_logputs("[" PLUGIN_NAME "] Error registering the \"" PLUGIN_NAME "\" menu!\n");
	}

	ICONDATA icon{ {0}, 0 };
	_plugin_menuseticon(hMenuDisasm, &icon);
	_plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
	_plugin_menuentrysethotkey(pluginHandle, 1, "F6");
}