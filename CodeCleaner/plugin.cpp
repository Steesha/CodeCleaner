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

//�ų�һ��nop����
int getLastInsIndex(const cs_insn* insn, int now_index)
{
	//�����Ҳ�(�������Ϊ0Ҳ��ζ��ǰ��ûָ��)
	if (now_index <= 0) return -1;

	//����ǰһ��
	int result = now_index - 1;
	for (; result >= -1; result--)
	{

		//����ʧ��
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

static uint32_t getRegByteSize(x86_reg cs_reg)
{
	using namespace asmjit::x86;

	// �� Capstone �Ĵ���ת��Ϊ AsmJit �Ĵ���
	Gp reg = cvrtCsRegToGp(cs_reg); // ʹ�������е�ת������

	// ��ȡ�ֽ���������
	return reg.size();
}

static uint32_t getRegBitWidth(x86_reg cs_reg)
{
	return getRegByteSize(cs_reg) * 8; // �ֽ��� * 8 = λ��
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

		//����MOV(MOV REG,REG)
		if (insn[i].id == X86_INS_MOV)
		{
			if (x86_this->operands[0].type == X86_OP_REG && x86_this->operands[0].reg == x86_this->operands[1].reg)
			{
				DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
				modified = true;
				break;
			}
		}

		//����XCHG(XCHG REG,REG)
		if (insn[i].id == X86_INS_XCHG)
		{
			if (x86_this->operands[0].type == X86_OP_REG && x86_this->operands[0].reg == x86_this->operands[1].reg)
			{
				DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
				modified = true;
				break;
			}
		}

		//����ָ�� MOV REG,0 / AND REG,0
		if (insn[i].id == X86_INS_MOV || insn[i].id == X86_INS_AND)
		{
			if (x86_this->operands[0].type == X86_OP_REG
				&& x86_this->operands[1].type == X86_OP_IMM
				&& x86_this->operands[1].imm == 0)
			{
				DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
				Environment env;
				env.setArch(Arch::kX64);
				//Asmjit ��ʼ��
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

		//����int��������
		int last = getLastInsIndex(insn, (int)i);

		//�������һ��ָ��
		if (last != -1)
		{
			cs_x86* x86_last = &(insn[last].detail->x86);
			//�����һ��ָ����PUSH �ұ���ָ���� MOV [RSP],xxx
			if (insn[last].id == X86_INS_PUSH && insn[i].id == X86_INS_MOV)
			{
				if (x86_this->operands[0].type == X86_OP_MEM
					&& x86_this->operands[0].mem.base == X86_REG_RSP
					&& x86_this->operands[0].mem.disp == 0
					&& x86_this->operands[0].mem.scale == 1
					)
				{

					//�滻ΪPUSH xxx
					if (x86_this->operands[1].type == X86_OP_IMM)
					{
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						Environment env;
						env.setArch(Arch::kX64);
						//Asmjit ��ʼ��
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
					else if (x86_this->operands[1].type == X86_OP_REG && x86_this->operands[1].reg != X86_REG_RSP) //����RSP���д���
					{
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						Environment env;
						env.setArch(Arch::kX64);
						//Asmjit ��ʼ��
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
					//Asmjit ��ʼ��
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

			//MOV + POP ����
			/*
			MOV R11, xxx
			POP R11
			-> �����һ��MOV
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
					//Asmjit ��ʼ��
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
					//Asmjit ��ʼ��
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
					//Asmjit ��ʼ��
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
					//Asmjit ��ʼ��
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
					/*  ��ʱ������!
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						Environment env;
						env.setArch(Arch::kX64);
						//Asmjit ��ʼ��
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

			//���ADD [RSP], IMM + POP REG ����(��pop�ٲ���)
			if (insn[i].id == X86_INS_POP)
			{
				//��һ��ָ���Ƿ�ΪXXX [RSP],IMM �ڶ���ָ���Ƿ�ΪPOP REG 
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
					//Asmjit ��ʼ��
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

			//����PUSH+POP(IMM�����ԣ������IMM��POP��Ȼ���޸ļĴ������ڴ�)
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

			//����ADD+SUB
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

			cs_x86* x86_next = &(insn[i + 1].detail->x86);
			//��������xor (reg, reg) -> xchg
			if (insn[i + 1].id == X86_INS_XOR && insn[i].id == X86_INS_XOR && insn[i - 1].id == X86_INS_XOR
				&& (x86_next->operands->type == X86_OP_REG && x86_last->operands->type == X86_OP_REG && x86_this->operands->type == X86_OP_REG))
			{
				if (x86_next->operands[0].reg == x86_last->operands[0].reg &&
					x86_next->operands[1].reg == x86_last->operands[1].reg &&
					x86_this->operands[0].reg == x86_last->operands[1].reg &&
					x86_this->operands[1].reg == x86_last->operands[0].reg
					)
				{

					Environment env;
					env.setArch(Arch::kX64);
					//Asmjit ��ʼ��
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.xchg(cvrtCsRegToGp(x86_this->operands[0].reg), cvrtCsRegToGp(x86_this->operands[1].reg));
					DbgFunctions()->AssembleAtEx(insn[i - 1].address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(insn[i + 1].address, "NOP", 0, true);
					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(insn[last].address, tCode, code.codeSize());
				}
				modified = true;
				break;
			}


			//����һ��ָ��
			int last2 = getLastInsIndex(insn, (int)last);
			//��ǰ����ָ��
			if (last2 != -1)
			{
				cs_x86* x86_last2 = &(insn[last2].detail->x86);
				cs_x86* x86_last = &(insn[last].detail->x86);
				cs_x86* x86_this = &(insn[i].detail->x86);
				//PUSH;PUSH;POP [RSP]
				if (insn[i].id == X86_INS_POP && x86_this->operands[0].type == X86_OP_MEM)
				{
					//ǰ��������PUSH ��һ��������SUB RSP,0x8
					if ((insn[last2].id == X86_INS_PUSH
						|| (insn[last2].id == X86_INS_SUB
							&& x86_last2->operands[0].type == X86_OP_REG
							&& x86_last2->operands[0].reg == X86_REG_RSP
							&& x86_last2->operands[1].type == X86_OP_IMM
							&& x86_last2->operands[1].imm == 0x8)
						) && insn[last].id == X86_INS_PUSH)
					{
						//ֻ���ڶ���PUSH
						DbgFunctions()->AssembleAtEx(insn[last2].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[last].address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(insn[i].address, "NOP", 0, true);
						if (x86_last->operands[0].type == X86_OP_IMM)
						{
							Environment env;
							env.setArch(Arch::kX64);
							//Asmjit ��ʼ��
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
							//Asmjit ��ʼ��
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
							//�ݲ�����
						}
					}
				}

			}
		}


		// ���� push reg; mov reg, imm; mov [rsp+8], reg; pop reg �����
		if (insn[i].id == X86_INS_POP) {
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_REG) {
				x86_reg pop_reg = x86_this->operands[0].reg;

				// ��ȡǰ������Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;
				int last2 = getLastInsIndex(insn, last1);
				if (last2 == -1) continue;
				int last3 = getLastInsIndex(insn, last2);
				if (last3 == -1) continue;

				// ��֤��ָ��ģʽ
				const cs_insn* push_insn = &insn[last3];
				const cs_insn* mov_imm_insn = &insn[last2];
				const cs_insn* mov_mem_insn = &insn[last1];
				const cs_insn* pop_insn = &insn[i];

				if (push_insn->id == X86_INS_PUSH &&
					push_insn->detail->x86.operands[0].type == X86_OP_REG &&
					push_insn->detail->x86.operands[0].reg == pop_reg &&

					mov_imm_insn->id == X86_INS_MOVABS &&
					mov_imm_insn->detail->x86.operands[0].type == X86_OP_REG &&
					mov_imm_insn->detail->x86.operands[0].reg == pop_reg &&

					mov_imm_insn->detail->x86.operands[1].type == X86_OP_IMM &&
					mov_mem_insn->id == X86_INS_MOV &&
					mov_mem_insn->detail->x86.operands[0].type == X86_OP_MEM &&

					mov_mem_insn->detail->x86.operands[0].mem.base == X86_REG_RSP &&
					mov_mem_insn->detail->x86.operands[0].mem.disp == 8 &&
					mov_mem_insn->detail->x86.operands[1].type == X86_OP_REG &&

					mov_mem_insn->detail->x86.operands[1].reg == pop_reg &&
					pop_insn->detail->x86.operands[0].reg == pop_reg) {

					// ��ȡ������ֵ
					uint64_t imm = mov_imm_insn->detail->x86.operands[1].imm;

					// ���ԭָ��
					DbgFunctions()->AssembleAtEx(push_insn->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(mov_imm_insn->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(mov_mem_insn->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(pop_insn->address, "NOP", 0, true);

					// ���� MOV [RSP], imm
					Environment env;
					env.setArch(Arch::kX64);
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.mov(qword_ptr(rsp), imm);

					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(push_insn->address, tCode, code.codeSize());
					delete[] tCode;
					code.reset();

					modified = true;
					break;
				}
			}
		}

		// ���� push rcx; mov rcx, r15; mov r15, rcx; pop rcx;
		if (insn[i].id == X86_INS_POP) {
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_REG) {
				x86_reg pop_reg = x86_this->operands[0].reg;

				// ��ȡǰ������Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;
				int last2 = getLastInsIndex(insn, last1);
				if (last2 == -1) continue;
				int last3 = getLastInsIndex(insn, last2);
				if (last3 == -1) continue;

				// ��֤��ָ��ģʽ
				const cs_insn* push_insn = &insn[last3];
				const cs_insn* mov_reg2_reg1 = &insn[last2];
				const cs_insn* mov_reg1_reg2 = &insn[last1];
				const cs_insn* pop_insn = &insn[i];


				if (push_insn->id == X86_INS_PUSH &&
					push_insn->detail->x86.operands[0].type == X86_OP_REG &&
					push_insn->detail->x86.operands[0].reg == pop_reg &&

					mov_reg2_reg1->id == X86_INS_MOV &&
					mov_reg2_reg1->detail->x86.operands[0].type == X86_OP_REG &&
					mov_reg2_reg1->detail->x86.operands[0].reg == pop_reg &&
					mov_reg2_reg1->detail->x86.operands[1].type == X86_OP_REG &&
					mov_reg2_reg1->detail->x86.operands[1].reg == mov_reg1_reg2->detail->x86.operands[0].reg &&

					mov_reg1_reg2->id == X86_INS_MOV &&
					mov_reg1_reg2->detail->x86.operands[0].type == X86_OP_REG &&
					mov_reg1_reg2->detail->x86.operands[0].reg == mov_reg2_reg1->detail->x86.operands[1].reg &&
					mov_reg1_reg2->detail->x86.operands[1].type == X86_OP_REG &&
					mov_reg1_reg2->detail->x86.operands[1].reg == pop_reg &&

					pop_insn->detail->x86.operands[0].reg == pop_reg) {

					// ���ԭָ��
					DbgFunctions()->AssembleAtEx(push_insn->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(mov_reg2_reg1->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(mov_reg1_reg2->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(pop_insn->address, "NOP", 0, true);

					modified = true;
					break;
				}
			}
		}

		// ����
		/*
		xor rdi,qword ptr ss:[rsp]
		xor qword ptr ss:[rsp],rdi
		xor rdi,qword ptr ss:[rsp]
		*/
		if (insn[i].id == X86_INS_XOR) {
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_REG) {
				// ��ȡǰ������Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;
				int last2 = getLastInsIndex(insn, last1);
				if (last2 == -1) continue;

				// ��֤��ָ��ģʽ
				const cs_insn* xor_rdi_mem = &insn[last2];
				const cs_insn* xor_mem_rdi = &insn[last1];
				const cs_insn* xor_rdi_mem_1 = &insn[i];


				if (xor_rdi_mem->id == X86_INS_XOR &&
					xor_rdi_mem->detail->x86.operands[0].type == X86_OP_REG &&
					xor_rdi_mem->detail->x86.operands[0].reg == xor_rdi_mem_1->detail->x86.operands[0].reg &&
					xor_rdi_mem->detail->x86.operands[1].type == X86_OP_MEM &&
					xor_rdi_mem->detail->x86.operands[1].mem.base == X86_REG_RSP &&
					xor_rdi_mem->detail->x86.operands[1].mem.disp == 0 &&

					xor_mem_rdi->id == X86_INS_XOR &&
					xor_mem_rdi->detail->x86.operands[1].type == X86_OP_REG &&
					xor_mem_rdi->detail->x86.operands[1].reg == xor_rdi_mem_1->detail->x86.operands[0].reg &&
					xor_mem_rdi->detail->x86.operands[0].type == X86_OP_MEM &&
					xor_mem_rdi->detail->x86.operands[0].mem.base == X86_REG_RSP &&
					xor_mem_rdi->detail->x86.operands[0].mem.disp == 0 &&

					xor_rdi_mem_1->id == X86_INS_XOR &&
					xor_rdi_mem_1->detail->x86.operands[0].type == X86_OP_REG &&
					xor_rdi_mem_1->detail->x86.operands[1].type == X86_OP_MEM &&
					xor_rdi_mem_1->detail->x86.operands[1].mem.base == X86_REG_RSP &&
					xor_rdi_mem_1->detail->x86.operands[1].mem.disp == 0)
				{
					// ���ԭָ��
					DbgFunctions()->AssembleAtEx(xor_rdi_mem->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(xor_mem_rdi->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(xor_rdi_mem_1->address, "NOP", 0, true);


					// ���� XCHG [RSP], reg
					Environment env;
					env.setArch(Arch::kX64);
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.xchg(qword_ptr(rsp), cvrtCsRegToGp(xor_rdi_mem_1->detail->x86.operands[0].reg));

					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(xor_rdi_mem->address, tCode, code.codeSize());
					delete[] tCode;
					code.reset();


					modified = true;
					break;
				}
			}
		}

		// ����
		/*
		add reg, Imm1
		add reg, Imm2
		*/
		if (insn[i].id == X86_INS_ADD)
		{
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_REG)
			{
				// ��ȡǰһ����Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;

				const cs_insn* add_r1 = &insn[last1];
				const cs_insn* add_r2 = &insn[i];

				if (add_r1->id == X86_INS_ADD &&
					add_r2->id == X86_INS_ADD &&
					add_r1->detail->x86.operands[0].type == X86_OP_REG &&
					add_r2->detail->x86.operands[0].type == X86_OP_REG &&
					add_r1->detail->x86.operands[1].type == X86_OP_IMM &&
					add_r2->detail->x86.operands[1].type == X86_OP_IMM)
				{
					// �ؼ��Ľ��㣺���Ĵ����Ƿ���ȫ��ͬ������λ��
					x86_reg reg1 = add_r1->detail->x86.operands[0].reg;
					x86_reg reg2 = add_r2->detail->x86.operands[0].reg;
					if (reg1 != reg2)
						continue; // �Ĵ�����ͬ������

					// ��ȡ�Ĵ���λ��
					int reg_size = getRegBitWidth(reg1);
					

					// BUG
					uint64_t max_imm = (1ULL << reg_size) - 1;
					uint64_t imm_total =
						add_r1->detail->x86.operands[1].imm +
						add_r2->detail->x86.operands[1].imm;
					_plugin_logprintf("imm_total=%llu", imm_total);
					_plugin_logprintf("max_imm=%llu", max_imm);

					if (imm_total > max_imm)
						continue; // ������������Ż�



					// ���ԭָ��
					DbgFunctions()->AssembleAtEx(add_r1->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(add_r2->address, "NOP", 0, true);

					// �����µ� ADD ָ��
					Environment env;
					env.setArch(Arch::kX64);
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);

					// ���ݼĴ���λ��ѡ����ȷ�Ĳ�����
					switch (reg_size)
					{
					case 64:
						a.add(cvrtCsRegToGp(reg1).r8(), imm_total & 0xffffffffffffffff);
						break;

					case 32:
						a.add(cvrtCsRegToGp(reg1).r32(), imm_total & 0xffffffff);
						break;
					case 16:
						a.add(cvrtCsRegToGp(reg1).r16(), imm_total & 0xffff);
						break;
					case 8:
						a.add(cvrtCsRegToGp(reg1).r8(), imm_total & 0xff);
						break;
					}

					// д��ԭ��һ�� ADD �ĵ�ַ
					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(add_r1->address, tCode, code.codeSize());
					delete[] tCode;
					code.reset();

					modified = true;
					break;
				}
			}
		}

		//// ����
		///*
		//sub reg, Imm1
		//sub reg, Imm2
		//*/
		//if (insn[i].id == X86_INS_SUB) {
		//	cs_x86* x86_this = &(insn[i].detail->x86);
		//	if (x86_this->operands[0].type == X86_OP_REG) {
		//		// ��ȡǰ������Чָ������
		//		int last1 = getLastInsIndex(insn, i);
		//		if (last1 == -1) continue;


		//		// ��֤��ָ��ģʽ
		//		const cs_insn* add_r1 = &insn[last1];
		//		const cs_insn* add_r2 = &insn[i];


		//		if (add_r1->id == X86_INS_SUB && add_r2->id == X86_INS_SUB &&

		//			add_r1->detail->x86.operands[0].type == X86_OP_REG &&
		//			add_r2->detail->x86.operands[0].type == X86_OP_REG &&

		//			add_r1->detail->x86.operands[1].type == X86_OP_IMM &&
		//			add_r2->detail->x86.operands[1].type == X86_OP_IMM &&

		//			add_r1->detail->x86.operands[0].reg == add_r2->detail->x86.operands[0].reg)
		//		{
		//			// ���ԭָ��
		//			DbgFunctions()->AssembleAtEx(add_r1->address, "NOP", 0, true);
		//			DbgFunctions()->AssembleAtEx(add_r2->address, "NOP", 0, true);


		//			// ���� XCHG [RSP], reg
		//			Environment env;
		//			env.setArch(Arch::kX64);
		//			CodeHolder code;
		//			code.init(env);
		//			x86::Assembler a(&code);
		//			a.sub(cvrtCsRegToGp(add_r1->detail->x86.operands[0].reg),
		//				add_r1->detail->x86.operands[1].imm + add_r2->detail->x86.operands[1].imm);

		//			PBYTE tCode = new BYTE[code.codeSize()];
		//			code.copyFlattenedData(tCode, code.codeSize());
		//			DbgFunctions()->MemPatch(add_r2->address, tCode, code.codeSize());
		//			delete[] tCode;
		//			code.reset();

		//			modified = true;
		//			break;
		//		}
		//	}
		//}

		//// ����
		///*
		//sub reg, Imm1
		//add reg, Imm2
		//*/
		//if (insn[i].id == X86_INS_ADD) {
		//	cs_x86* x86_this = &(insn[i].detail->x86);
		//	if (x86_this->operands[0].type == X86_OP_REG) {
		//		// ��ȡǰ������Чָ������
		//		int last1 = getLastInsIndex(insn, i);
		//		if (last1 == -1) continue;


		//		// ��֤��ָ��ģʽ
		//		const cs_insn* add_r1 = &insn[last1];
		//		const cs_insn* add_r2 = &insn[i];


		//		if (add_r1->id == X86_INS_SUB && add_r2->id == X86_INS_ADD &&

		//			add_r1->detail->x86.operands[0].type == X86_OP_REG &&
		//			add_r2->detail->x86.operands[0].type == X86_OP_REG &&

		//			add_r1->detail->x86.operands[1].type == X86_OP_IMM &&
		//			add_r2->detail->x86.operands[1].type == X86_OP_IMM &&

		//			add_r1->detail->x86.operands[0].reg == add_r2->detail->x86.operands[0].reg)
		//		{
		//			// ���ԭָ��
		//			DbgFunctions()->AssembleAtEx(add_r1->address, "NOP", 0, true);
		//			DbgFunctions()->AssembleAtEx(add_r2->address, "NOP", 0, true);


		//			// ���� XCHG [RSP], reg
		//			Environment env;
		//			env.setArch(Arch::kX64);
		//			CodeHolder code;
		//			code.init(env);
		//			x86::Assembler a(&code);
		//			a.add(cvrtCsRegToGp(add_r1->detail->x86.operands[0].reg),
		//				-add_r1->detail->x86.operands[1].imm + add_r2->detail->x86.operands[1].imm);

		//			PBYTE tCode = new BYTE[code.codeSize()];
		//			code.copyFlattenedData(tCode, code.codeSize());
		//			DbgFunctions()->MemPatch(add_r2->address, tCode, code.codeSize());
		//			delete[] tCode;
		//			code.reset();

		//			modified = true;
		//			break;
		//		}
		//	}
		//}
		//
		//// ����
		///*
		//add reg, Imm1
		//sub reg, Imm2
		//*/
		//if (insn[i].id == X86_INS_SUB) {
		//	cs_x86* x86_this = &(insn[i].detail->x86);
		//	if (x86_this->operands[0].type == X86_OP_REG) {
		//		// ��ȡǰ������Чָ������
		//		int last1 = getLastInsIndex(insn, i);
		//		if (last1 == -1) continue;


		//		// ��֤��ָ��ģʽ
		//		const cs_insn* add_r1 = &insn[last1];
		//		const cs_insn* add_r2 = &insn[i];


		//		if (add_r1->id == X86_INS_ADD && add_r2->id == X86_INS_SUB &&

		//			add_r1->detail->x86.operands[0].type == X86_OP_REG &&
		//			add_r2->detail->x86.operands[0].type == X86_OP_REG &&

		//			add_r1->detail->x86.operands[1].type == X86_OP_IMM &&
		//			add_r2->detail->x86.operands[1].type == X86_OP_IMM &&

		//			add_r1->detail->x86.operands[0].reg == add_r2->detail->x86.operands[0].reg)
		//		{
		//			// ���ԭָ��
		//			DbgFunctions()->AssembleAtEx(add_r1->address, "NOP", 0, true);
		//			DbgFunctions()->AssembleAtEx(add_r2->address, "NOP", 0, true);


		//			// ���� XCHG [RSP], reg
		//			Environment env;
		//			env.setArch(Arch::kX64);
		//			CodeHolder code;
		//			code.init(env);
		//			x86::Assembler a(&code);
		//			a.add(cvrtCsRegToGp(add_r1->detail->x86.operands[0].reg),
		//				add_r1->detail->x86.operands[1].imm - add_r2->detail->x86.operands[1].imm);

		//			PBYTE tCode = new BYTE[code.codeSize()];
		//			code.copyFlattenedData(tCode, code.codeSize());
		//			DbgFunctions()->MemPatch(add_r2->address, tCode, code.codeSize());
		//			delete[] tCode;
		//			code.reset();

		//			modified = true;
		//			break;
		//		}
		//	}
		//}



		// ����
		/*
		push rdi
		mov rdi,rsp
		add rdi,0x10
		xchg qword ptr ss:[rsp],rdi
		pop rsp
		*/
		if (insn[i].id == X86_INS_POP) {
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_REG && x86_this->operands[0].reg == X86_REG_RSP) {
				// ��ȡǰ������Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;

				int last2 = getLastInsIndex(insn, last1);
				if (last2 == -1) continue;

				int last3 = getLastInsIndex(insn, last2);
				if (last3 == -1) continue;

				int last4 = getLastInsIndex(insn, last3);
				if (last4 == -1) continue;


				// ��֤��ָ��ģʽ
				const cs_insn* push_rdi = &insn[last4];
				const cs_insn* mov_rdi_rsp = &insn[last3];
				const cs_insn* add_rdi_16 = &insn[last2];
				const cs_insn* xchg_memRSP_rdi = &insn[last1];
				const cs_insn* pop_rsp = &insn[i];
				auto mainREG = push_rdi->detail->x86.operands[0].reg;

				if (push_rdi->id == X86_INS_PUSH &&
					push_rdi->detail->x86.operands[0].type == X86_OP_REG &&

					mov_rdi_rsp->id == X86_INS_MOV &&
					mov_rdi_rsp->detail->x86.operands[0].type == X86_OP_REG &&
					mov_rdi_rsp->detail->x86.operands[0].reg == mainREG &&
					mov_rdi_rsp->detail->x86.operands[1].type == X86_OP_REG &&
					mov_rdi_rsp->detail->x86.operands[1].reg == X86_REG_RSP &&

					add_rdi_16->id == X86_INS_ADD &&
					add_rdi_16->detail->x86.operands[0].type == X86_OP_REG &&
					add_rdi_16->detail->x86.operands[0].reg == mainREG &&
					add_rdi_16->detail->x86.operands[1].type == X86_OP_IMM &&
					add_rdi_16->detail->x86.operands[1].imm == 0x10 &&

					xchg_memRSP_rdi->id == X86_INS_XCHG &&
					xchg_memRSP_rdi->detail->x86.operands[0].type == X86_OP_MEM &&
					xchg_memRSP_rdi->detail->x86.operands[0].mem.base == X86_REG_RSP &&
					xchg_memRSP_rdi->detail->x86.operands[0].mem.disp == 0 &&
					xchg_memRSP_rdi->detail->x86.operands[1].type == X86_OP_REG &&
					xchg_memRSP_rdi->detail->x86.operands[1].reg == mainREG &&

					pop_rsp->id == X86_INS_POP&&
					pop_rsp->detail->x86.operands[0].type == X86_OP_REG&&
					pop_rsp->detail->x86.operands[0].reg == X86_REG_RSP)

				{
					// ���ԭָ��
					DbgFunctions()->AssembleAtEx(push_rdi->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(mov_rdi_rsp->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(add_rdi_16->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(xchg_memRSP_rdi->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(pop_rsp->address, "NOP", 0, true);


					// ���� XCHG [RSP], reg
					Environment env;
					env.setArch(Arch::kX64);
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.add(rsp, 0x8);

					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(push_rdi->address, tCode, code.codeSize());
					delete[] tCode;
					code.reset();


					modified = true;
					break;
				}
			}
		}


		// ����
		/*
		push rdi
		mov rdi,rsp
		xchg qword ptr ss:[rsp],rdi
		pop rsp
		*/
		if (insn[i].id == X86_INS_POP) {
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_REG && x86_this->operands[0].reg == X86_REG_RSP) {
				// ��ȡǰ������Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;

				int last2 = getLastInsIndex(insn, last1);
				if (last2 == -1) continue;

				int last3 = getLastInsIndex(insn, last2);
				if (last3 == -1) continue;


				// ��֤��ָ��ģʽ
				const cs_insn* push_rdi = &insn[last3];
				const cs_insn* mov_rdi_rsp = &insn[last2];
				const cs_insn* xchg_memRSP_rdi = &insn[last1];
				const cs_insn* pop_rsp = &insn[i];
				auto mainREG = push_rdi->detail->x86.operands[0].reg;

				if (push_rdi->id == X86_INS_PUSH &&
					push_rdi->detail->x86.operands[0].type == X86_OP_REG &&

					mov_rdi_rsp->id == X86_INS_MOV &&
					mov_rdi_rsp->detail->x86.operands[0].type == X86_OP_REG &&
					mov_rdi_rsp->detail->x86.operands[0].reg == mainREG &&
					mov_rdi_rsp->detail->x86.operands[1].type == X86_OP_REG &&
					mov_rdi_rsp->detail->x86.operands[1].reg == X86_REG_RSP &&

					xchg_memRSP_rdi->id == X86_INS_XCHG &&
					xchg_memRSP_rdi->detail->x86.operands[0].type == X86_OP_MEM &&
					xchg_memRSP_rdi->detail->x86.operands[0].mem.base == X86_REG_RSP &&
					xchg_memRSP_rdi->detail->x86.operands[0].mem.disp == 0 &&
					xchg_memRSP_rdi->detail->x86.operands[1].type == X86_OP_REG &&
					xchg_memRSP_rdi->detail->x86.operands[1].reg == mainREG &&

					pop_rsp->id == X86_INS_POP &&
					pop_rsp->detail->x86.operands[0].type == X86_OP_REG &&
					pop_rsp->detail->x86.operands[0].reg == X86_REG_RSP)

				{
					// ���ԭָ��
					DbgFunctions()->AssembleAtEx(push_rdi->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(mov_rdi_rsp->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(xchg_memRSP_rdi->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(pop_rsp->address, "NOP", 0, true);


					// ���� XCHG [RSP], reg
					Environment env;
					env.setArch(Arch::kX64);
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.sub(rsp, 0x8);
					a.mov(qword_ptr(rsp), rsp);

					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(push_rdi->address, tCode, code.codeSize());
					delete[] tCode;
					code.reset();


					modified = true;
					break;
				}
			}
		}


		// ����
		/*
		mov [rsp], Imm1/Regxx
		mov [rsp], Imm2/Reg
		*/
		if (insn[i].id == X86_INS_MOV) {
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_MEM) {
				// ��ȡǰ������Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;

				// ��֤��ָ��ģʽ
				const cs_insn* mov_1 = &insn[last1];
				const cs_insn* mov_2 = &insn[i];

				if (mov_1->id == X86_INS_MOV && mov_2->id == X86_INS_MOV &&
					mov_1->detail->x86.operands[0].type == X86_OP_MEM &&
					mov_1->detail->x86.operands[0].mem.base == X86_REG_RSP &&
					mov_1->detail->x86.operands[0].mem.disp == mov_2->detail->x86.operands[0].mem.disp&&

					mov_2->detail->x86.operands[0].type == X86_OP_MEM &&
					mov_2->detail->x86.operands[0].mem.base == X86_REG_RSP&&
					mov_2->detail->x86.operands[0].mem.scale == 1 &&
					mov_2->detail->x86.operands[0].mem.index == X86_REG_INVALID
					)
				{
					// Check mop_2 is Imm/Reg
					if (mov_2->detail->x86.operands[1].type == X86_OP_IMM)
					{
						// ���ԭָ��
						DbgFunctions()->AssembleAtEx(mov_1->address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(mov_2->address, "NOP", 0, true);


						// ���� XCHG [RSP], reg
						Environment env;
						env.setArch(Arch::kX64);
						CodeHolder code;
						code.init(env);
						x86::Assembler a(&code);
						a.mov(qword_ptr(rsp, mov_2->detail->x86.operands[0].mem.disp), mov_2->detail->x86.operands[1].imm);

						PBYTE tCode = new BYTE[code.codeSize()];
						code.copyFlattenedData(tCode, code.codeSize());
						DbgFunctions()->MemPatch(mov_1->address, tCode, code.codeSize());
						delete[] tCode;
						code.reset();


						modified = true;
						break;
					}
					else if (mov_2->detail->x86.operands[1].type == X86_OP_REG) {
						// ���ԭָ��
						DbgFunctions()->AssembleAtEx(mov_1->address, "NOP", 0, true);
						DbgFunctions()->AssembleAtEx(mov_2->address, "NOP", 0, true);


						// ���� XCHG [RSP], reg
						Environment env;
						env.setArch(Arch::kX64);
						CodeHolder code;
						code.init(env);
						x86::Assembler a(&code);
						a.mov(qword_ptr(rsp, mov_2->detail->x86.operands[0].mem.disp), cvrtCsRegToGp(mov_2->detail->x86.operands[1].reg));

						PBYTE tCode = new BYTE[code.codeSize()];
						code.copyFlattenedData(tCode, code.codeSize());
						DbgFunctions()->MemPatch(mov_1->address, tCode, code.codeSize());
						delete[] tCode;
						code.reset();


						modified = true;
						break;
					}

					
				}
			}
		}

		// ����
		/*
		push rcx 
		mov rcx,rbp
		xor qword ptr ss:[rsp+0x8],rcx 
		pop rcx
		*/
		if (insn[i].id == X86_INS_POP) {
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_REG) {
				// ��ȡǰ������Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;

				int last2 = getLastInsIndex(insn, last1);
				if (last2 == -1) continue;

				int last3 = getLastInsIndex(insn, last2);
				if (last3 == -1) continue;


				// ��֤��ָ��ģʽ
				const cs_insn* push_rcx = &insn[last3];
				const cs_insn* mov_rcx_rbp = &insn[last2];
				const cs_insn* xor_rsp_8_rcx = &insn[last1];
				const cs_insn* pop_rcx = &insn[i];
				auto mainREG = push_rcx->detail->x86.operands[0].reg;

				if (push_rcx->id == X86_INS_PUSH &&
					push_rcx->detail->x86.operands[0].type == X86_OP_REG &&

					mov_rcx_rbp->id == X86_INS_MOV &&
					mov_rcx_rbp->detail->x86.operands[0].type == X86_OP_REG &&
					mov_rcx_rbp->detail->x86.operands[0].reg == mainREG &&
					mov_rcx_rbp->detail->x86.operands[1].type == X86_OP_REG &&

					xor_rsp_8_rcx->id == X86_INS_XOR &&
					xor_rsp_8_rcx->detail->x86.operands[0].type == X86_OP_MEM &&
					xor_rsp_8_rcx->detail->x86.operands[0].mem.base == X86_REG_RSP &&
					xor_rsp_8_rcx->detail->x86.operands[0].mem.disp == 8 &&
					xor_rsp_8_rcx->detail->x86.operands[1].type == X86_OP_REG &&
					xor_rsp_8_rcx->detail->x86.operands[1].reg == mainREG &&

					pop_rcx->id == X86_INS_POP &&
					pop_rcx->detail->x86.operands[0].type == X86_OP_REG &&
					pop_rcx->detail->x86.operands[0].reg == mainREG)

				{
					// ���ԭָ��
					DbgFunctions()->AssembleAtEx(push_rcx->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(mov_rcx_rbp->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(xor_rsp_8_rcx->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(pop_rcx->address, "NOP", 0, true);


					// ���� XCHG [RSP], reg
					Environment env;
					env.setArch(Arch::kX64);
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.xor_(qword_ptr(rsp), cvrtCsRegToGp(mov_rcx_rbp->detail->x86.operands[1].reg));

					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(push_rcx->address, tCode, code.codeSize());
					delete[] tCode;
					code.reset();


					modified = true;
					break;
				}
			}
		}

		// ����
		/*
		push r14
		sub rsp,0x8
		mov qword ptr ss:[rsp],rsp
		pop r14
		add r14,0x18
		xchg qword ptr ss:[rsp],r14
		pop rsp
		*/
		if (insn[i].id == X86_INS_POP) {
			cs_x86* x86_this = &(insn[i].detail->x86);
			if (x86_this->operands[0].type == X86_OP_REG && x86_this->operands[0].reg == X86_REG_RSP) {
				// ��ȡǰ������Чָ������
				int last1 = getLastInsIndex(insn, i);
				if (last1 == -1) continue;

				int last2 = getLastInsIndex(insn, last1);
				if (last2 == -1) continue;

				int last3 = getLastInsIndex(insn, last2);
				if (last3 == -1) continue;

				int last4 = getLastInsIndex(insn, last3);
				if (last4 == -1) continue;

				int last5 = getLastInsIndex(insn, last4);
				if (last5 == -1) continue;

				int last6 = getLastInsIndex(insn, last5);
				if (last6 == -1) continue;


				// ��֤��ָ��ģʽ
				const cs_insn* push_r14 = &insn[last6];
				const cs_insn* sub_rsp_0x8 = &insn[last5];
				const cs_insn* mov_mrsp_rsp = &insn[last4];
				const cs_insn* pop_r14 = &insn[last3];
				const cs_insn* add_r14_0x18 = &insn[last2];
				const cs_insn* xchg_mrsp_r14 = &insn[last1];
				const cs_insn* pop_rsp = &insn[i];

				auto mainREG = push_r14->detail->x86.operands[0].reg;

				if (push_r14->id == X86_INS_PUSH &&
					push_r14->detail->x86.operands[0].type == X86_OP_REG &&

					sub_rsp_0x8->id == X86_INS_SUB &&
					sub_rsp_0x8->detail->x86.operands[0].type == X86_OP_REG &&
					sub_rsp_0x8->detail->x86.operands[0].reg == X86_REG_RSP &&
					sub_rsp_0x8->detail->x86.operands[1].type == X86_OP_IMM &&
					sub_rsp_0x8->detail->x86.operands[1].imm == 0x8 &&

					mov_mrsp_rsp->id == X86_INS_MOV &&
					mov_mrsp_rsp->detail->x86.operands[0].type == X86_OP_MEM &&
					mov_mrsp_rsp->detail->x86.operands[0].mem.base == X86_REG_RSP &&
					mov_mrsp_rsp->detail->x86.operands[0].mem.disp == 0 &&
					mov_mrsp_rsp->detail->x86.operands[1].type == X86_OP_REG &&
					mov_mrsp_rsp->detail->x86.operands[1].reg == X86_REG_RSP &&

					pop_r14->id == X86_INS_POP &&
					pop_r14->detail->x86.operands[0].type == X86_OP_REG&&
					pop_r14->detail->x86.operands[0].reg == mainREG&&

					add_r14_0x18->id == X86_INS_ADD&&
					add_r14_0x18->detail->x86.operands[0].type == X86_OP_REG&&
					add_r14_0x18->detail->x86.operands[0].reg == mainREG&&
					add_r14_0x18->detail->x86.operands[1].type == X86_OP_IMM&&
					add_r14_0x18->detail->x86.operands[1].imm == 0x18 &&

					xchg_mrsp_r14->id == X86_INS_XCHG&&
					xchg_mrsp_r14->detail->x86.operands[0].type == X86_OP_MEM&&
					xchg_mrsp_r14->detail->x86.operands[0].mem.base == X86_REG_RSP&&
					xchg_mrsp_r14->detail->x86.operands[0].mem.disp == 0 &&
					xchg_mrsp_r14->detail->x86.operands[1].type == X86_OP_REG&&
					xchg_mrsp_r14->detail->x86.operands[1].reg == mainREG&&
					pop_rsp->id == X86_INS_POP&&
					pop_rsp->detail->x86.operands[0].type == X86_OP_REG&&
					pop_rsp->detail->x86.operands[0].reg == X86_REG_RSP)
				{
					// ���ԭָ��
					DbgFunctions()->AssembleAtEx(push_r14->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(sub_rsp_0x8->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(mov_mrsp_rsp->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(pop_r14->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(add_r14_0x18->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(xchg_mrsp_r14->address, "NOP", 0, true);
					DbgFunctions()->AssembleAtEx(pop_rsp->address, "NOP", 0, true);


					// ���� XCHG [RSP], reg
					Environment env;
					env.setArch(Arch::kX64);
					CodeHolder code;
					code.init(env);
					x86::Assembler a(&code);
					a.add(rsp, 0x8);

					PBYTE tCode = new BYTE[code.codeSize()];
					code.copyFlattenedData(tCode, code.codeSize());
					DbgFunctions()->MemPatch(push_r14->address, tCode, code.codeSize());
					delete[] tCode;
					code.reset();


					modified = true;
					break;
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

	//����Ƿ�Ϊһ��ָ��
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

		//���û���κ�Clean�ˣ��˳���ѭ��
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
			int res = MessageBoxA(hwndDlg, "��ǰ����Ĵ�����࣬�������������ܻῨ�����Ƿ�ֹͣ��", "����", MB_YESNO | MB_ICONASTERISK);
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