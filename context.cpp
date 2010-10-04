
#include "cpu.h"
#include "context.h"

//Copy current CPU state into CONTEXT structure for Windows Exception Handling
//Note that the global ctx struct is the only place that Debug and Floating
//point registers are currently defined
void regsToContext(Registers *regs, WIN_CONTEXT *ctx) {
   ctx->Dr0 = regs->debug_regs[DR0];
   ctx->Dr1 = regs->debug_regs[DR1];
   ctx->Dr2 = regs->debug_regs[DR2];
   ctx->Dr3 = regs->debug_regs[DR3];
   ctx->Dr6 = regs->debug_regs[DR6];
   ctx->Dr7 = regs->debug_regs[DR7];
   ctx->Eax = regs->general[EAX];
   ctx->Ebx = regs->general[EBX];
   ctx->Ecx = regs->general[ECX];
   ctx->Edx = regs->general[EDX];
   ctx->Edi = regs->general[EDI];
   ctx->Esi = regs->general[ESI];
   ctx->Ebp = regs->general[EBP];
   ctx->Esp = regs->general[ESP];
//   ctx->Eip = eip;
   ctx->Eip = regs->eip;  //use address at which exception occurred
   ctx->EFlags = regs->eflags;
   ctx->SegSs = regs->segReg[SS];
   ctx->SegCs = regs->segReg[CS];
   ctx->SegDs = regs->segReg[DS];
   ctx->SegEs = regs->segReg[ES];
   ctx->SegFs = regs->segReg[FS];
   ctx->SegGs = regs->segReg[GS];
}

//Copy from CONTEXT structure into CPU state for Windows Exception Handling
//Note that the global ctx struct is the only place that Debug and Floating
//point registers are currently defined
void contextToRegs(WIN_CONTEXT *ctx, Registers *regs) {
   regs->debug_regs[DR0] = ctx->Dr0;
   regs->debug_regs[DR1] = ctx->Dr1;
   regs->debug_regs[DR2] = ctx->Dr2;
   regs->debug_regs[DR3] = ctx->Dr3;
   regs->debug_regs[DR6] = ctx->Dr6;
   regs->debug_regs[DR7] = ctx->Dr7;
   regs->general[EAX] = ctx->Eax;
   regs->general[EBX] = ctx->Ebx;
   regs->general[ECX] = ctx->Ecx;
   regs->general[EDX] = ctx->Edx;
   regs->general[EDI] = ctx->Edi;
   regs->general[ESI] = ctx->Esi;
   regs->general[EBP] = ctx->Ebp;
   regs->general[ESP] = ctx->Esp;
   regs->eip = ctx->Eip;
   regs->eflags = ctx->EFlags;
   regs->segReg[SS] = ctx->SegSs;
   regs->segReg[CS] = ctx->SegCs;
   regs->segReg[DS] = ctx->SegDs;
   regs->segReg[ES] = ctx->SegEs;
   regs->segReg[FS] = ctx->SegFs;
   regs->segReg[GS] = ctx->SegGs;
}

void initContext(WIN_CONTEXT *ctx) {
   memset(ctx, 0, sizeof(WIN_CONTEXT));
}

void copyContextToMem(WIN_CONTEXT *ctx, dword addr) {
   byte *ptr = (byte*) ctx;
   for (dword i = 0; i < sizeof(WIN_CONTEXT); i++) {
      writeMem(addr++, *ptr++, SIZE_BYTE);
   }
}
/*
dword pushContext() {
   dword ctx_size = (sizeof(CONTEXT) + 3) & ~3;  //round up to next dword
   dword addr = esp - ctx_size;
   copyContextToMem(addr);
   esp = addr;
   return esp;
}
*/
