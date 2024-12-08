/*
   Source for x86 emulator IdaPro plugin
   File: memmgr.cpp
   Copyright (c) 2004-2010, Chris Eagle
   
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option) 
   any later version.
   
   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for 
   more details.
   
   You should have received a copy of the GNU General Public License along with 
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple 
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#define NO_OBSOLETE_FUNCS

#include <ida.hpp>
#include <idp.hpp>
#include <segregs.hpp>
#include <segment.hpp>

#include "memmgr.h"
#include "sdk_versions.h"

//lifted from intel.hpp
#define R_fs 33

#if IDA_SDK_VERSION < 500
#define SEGDEL_KEEP 0
#define SEGDEL_SILENT 1
#endif

#if IDA_SDK_VERSION < 530
#define SEGMOD_SILENT 0
#define SEGMOD_KEEP 0
#else
#define SEGDEL_KEEP SEGMOD_KEEP
#define SEGDEL_SILENT SEGMOD_SILENT
#endif


#define SEG_RESERVE 200

static bool haveTEB = false;
static sel_t tebSel = 0;

void createNewSegment(const char *name, unsigned int base, unsigned int size) {
//msg("createNewSegment: %s\n", name);
   //create the new segment
   segment_t s;
   memset(&s, 0, sizeof(s));
   if (strcmp(name, ".teb") == 0) {
      haveTEB = true;
      tebSel = s.sel = allocate_selector(base >> 4);
#if IDA_SDK_VERSION >= 650
      set_default_sreg_value(NULL, R_fs, s.sel);
#else
      SetDefaultRegisterValue(NULL, R_fs, s.sel);
#endif
   }
   s.start_ea = base;
   s.end_ea = base + size;
   s.align = saRelPara;
   s.comb = scPub;
   s.perm = SEGPERM_WRITE | SEGPERM_READ | SEGPERM_EXEC;
   s.bitness = 1;   //== 32
   s.type = SEG_CODE;
   s.color = DEFCOLOR;
   
//   if (add_segm_ex(&s, name, "DATA", ADDSEG_QUIET | ADDSEG_NOSREG)) {
   if (add_segm_ex(&s, name, "CODE", ADDSEG_QUIET | ADDSEG_NOSREG)) {
      //zero out the newly created segment
      ea_t ea;
      for (ea = s.start_ea; ea < (s.end_ea - 4); ea += 4) {
         patch_dword(ea, 0);
      }
      while (ea < s.end_ea) {
         patch_dword(ea++, 0);
      }
      if (haveTEB) {
#if IDA_SDK_VERSION >= 650
         set_default_sreg_value(&s, R_fs, tebSel);
#else
         SetDefaultRegisterValue(&s, R_fs, tebSel);
#endif
      }
   }
}

segment_t *next_seg(ea_t addr) {
#if IDA_SDK_VERSION >= 530
   return get_next_seg(addr);
#else
   int snum = segs.get_next_area(addr);
   if (snum == -1) {
      return NULL;
   }
   else {
      return getnseg(snum);
   }
#endif
}

/*
static const char memmgr_node_name[] = "$ X86emu memory manager";

//The IDA database node identifier into which the plug-in will
//store its state information when the database is saved.
static netnode memmgr_node(x86emu_node_name);

MemMgr::MemMgr() {
   if (netnode_exist(memmgr_node)) {
   }
   else {
      memmgr_node.create(memmgr_node_name);
   }
}
*/

void MemMgr::reserve(unsigned int addr, unsigned int size) {
   segment_t *s = getseg(addr);
   if (s) {
      size = (size + 0xFFF) & 0xFFFFF000;
      unsigned int end = addr + size;
      if (end > s->end_ea) {
         segment_t *n = next_seg(addr);
         if (n) {
            if (n->start_ea <= end) {
               //no room so fail
               return;
            }
         }
         else {
            if (end < s->start_ea) {
               //end wrapped around so fail
               return;
            }
         }
         netnode segnode(s->start_ea);
         segnode.altset(SEG_RESERVE, end, 'Z');
      }
   }
}

unsigned int MemMgr::mapFixed(unsigned int addr, unsigned int size, unsigned int /*prot*/, unsigned int flags, const char *name) {
   if (addr == 0 || (flags & MM_MAP_FIXED) == 0) {
      return (unsigned int)BADADDR;
   }
   unsigned int end = addr + size;
   segment_t *s = getseg(addr);
   segment_t *n = next_seg(addr);

   while (n && end >= n->end_ea) {
      //range completely consumes next segment
      del_segm(n->start_ea, SEGDEL_KEEP | SEGDEL_SILENT);
      n = next_seg(addr);
   }
   if (n && end > n->start_ea) {
      //range partly overlaps next segment
      set_segm_start(n->start_ea, end, SEGMOD_SILENT);
   }

   if (s) {
      if (s->start_ea < addr) {
         //may need to split segment
         //addr == s->start_ea
         if (end >= s->end_ea) {
            //new extends beyond end of s
            set_segm_end(s->start_ea, addr, SEGMOD_SILENT);
         }
         else {
            //old completely overlaps new
         }
      }
      else {
         //addr == s->start_ea
         if (end >= s->end_ea) {
            //new completely overlaps s
            del_segm(s->start_ea, SEGDEL_KEEP | SEGDEL_SILENT);
         }
         else {
            //need to move start_ea
            set_segm_start(s->start_ea, end, SEGMOD_SILENT);
         }
      }
   }
   
   unsigned int suffix = (addr >> 12) & 0xFFFFF;
   if (name == NULL) {
      char segName[64];
      ::qsnprintf(segName, sizeof(segName), "mmap_%05x", suffix);
      createNewSegment(segName, addr, size);
   }
   else {
      createNewSegment(name, addr, size);
   }
   return addr;
}

unsigned int MemMgr::mmap(unsigned int addr, unsigned int size, unsigned int prot, unsigned int flags, const char *name) {
   if (flags & MM_MAP_FIXED) {
      return mapFixed(addr, size, prot, flags, name);
   }
   if (addr == 0) {
      addr = (unsigned int)kernel_node.altval(OS_MIN_ADDR);
//      addr = inf.minEA;
   }
   while (1) {
      segment_t *s = getseg(addr);
      if (s == NULL) {            
         segment_t *n = next_seg(addr);
         unsigned int avail = 0;
         if (n) {
            avail = (unsigned int)n->start_ea - addr;
         }
         else {
            avail = 0 - addr;
         }
         if (avail >= size) {
            unsigned int suffix = (addr >> 12) & 0xFFFFF;
            if (name == NULL) {
               char segName[64];
               ::qsnprintf(segName, sizeof(segName), "mmap_%05x", suffix);
               createNewSegment(segName, addr, size);
            }
            else {
               createNewSegment(name, addr, size);
            }
            return addr;
         }
         if (n == NULL) {
            return (unsigned int)BADADDR;
         }
         s = n;
      }
      addr = (s->end_ea + 0xFFF) & 0xFFFFF000;
   }
}

unsigned int MemMgr::munmap(unsigned int addr, unsigned int size) {
   segment_t *s = getseg(addr);
   size = (size + 0xFFF) & 0xFFFFF000;
   unsigned int end = addr + size;
   if (s) {
      if (end >= s->end_ea) {
         del_segm(addr, SEGDEL_KEEP);
      }
      else {
         set_segm_start(addr, end, SEGMOD_KEEP);
      }
      return 0;
   }
   return 0xFFFFFFFF;
}

