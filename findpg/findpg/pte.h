//
// This module implements page table related definitions.
//
#pragma once

// C/C++ standard headers
// Other external headers
// Windows headers
#include <Windows.h>

// Original headers

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

static auto PXE_BASE = 0xFFFFF6FB7DBED000UI64;
static auto PPE_BASE = 0xFFFFF6FB7DA00000UI64;
static auto PDE_BASE = 0xFFFFF6FB40000000UI64;
static auto PTE_BASE = 0xFFFFF68000000000UI64;

static const auto PXE_TOP = 0xFFFFF6FB7DBEDFFFUI64;
static const auto PPE_TOP = 0xFFFFF6FB7DBFFFFFUI64;
static const auto PDE_TOP = 0xFFFFF6FB7FFFFFFFUI64;
static const auto PTE_TOP = 0xFFFFF6FFFFFFFFFFUI64;

static const auto PTI_SHIFT = 12;
static const auto PDI_SHIFT = 21;
static const auto PPI_SHIFT = 30;
static const auto PXI_SHIFT = 39;

__forceinline static void PteInitialize(ULONG_PTR PteBase) {
  PTE_BASE = PteBase;
  PDE_BASE = PTE_BASE + ((PTE_BASE & 0xffffffffffff) >> 9);
  PPE_BASE = PTE_BASE + ((PDE_BASE & 0xffffffffffff) >> 9);
  PXE_BASE = PTE_BASE + ((PPE_BASE & 0xffffffffffff) >> 9);
}

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

#pragma warning(disable : 4214)
typedef struct _MMPTE_HARDWARE64 {
  ULONGLONG Valid : 1;
  ULONGLONG Dirty1 : 1;
  ULONGLONG Owner : 1;
  ULONGLONG WriteThrough : 1;
  ULONGLONG CacheDisable : 1;
  ULONGLONG Accessed : 1;
  ULONGLONG Dirty : 1;
  ULONGLONG LargePage : 1;
  ULONGLONG Global : 1;
  ULONGLONG CopyOnWrite : 1;
  ULONGLONG Unused : 1;
  ULONGLONG Write : 1;
  ULONGLONG PageFrameNumber : 36;
  ULONGLONG reserved1 : 4;
  ULONGLONG SoftwareWsIndex : 11;
  ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, *PMMPTE_HARDWARE64;

typedef struct _MMPTE {
  union {
    ULONG_PTR Long;
    MMPTE_HARDWARE64 Hard;
  } u;
} MMPTE;
typedef MMPTE* PMMPTE;
#pragma warning(default : 4214)

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#define PAGE_SHIFT 12L

#ifndef PTE_SHIFT
#define PTE_SHIFT 3
#endif
#ifndef PTI_SHIFT
#define PTI_SHIFT 12
#endif
#ifndef PDI_SHIFT
#define PDI_SHIFT 21
#endif
#ifndef PPI_SHIFT
#define PPI_SHIFT 30
#endif
#ifndef PXI_SHIFT
#define PXI_SHIFT 39
#endif

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define MiGetPxeOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PXI_SHIFT) & PXI_MASK))

#define MiGetPxeAddress(va) ((PMMPTE)PXE_BASE + MiGetPxeOffset(va))

#define MiGetPpeAddress(va)                                          \
  ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) \
             << PTE_SHIFT) +                                         \
            PPE_BASE))

#define MiGetPdeAddress(va)                                          \
  ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) \
             << PTE_SHIFT) +                                         \
            PDE_BASE))

#define MiGetPteAddress(va)                                          \
  ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) \
             << PTE_SHIFT) +                                         \
            PTE_BASE))

#define VA_SHIFT (63 - 47)  // address sign extend shift count

#define MiGetVirtualAddressMappedByPte(PTE)                      \
  ((PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - PTE_BASE)               \
                      << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> \
           VA_SHIFT))
