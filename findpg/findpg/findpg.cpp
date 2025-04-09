//
// This module implements exported debugger extension commands
//
#include "stdafx.h"

// C/C++ standard headers
// Other external headers
// Windows headers
// Original headers
#include "PoolTagDescription.h"
#include "Progress.h"
#include "pte.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

typedef struct _POOL_TRACKER_BIG_PAGES {
  PVOID Va;
  ULONG Key;
  ULONG PoolType;
  SIZE_T Size;  // InBytes
} POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;
C_ASSERT(sizeof(POOL_TRACKER_BIG_PAGES) == 0x18);

struct RandomnessInfo {
  ULONG NumberOfDistinctiveNumbers;
  ULONG Ramdomness;
};

//----------------------------------------------------------------------------
//
// Base extension class.
// Extensions derive from the provided ExtExtension class.
//
// The standard class name is "Extension".  It can be
// overridden by providing an alternate definition of
// EXT_CLASS before including engextcpp.hpp.
//
//----------------------------------------------------------------------------
class EXT_CLASS : public ExtExtension {
 public:
  virtual HRESULT Initialize();
  EXT_COMMAND_METHOD(findpg);

 private:
  void findpgInternal();

  std::vector<std::tuple<POOL_TRACKER_BIG_PAGES, RandomnessInfo>>
  FindPgPagesFromNonPagedPool();

  std::vector<std::tuple<ULONG64, SIZE_T, RandomnessInfo>>
  FindPgPagesFromIndependentPages();

  std::array<MMPTE, 512> GetPtes(__in ULONG64 PteBase);

  bool IsPatchGuardPageAttribute(__in ULONG64 PageBase);

  bool IsPageValidReadWriteExecutable(__in ULONG64 PteAddr);

  // The number of bytes to examine to calculate the number of distinctive
  // bytes and randomness
  static const auto EXAMINATION_BYTES = 100;

  // It is not a PatchGuard page if the number of distinctive bytes are bigger
  // than this number
  static const auto MAXIMUM_DISTINCTIVE_NUMBER = 5;

  // It is not a PatchGuard page if randomness is smaller than this number
  static const auto MINIMUM_RANDOMNESS = 50;

  // It is not a PatchGuard page if the size of the page is smaller than this
  static const auto MINIMUM_REGION_SIZE = 0x004000;

  // It is not a PatchGuard page if the size of the page is larger than this
  static const auto MAXIMUM_REGION_SIZE = 0xf00000;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

namespace {

ULONG GetNumberOfDistinctiveNumbers(void* Addr, SIZE_T Size);

ULONG GetRandomness(void* Addr, SIZE_T Size);

}  // namespace

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// EXT_DECLARE_GLOBALS must be used to instantiate
// the framework's assumed globals.
EXT_DECLARE_GLOBALS();

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

HRESULT EXT_CLASS::Initialize() {
  // Initialize ExtensionApis to use dprintf and so on
  // when this extension is loaded.
  PDEBUG_CLIENT debugClient = nullptr;
  auto result = DebugCreate(__uuidof(IDebugClient),
                            reinterpret_cast<void**>(&debugClient));
  if (!SUCCEEDED(result)) {
    return result;
  }
  auto debugClientScope = std::experimental::scope_guard(
      [debugClient]() { debugClient->Release(); });

  PDEBUG_CONTROL debugControl = nullptr;
  result = debugClient->QueryInterface(__uuidof(IDebugControl),
                                       reinterpret_cast<void**>(&debugControl));
  if (!SUCCEEDED(result)) {
    return result;
  }
  auto debugControlScope = std::experimental::scope_guard(
      [debugControl]() { debugControl->Release(); });

  ExtensionApis.nSize = sizeof(ExtensionApis);
  result = debugControl->GetWindbgExtensionApis64(&ExtensionApis);
  if (!SUCCEEDED(result)) {
    return result;
  }

  // Display guide messages
  dprintf("Use ");
  debugControl->ControlledOutput(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL,
                                 "<exec cmd=\"!findpg\">!findpg</exec>");
  dprintf(" to find base addresses of the pages allocated for PatchGuard.\n");
  return result;
}

// Exported command !findpg (no options)
EXT_COMMAND(findpg, "Displays base addresses of PatchGuard pages", "") {
  try {
    findpgInternal();
  } catch (std::exception& e) {
    // As an exception string does not appear on Windbg,
    // we need to handle it manually.
    Err("%s\n", e.what());
  }
}

// Does main stuff and throws an exception when
void EXT_CLASS::findpgInternal() {
  Out("Wait until analysis is completed. It typically takes 2-5 minutes.\n");
  Out("Or press Ctrl+Break or [Debug] > [Break] to stop analysis.\n");

  // Collect PatchGuard pages from NonPagedPool and independent pages
  auto foundNonPaged = FindPgPagesFromNonPagedPool();
  Out("Phase 1 analysis has been done.\n");
  auto foundIndependent = FindPgPagesFromIndependentPages();
  Out("Phase 2 analysis has been done.\n");

  // Sort data according to its base addresses
  std::sort(foundNonPaged.begin(), foundNonPaged.end(),
            [](const auto& lhs, const auto& rhs) {
              return std::get<0>(lhs).Va < std::get<0>(rhs).Va;
            });

  std::sort(foundIndependent.begin(), foundIndependent.end(),
            [](const auto& Lhs, const auto& Rhs) {
              return std::get<0>(Lhs) < std::get<0>(Rhs);
            });

  // Display collected data
  PoolTagDescription pooltag(this);
  for (const auto& n : foundNonPaged) {
    const auto description = pooltag.get(std::get<0>(n).Key);
    Out("[BigPagePool] PatchGuard context page base: %y, size: 0x%08x,"
        " Randomness %3d:%3d,%s\n",
        std::get<0>(n).Va, std::get<0>(n).Size,
        std::get<1>(n).NumberOfDistinctiveNumbers, std::get<1>(n).Ramdomness,
        description.c_str());
  }
  for (const auto& n : foundIndependent) {
    Out("[Independent] PatchGuard context page base: %y, Size: 0x%08x,"
        " Randomness %3d:%3d,\n",
        std::get<0>(n), std::get<1>(n),
        std::get<2>(n).NumberOfDistinctiveNumbers, std::get<2>(n).Ramdomness);
  }
}

// Collects PatchGuard pages reside in NonPagedPool
std::vector<std::tuple<POOL_TRACKER_BIG_PAGES, RandomnessInfo>>
EXT_CLASS::FindPgPagesFromNonPagedPool() {
  ULONG64 offset = 0;

  // Read MmNonPagedPoolStart if it is possible. On Windows 8.1, this symbol
  // has been removed and this magic value is used instead.
  ULONG64 mmNonPagedPoolStart = 0xFFFFE00000000000;
  auto result = m_Symbols->GetOffsetByName("nt!MmNonPagedPoolStart", &offset);
  if (SUCCEEDED(result)) {
    result = m_Data->ReadPointersVirtual(1, offset, &mmNonPagedPoolStart);
    if (!SUCCEEDED(result)) {
      throw std::runtime_error("nt!MmNonPagedPoolStart could not be read.");
    }
  }

  // Read PoolBigPageTableSize
  result = m_Symbols->GetOffsetByName("nt!PoolBigPageTableSize", &offset);
  if (!SUCCEEDED(result)) {
    throw std::runtime_error("nt!PoolBigPageTableSize could not be found.");
  }
  SIZE_T poolBigPageTableSize = 0;
  result = m_Data->ReadPointersVirtual(1, offset, &poolBigPageTableSize);
  if (!SUCCEEDED(result)) {
    throw std::runtime_error("nt!PoolBigPageTableSize could not be read.");
  }

  // Read PoolBigPageTable
  result = m_Symbols->GetOffsetByName("nt!PoolBigPageTable", &offset);
  if (!SUCCEEDED(result)) {
    throw std::runtime_error("nt!PoolBigPageTable could not be found.");
  }
  ULONG64 poolBigPageTable = 0;
  result = m_Data->ReadPointersVirtual(1, offset, &poolBigPageTable);
  if (!SUCCEEDED(result)) {
    throw std::runtime_error("nt!PoolBigPageTable could not be read.");
  }

  // Read actual PoolBigPageTable contents
  ULONG readBytes = 0;
  std::vector<POOL_TRACKER_BIG_PAGES> table(poolBigPageTableSize);
  result = m_Data->ReadVirtual(
      poolBigPageTable, table.data(),
      static_cast<ULONG>(table.size() * sizeof(POOL_TRACKER_BIG_PAGES)),
      &readBytes);
  if (!SUCCEEDED(result)) {
    throw std::runtime_error("nt!PoolBigPageTable could not be read.");
  }

  // Walk BigPageTable
  Progress progress(this);
  std::vector<std::tuple<POOL_TRACKER_BIG_PAGES, RandomnessInfo>> found;
  for (SIZE_T i = 0; i < poolBigPageTableSize; ++i) {
    if ((i % 0x1000) == 0) {
      ++progress;
    }

    const auto& entry = table[i];
    auto startAddr = reinterpret_cast<ULONG_PTR>(entry.Va);

    // Ignore unused entries
    if (!startAddr || (startAddr & 1)) {
      continue;
    }

    // Filter by the size of region
    if (MINIMUM_REGION_SIZE > entry.Size || entry.Size > MAXIMUM_REGION_SIZE) {
      continue;
    }

    // Filter by the address
    if (startAddr < mmNonPagedPoolStart) {
      // This assertion seem reasonable but not always be true.
      // assert(entry.PoolType & 1 /*PagedPool*/);
      continue;
    }

    // Filter by the page protection
    if (!IsPatchGuardPageAttribute(startAddr)) {
      continue;
    }

    // Read and check randomness of the contents
    std::array<std::uint8_t, EXAMINATION_BYTES> contents;
    result =
        m_Data->ReadVirtual(startAddr, contents.data(),
                            static_cast<ULONG>(contents.size()), &readBytes);
    if (!SUCCEEDED(result)) {
      continue;
    }
    const auto numberOfDistinctiveNumbers =
        GetNumberOfDistinctiveNumbers(contents.data(), EXAMINATION_BYTES);
    const auto randomness = GetRandomness(contents.data(), EXAMINATION_BYTES);
    if (numberOfDistinctiveNumbers > MAXIMUM_DISTINCTIVE_NUMBER ||
        randomness < MINIMUM_RANDOMNESS) {
      continue;
    }

    // It seems to be a PatchGuard page
    found.emplace_back(entry, RandomnessInfo{
                                  numberOfDistinctiveNumbers,
                                  randomness,
                              });
  }
  return found;
}

// Collects PatchGuard pages reside in independent pages
std::vector<std::tuple<ULONG64, SIZE_T, RandomnessInfo>>
EXT_CLASS::FindPgPagesFromIndependentPages() {
  ULONG64 offset = 0;

  // -- NtBuildNumber
  if (!SUCCEEDED(m_Symbols->GetOffsetByName("nt!NtBuildNumber", &offset)))
    throw std::runtime_error("nt!NtBuildNumber not found.");

  ULONG64 buildNumber = 0;
  if (!SUCCEEDED(m_Data->ReadPointersVirtual(1, offset, &buildNumber)))
    throw std::runtime_error("nt!NtBuildNumber could not be read.");

  // fix for Windows 10 RS4 (Redstone 4)
  if (buildNumber >= 17134) {
    // -- MmPteBase
    if (!SUCCEEDED(m_Symbols->GetOffsetByName("nt!MmPteBase", &offset)))
      throw std::runtime_error("nt!MmPteBase not found.");
    ULONG64 pteBase = 0;
    if (!SUCCEEDED(m_Data->ReadPointersVirtual(1, offset, &pteBase)))
      throw std::runtime_error("nt!MmPteBase could not be read.");

    PteInitialize(pteBase);
  }

  Out("PTE_BASE = 0x%p | PDE_BASE = 0x%p | PPE_BASE = 0x%p | PXE_BASE = 0x%p\n",
      (void*)PTE_BASE, (void*)PDE_BASE, (void*)PPE_BASE, (void*)PXE_BASE);

  // -- MmSystemRangeStart
  if (!SUCCEEDED(m_Symbols->GetOffsetByName("nt!MmSystemRangeStart", &offset)))
    throw std::runtime_error("nt!MmSystemRangeStart not found.");
  ULONG64 mmSystemRangeStart = 0;
  if (!SUCCEEDED(m_Data->ReadPointersVirtual(1, offset, &mmSystemRangeStart)))
    throw std::runtime_error("nt!MmSystemRangeStart could not be read.");

  std::vector<std::tuple<ULONG64, SIZE_T, RandomnessInfo>> found;
  Progress progress(this);

  const auto startPxe = reinterpret_cast<ULONG64>(
      MiGetPxeAddress(reinterpret_cast<void*>(mmSystemRangeStart)));

  const auto pxes = GetPtes(PXE_BASE);
  for (ULONG64 currentPxe = startPxe; currentPxe < PXE_TOP;
       currentPxe += sizeof(MMPTE)) {
    const size_t pxeIndex = (currentPxe - PXE_BASE) / sizeof(MMPTE);
    const auto& pxe = pxes[pxeIndex];
    if (!pxe.u.Hard.Valid)
      continue;

    const ULONG64 startPpe = PPE_BASE + 0x1000 * pxeIndex;
    const auto ppes = GetPtes(startPpe);

    for (ULONG64 currentPpe = startPpe; currentPpe < startPpe + 0x1000;
         currentPpe += sizeof(MMPTE)) {
      const size_t ppeIndex1 = (currentPpe - PPE_BASE) / sizeof(MMPTE);
      const size_t ppeIndex2 = (currentPpe - startPpe) / sizeof(MMPTE);
      const auto& ppe = ppes[ppeIndex2];
      if (!ppe.u.Hard.Valid)
        continue;

      const ULONG64 startPde = PDE_BASE + 0x1000 * ppeIndex1;
      const auto pdes = GetPtes(startPde);

      for (ULONG64 currentPde = startPde; currentPde < startPde + 0x1000;
           currentPde += sizeof(MMPTE)) {
        const size_t pdeIndex1 = (currentPde - PDE_BASE) / sizeof(MMPTE);
        const size_t pdeIndex2 = (currentPde - startPde) / sizeof(MMPTE);
        const auto& pde = pdes[pdeIndex2];
        ++progress;

        if (!pde.u.Hard.Valid || pde.u.Hard.LargePage)
          continue;

        const ULONG64 startPte = PTE_BASE + 0x1000 * pdeIndex1;
        const auto ptes = GetPtes(startPte);

        for (ULONG64 currentPte = startPte; currentPte < startPte + 0x1000;
             currentPte += sizeof(MMPTE)) {
          const size_t pteIndex2 = (currentPte - startPte) / sizeof(MMPTE);
          const auto& pte = ptes[pteIndex2];

          if (!pte.u.Hard.Valid || !pte.u.Hard.Write || pte.u.Hard.NoExecute)
            continue;

          const ULONG64 virtualAddress = reinterpret_cast<ULONG64>(
              MiGetVirtualAddressMappedByPte(currentPte));

          std::array<std::uint8_t, EXAMINATION_BYTES + sizeof(ULONG64)>
              contents{};
          ULONG readBytes = 0;
          if (!SUCCEEDED(m_Data->ReadVirtual(
                  virtualAddress, contents.data(),
                  static_cast<ULONG>(contents.size()), &readBytes))) {
            continue;
          }

          const auto numberOfDistinctiveNumbers = GetNumberOfDistinctiveNumbers(
              contents.data() + sizeof(ULONG64), EXAMINATION_BYTES);
          const auto randomness = GetRandomness(
              contents.data() + sizeof(ULONG64), EXAMINATION_BYTES);

          if (numberOfDistinctiveNumbers > MAXIMUM_DISTINCTIVE_NUMBER ||
              randomness < MINIMUM_RANDOMNESS)
            continue;

          const auto independentPageSize =
              *reinterpret_cast<const ULONG64*>(contents.data());

          if (independentPageSize < MINIMUM_REGION_SIZE ||
              independentPageSize > MAXIMUM_REGION_SIZE)
            continue;

          Out("Found possible PG page at 0x%p size 0x%llX\n",
              (void*)virtualAddress, independentPageSize);

          found.emplace_back(
              virtualAddress, independentPageSize,
              RandomnessInfo{numberOfDistinctiveNumbers, randomness});
        }
      }
    }
  }

  return found;
}

// Returns PTEs in one page
std::array<MMPTE, 512> EXT_CLASS::GetPtes(__in ULONG64 PteBase) {
  ULONG readBytes = 0;
  std::array<MMPTE, 512> ptes;
  auto result = m_Data->ReadVirtual(
      PteBase, ptes.data(), static_cast<ULONG>(ptes.size() * sizeof(MMPTE)),
      &readBytes);
  if (!SUCCEEDED(result)) {
    throw std::runtime_error(
        std::format("The given address {:#X} could not be read. hr = {:#010X}",
                    PteBase, static_cast<DWORD>(result)));
  }
  return ptes;
}

// Returns true when page protection of the given page or a parant page
// of the given page is Valid and Readable/Writable/Executable.
bool EXT_CLASS::IsPatchGuardPageAttribute(__in ULONG64 PageBase) {
  const auto pteAddr = MiGetPteAddress(reinterpret_cast<void*>(PageBase));
  if (IsPageValidReadWriteExecutable(reinterpret_cast<ULONG64>(pteAddr))) {
    return true;
  }
  const auto pdeAddr = MiGetPdeAddress(reinterpret_cast<void*>(PageBase));
  if (IsPageValidReadWriteExecutable(reinterpret_cast<ULONG64>(pdeAddr))) {
    return true;
  }
  return false;
}

// Returns true when page protection of the given page is
// Readable/Writable/Executable.
bool EXT_CLASS::IsPageValidReadWriteExecutable(__in ULONG64 PteAddr) {
  ULONG readBytes = 0;
  MMPTE pte = {};
  auto result = m_Data->ReadVirtual(PteAddr, &pte, sizeof(pte), &readBytes);
  if (!SUCCEEDED(result)) {
    return false;
  }
  return pte.u.Hard.Valid && pte.u.Hard.Write && !pte.u.Hard.NoExecute;
}

namespace {

// Returns the number of 0x00 and 0xff in the given range
ULONG GetNumberOfDistinctiveNumbers(__in void* Addr, __in SIZE_T Size) {
  const auto p = static_cast<UCHAR*>(Addr);
  ULONG count = 0;
  for (SIZE_T i = 0; i < Size; ++i) {
    if (p[i] == 0xff || p[i] == 0x00) {
      count++;
    }
  }
  return count;
}

// Returns the number of unique bytes in the given range.
// For example, it returns 3 for the following bytes
// 00 01 01 02 02 00 02
ULONG GetRandomness(__in void* Addr, __in SIZE_T Size) {
  const auto p = static_cast<UCHAR*>(Addr);
  std::set<UCHAR> dic;
  for (SIZE_T i = 0; i < Size; ++i) {
    dic.insert(p[i]);
  }
  return static_cast<ULONG>(dic.size());
}

}  // namespace
