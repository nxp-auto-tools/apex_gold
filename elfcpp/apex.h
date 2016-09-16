#ifndef ELFCPP_APEX_H
#define ELFCPP_APEX_H

#define R_APEX(I, N, S, D, PCR, E, M) N = I,

namespace elfcpp
{
  enum
  {
    R_APEX_NONE = -1,
// sync with include/llvm/Support/ELFRelocs/APEX.def
#include "APEX.def"
    R_APEX_COPY = 999,
  };
} // End namespace elfcpp

#endif // !defined(ELFCPP_APEX_H)
