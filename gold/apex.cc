//===---------------------------------------------------------------------===//
// Copyright (C) 2015 Freescale Semiconductor Inc. All rights reserved.
// Copyright (C) 2016 NXP
//
// SPDX-License-Identifier: BSD-3-Clause
//===---------------------------------------------------------------------===//
//
// Apex target for gold linker
//
//===---------------------------------------------------------------------===//

#include "gold.h"
#include "elfcpp.h"
#include "dwarf.h"
#include "parameters.h"
#include "reloc.h"
#include "apex.h"
#include "object.h"
#include "symtab.h"
#include "layout.h"
#include "output.h"
#include "copy-relocs.h"
#include "target.h"
#include "target-reloc.h"
#include "target-select.h"
#include "errors.h"
#include "gc.h"

namespace
{

using namespace gold;

template<int size, bool big_endian>
class Apex_output_section_tctmemtab;

template<int size, bool big_endian>
class Target_apex : public Sized_target<size, big_endian>
{
public:
  typedef
  Output_data_reloc<elfcpp::SHT_RELA, true /*dynamic*/, size, big_endian> Reloc_section;
  typedef typename elfcpp::Elf_types<size>::Elf_Addr Address;
  typedef typename elfcpp::Elf_types<size>::Elf_Swxword Signed_address;
  static const Address invalid_address = static_cast<Address>(0) - 1;
  
  Target_apex()
    : Sized_target<size, big_endian>(&apex_info),
      copy_relocs_(elfcpp::R_APEX_COPY)
  {}

  // Scan the relocations to look for symbol adjustments.
  void
  gc_process_relocs(Symbol_table* symtab,
                    Layout* layout,
                    Sized_relobj_file<size, big_endian>* object,
                    unsigned int data_shndx,
                    unsigned int sh_type,
                    const unsigned char* prelocs,
                    size_t reloc_count,
                    Output_section* output_section,
                    bool needs_special_offset_handling,
                    size_t local_symbol_count,
                    const unsigned char* plocal_symbols);

  // Scan the relocations to look for symbol adjustments.
  void
  scan_relocs(Symbol_table* symtab,
              Layout* layout,
              Sized_relobj_file<size, big_endian>* object,
              unsigned int data_shndx,
              unsigned int sh_type,
              const unsigned char* prelocs,
              size_t reloc_count,
              Output_section* output_section,
              bool needs_special_offset_handling,
              size_t local_symbol_count,
              const unsigned char* plocal_symbols);

  // Relocate a section.
  void
  relocate_section(const Relocate_info<size, big_endian>*,
                   unsigned int sh_type,
                   const unsigned char* prelocs,
                   size_t reloc_count,
                   Output_section* output_section,
                   bool needs_special_offset_handling,
                   unsigned char* view,
                   Address view_address,
                   section_size_type view_size,
                   const Reloc_symbol_changes*);

  // Scan the relocs during a relocatable link.
  void
  scan_relocatable_relocs(Symbol_table* symtab,
                          Layout* layout,
                          Sized_relobj_file<size, big_endian>* object,
                          unsigned int data_shndx,
                          unsigned int sh_type,
                          const unsigned char* prelocs,
                          size_t reloc_count,
                          Output_section* output_section,
                          bool needs_special_offset_handling,
                          size_t local_symbol_count,
                          const unsigned char* plocal_symbols,
                          Relocatable_relocs*);

  // Relocate a section during a relocatable link.
  void
  relocate_relocs(
      const Relocate_info<size, big_endian>*,
      unsigned int sh_type,
      const unsigned char* prelocs,
      size_t reloc_count,
      Output_section* output_section,
      typename elfcpp::Elf_types<size>::Elf_Off offset_in_output_section,
      const Relocatable_relocs*,
      unsigned char* view,
      typename elfcpp::Elf_types<size>::Elf_Addr view_address,
      section_size_type view_size,
      unsigned char* reloc_view,
      section_size_type reloc_view_size);

  // define Apex specific symbols
  //void
  //do_define_standard_symbols(Symbol_table*, Layout*);

  bool
  do_should_include_section(elfcpp::Elf_Word sh_type) const
  // skip tctmemtab as we will create base on output segments.
  {
    if (sh_type != elfcpp::SHT_LOPROC + 0x123456)
      return true;
    return false;
  }

  // Finalize the sections.
  void
  do_finalize_sections(Layout*, const Input_objects*, Symbol_table*);

protected:
  // Make an output section.
  Output_section*
  do_make_output_section(const char* name, elfcpp::Elf_Word type,
                         elfcpp::Elf_Xword flags)
    {
      if (type == elfcpp::SHT_LOPROC + 0x123456 /*.tctmemtab*/)
        return new Apex_output_section_tctmemtab<size, big_endian>(name, type,
                                                                   flags, this);
      else
        return new Output_section(name, type, flags);
    }

private:
  // Info  // The class which implements relocation.
  class Relocate
  {
   public:
    Relocate()
    { }

    ~Relocate()
    {
    }

    // Do a relocation.  Return false if the caller should not issue
    // any warnings about this relocation.
    inline bool
    relocate(const Relocate_info<size, big_endian>*, Target_apex*,
             Output_section*,
             size_t relnum, const elfcpp::Rela<size, big_endian>&,
             unsigned int r_type, const Sized_symbol<size>*,
             const Symbol_value<size>*,
             unsigned char*, typename elfcpp::Elf_types<size>::Elf_Addr,
             section_size_type);
  };

  class Relocatable_size_for_reloc
  {
   public:
    unsigned int
    get_size_for_reloc(unsigned int, Relobj*)
    {
      // We are always SHT_RELA, so we should never get here.
      gold_unreachable();
      return 0;
    }
  };

  // The class which scans relocations.
  class Scan
  {
  public:
    Scan()
    { }

    inline void
    local(Symbol_table* symtab, Layout* layout, Target_apex* target,
          Sized_relobj_file<size, big_endian>* object,
          unsigned int data_shndx,
          Output_section* output_section,
          const elfcpp::Rela<size, big_endian>& reloc, unsigned int r_type,
          const elfcpp::Sym<size, big_endian>& lsym,
          bool is_discarded);

    inline void
    global(Symbol_table* symtab, Layout* layout, Target_apex* target,
           Sized_relobj_file<size, big_endian>* object,
           unsigned int data_shndx,
           Output_section* output_section,
           const elfcpp::Rela<size, big_endian>& reloc, unsigned int r_type,
           Symbol* gsym);

    inline bool
    local_reloc_may_be_function_pointer(Symbol_table* symtab, Layout* layout,
                            Target_apex* target,
                            Sized_relobj_file<size, big_endian>* object,
                            unsigned int data_shndx,
                            Output_section* output_section,
                            const elfcpp::Rela<size, big_endian>& reloc,
                            unsigned int r_type,
                            const elfcpp::Sym<size, big_endian>& lsym);

    inline bool
    global_reloc_may_be_function_pointer(Symbol_table* symtab, Layout* layout,
                            Target_apex* target,
                            Sized_relobj_file<size, big_endian>* object,
                            unsigned int data_shndx,
                            Output_section* output_section,
                            const elfcpp::Rela<size, big_endian>& reloc,
                            unsigned int r_type,
                            Symbol* gsym);

  private:
    //static void
    //unsupported_reloc_local(Sized_relobj_file<size, big_endian>*,
    //                        unsigned int r_type);

    //static void
    //unsupported_reloc_global(Sized_relobj_file<size, big_endian>*,
    //                         unsigned int r_type, Symbol*);
  };

  // general Target structure.
  static Target::Target_info apex_info;

  // Relocs saved to avoid a COPY reloc.
  Copy_relocs<elfcpp::SHT_RELA, size, big_endian> copy_relocs_;

};

// Handles Apex .tctmemtab output section.

template<int size, bool big_endian>
class Apex_output_section_tctmemtab : public Output_section
{
  typedef typename elfcpp::Swap<size, big_endian>::Valtype Valtype;

 public:
  Apex_output_section_tctmemtab(const char* name, elfcpp::Elf_Word type,
                              elfcpp::Elf_Xword flags,
                              Target_apex<size, big_endian>* target)
    : Output_section(name, type, flags), target_(target)
  { }

  // Downcast a base pointer to a Apex_output_section_tctmemtab pointer.
  static Apex_output_section_tctmemtab<size, big_endian>*
  as_apex_output_section_tctmemtab(Output_section* os)
  { return static_cast<Apex_output_section_tctmemtab<size, big_endian>*>(os); }

  // add a {segment, strtab offset} pair to tctmemtab section.
  void
  add_seg_str(unsigned int seg, unsigned int str_offset)
  {
    std::pair<unsigned int, unsigned int> p(seg, str_offset);
    this->seg_str_.push_back(p);
  }

 protected:
  // Set the final data size.
  void
  set_final_data_size()
  { this->set_data_size(seg_str_.size() * sizeof(int) * 2); }

  // Write out tctmemtab section.
  void
  do_write(Output_file* of);

 private:
  Target_apex<size, big_endian>* target_;

  // list of {segment,strtab offset} pair
  std::vector<std::pair<unsigned int, unsigned int> > seg_str_;

};

template<int size, bool big_endian>
class Apex_relocate_functions
{
public:
  enum Overflow_check
  {
    CHECK_NONE,
    CHECK_SIGNED,
    CHECK_UNSIGNED
  };

  enum Status
  {
    STATUS_OK,
    STATUS_OVERFLOW
  };

private:
  typedef Apex_relocate_functions<size, big_endian> This;
  typedef typename elfcpp::Elf_types<size>::Elf_Addr Address;

  template<int valsize>
  static inline bool
  has_overflow_signed(Address value)
  {
    // limit = 1 << (valsize - 1) without shift count exceeding size of type
    Address limit = static_cast<Address>(1) << ((valsize - 1) >> 1);
    limit <<= ((valsize - 1) >> 1);
    limit <<= ((valsize - 1) - 2 * ((valsize - 1) >> 1));
    return value + limit > (limit << 1) - 1;
  }

  template<int valsize>
  static inline bool
  has_overflow_unsigned(Address value)
  {
    Address limit = static_cast<Address>(1) << ((valsize - 1) >> 1);
    limit <<= ((valsize - 1) >> 1);
    limit <<= ((valsize - 1) - 2 * ((valsize - 1) >> 1));
    return value > (limit << 1) - 1;
  }

  template<int valsize>
  static inline Status
  overflowed(Address value, Overflow_check overflow)
  {
    if (overflow == CHECK_SIGNED)
      {
        if (has_overflow_signed<valsize>(value))
          return STATUS_OVERFLOW;
      }
    else if (overflow == CHECK_UNSIGNED)
      {
        if (has_overflow_unsigned<valsize>(value))
          return STATUS_OVERFLOW;
      }
    return STATUS_OK;
  }

  // Do a simple RELA relocation
  template<int fieldsize, int valsize>
  static inline void
  rela(unsigned char* view,
       const Sized_relobj_file<size, big_endian>* object,
       const Symbol_value<size>* psymval,
       typename elfcpp::Swap<size, big_endian>::Valtype addend,
       elfcpp::Elf_Xword bitmask
       /*Overflow_check overflow*/)
  {
    typedef typename elfcpp::Swap<fieldsize, big_endian>::Valtype Valtype;
    Valtype* wv = reinterpret_cast<Valtype*>(view);
    Valtype val = elfcpp::Swap<fieldsize, big_endian>::readval(wv);
    Valtype reloc = psymval->value(object, addend);

    val &= ~bitmask;
    reloc &= bitmask;

    elfcpp::Swap<fieldsize, big_endian>::writeval(wv, val | (reloc));
    //return overflowed<valsize>(value, overflow);
  }

  template<int fieldsize>
  static inline void
  abs32_swap(unsigned char* view,
       const Sized_relobj_file<size, big_endian>* object,
       const Symbol_value<size>* psymval,
       typename elfcpp::Swap<size, big_endian>::Valtype addend
       /*Overflow_check overflow*/)
  {
    // reverse the template parameter big_endian as apex data is in little endian
    typedef typename elfcpp::Swap<fieldsize, !big_endian>::Valtype Valtype;
    Valtype* wv = reinterpret_cast<Valtype*>(view);
    Valtype val = elfcpp::Swap<fieldsize, !big_endian>::readval(wv);
    Valtype reloc = psymval->value(object, addend);

    elfcpp::Swap<fieldsize, !big_endian>::writeval(wv, val | (reloc));
    //return overflowed<valsize>(value, overflow);
  }

  template<int fieldsize>
  static inline void
  abs32(unsigned char* view,
       const Sized_relobj_file<size, big_endian>* object,
       const Symbol_value<size>* psymval,
       typename elfcpp::Swap<size, big_endian>::Valtype addend
       /*Overflow_check overflow*/)
  {
    typedef typename elfcpp::Swap<fieldsize, big_endian>::Valtype Valtype;
    Valtype* wv = reinterpret_cast<Valtype*>(view);
    Valtype val = elfcpp::Swap<fieldsize, big_endian>::readval(wv);
    Valtype reloc = psymval->value(object, addend);

    elfcpp::Swap<fieldsize, big_endian>::writeval(wv, val | (reloc));
  }


  // pc-relative branch in word offset minus various delay slots
  template<int valsize>
  static inline void
  pcrela(unsigned char* view,
         const Sized_relobj_file<size, big_endian>* object,
         const Symbol_value<size>* psymval,
         typename elfcpp::Swap<size, big_endian>::Valtype addend,
         typename elfcpp::Elf_types<size>::Elf_Addr address,
         unsigned minus,
         elfcpp::Elf_Xword bitmask)

  {
    typedef typename elfcpp::Swap<valsize, big_endian>::Valtype Valtype;
    Valtype* wv = reinterpret_cast<Valtype*>(view);
    Valtype val = elfcpp::Swap<valsize, big_endian>::readval(wv);
    // distance unit is words
    Valtype reloc = (psymval->value(object, addend) - address - minus*4) / 4;

    val &= ~bitmask;
    reloc &= bitmask;

    elfcpp::Swap<valsize, big_endian>::writeval(wv, val | (reloc));
  }

public:
   // R_APEX_198: (Symbol + Addend) s64
  static inline void
  addr32(unsigned char* view,
       const Sized_relobj_file<size, big_endian>* object,
       const Symbol_value<size>* psymval,
       typename elfcpp::Swap<size, big_endian>::Valtype addend)
  { This::template rela<64,32>(view, object, psymval, addend, 0xffffffff); }

   // R_APEX_237 : (Symbol + Addend) s32 data relocation in little endian
  static inline void
  d_addr32(unsigned char* view,
       const Sized_relobj_file<size, big_endian>* object,
       const Symbol_value<size>* psymval,
       typename elfcpp::Swap<size, big_endian>::Valtype addend,
       bool swap)
  { 
    if (swap)
      This::template abs32_swap<32>(view, object, psymval, addend); 
    else
      This::template abs32<32>(view, object, psymval, addend); 
  }

   // R_APEX_201: (Symbol + Addend) u15
  static inline void
  addr15(unsigned char* view,
       const Sized_relobj_file<size, big_endian>* object,
       const Symbol_value<size>* psymval,
       typename elfcpp::Swap<size, big_endian>::Valtype addend)
  { This::template rela<32,15>(view, object, psymval, addend, 0x7fff); }

  // pc-relative branch in word offset minus various delay slots
  static inline void
  pc_addr25(unsigned char* view,
       const Sized_relobj_file<size, big_endian>* object,
       const Symbol_value<size>* psymval,
       typename elfcpp::Swap<size, big_endian>::Valtype addend,
       typename elfcpp::Elf_types<size>::Elf_Addr address,
       unsigned minus)
  { This::template pcrela<32>(view, object, psymval, addend, address, minus, 0x1ffffffUL); }

  static inline void
  pc_addr16(unsigned char* view,
       const Sized_relobj_file<size, big_endian>* object,
       const Symbol_value<size>* psymval,
       typename elfcpp::Swap<size, big_endian>::Valtype addend,
       typename elfcpp::Elf_types<size>::Elf_Addr address,
       unsigned minus)
  { This::template pcrela<32>(view, object, psymval, addend, address, minus, 0xffffUL); }

};

// Apex_output_section_tctmemtab do_write method

template<int size, bool big_endian>
void
Apex_output_section_tctmemtab<size, big_endian>::do_write(Output_file* of)
{
  off_t offset = this->offset();
  off_t data_size = this->data_size();

  unsigned char* view = of->get_output_view(offset, data_size);
  unsigned char* word = view;

  for (unsigned int i = 0; i < this->seg_str_.size(); ++i) {
    elfcpp::Swap<size, big_endian>::writeval(word, this->seg_str_[i].first);
    elfcpp::Swap<size, big_endian>::writeval(word + 4, this->seg_str_[i].second);
    word += 8;
  }

  of->write_output_view(offset, data_size, view);
}

template<int size, bool big_endian>
void
Target_apex<size, big_endian>::gc_process_relocs(Symbol_table* symtab,
                                  Layout* layout,
                                  Sized_relobj_file<size, big_endian>* object,
                                  unsigned int data_shndx,
                                  unsigned int sh_type,
                                  const unsigned char* prelocs,
                                  size_t reloc_count,
                                  Output_section* output_section,
                                  bool needs_special_offset_handling,
                                  size_t local_symbol_count,
                                  const unsigned char* plocal_symbols)
{
  typedef Target_apex<size, big_endian> Apex;
  typedef typename Target_apex<size, big_endian>::Scan Scan;

  if (sh_type == elfcpp::SHT_REL)
    {
      return;
    }

   gold::gc_process_relocs<size, big_endian,
                           Apex, elfcpp::SHT_RELA, Scan,
      typename Target_apex<size, big_endian>::Relocatable_size_for_reloc>(
          symtab,
          layout,
          this,
          object,
          data_shndx,
          prelocs,
          reloc_count,
          output_section,
          needs_special_offset_handling,
          local_symbol_count,
          plocal_symbols);
}

// Scan relocations for a section.
template<int size, bool big_endian>
void
Target_apex<size, big_endian>::scan_relocs(Symbol_table* symtab,
                                 Layout* layout,
                                 Sized_relobj_file<size, big_endian>* object,
                                 unsigned int data_shndx,
                                 unsigned int sh_type,
                                 const unsigned char* prelocs,
                                 size_t reloc_count,
                                 Output_section* output_section,
                                 bool needs_special_offset_handling,
                                 size_t local_symbol_count,
                                 const unsigned char* plocal_symbols)
{
  typedef Target_apex<size, big_endian> Apex;
  typedef typename Target_apex<size, big_endian>::Scan Scan;

  if (sh_type == elfcpp::SHT_REL)
    {
      gold_error(_("%s: unsupported REL reloc section"),
                 object->name().c_str());
      return;
    }

  gold::scan_relocs<size, big_endian, Apex, elfcpp::SHT_RELA, Scan>(
    symtab,
    layout,
    this,
    object,
    data_shndx,
    prelocs,
    reloc_count,
    output_section,
    needs_special_offset_handling,
    local_symbol_count,
    plocal_symbols);
}

// Relocate section data.
template<int size, bool big_endian>
void
Target_apex<size, big_endian>::relocate_section(
    const Relocate_info<size, big_endian>* relinfo,
    unsigned int sh_type,
    const unsigned char* prelocs,
    size_t reloc_count,
    Output_section* output_section,
    bool needs_special_offset_handling,
    unsigned char* view,
    Address address,
    section_size_type view_size,
    const Reloc_symbol_changes* reloc_symbol_changes)
{
  typedef Target_apex<size, big_endian> Apex;
  typedef typename Target_apex<size, big_endian>::Relocate Apex_relocate;

  gold_assert(sh_type == elfcpp::SHT_RELA);

  gold::relocate_section<size, big_endian, Apex, elfcpp::SHT_RELA,
                         Apex_relocate, gold::Default_comdat_behavior>(
    relinfo,
    this,
    prelocs,
    reloc_count,
    output_section,
    needs_special_offset_handling,
    view,
    address,
    view_size,
    reloc_symbol_changes);
}

// Scan the relocs during a relocatable link.

template<int size, bool big_endian>
void
Target_apex<size, big_endian>::scan_relocatable_relocs(
    Symbol_table* symtab,
    Layout* layout,
    Sized_relobj_file<size, big_endian>* object,
    unsigned int data_shndx,
    unsigned int sh_type,
    const unsigned char* prelocs,
    size_t reloc_count,
    Output_section* output_section,
    bool needs_special_offset_handling,
    size_t local_symbol_count,
    const unsigned char* plocal_symbols,
    Relocatable_relocs* rr)
{
  gold_assert(sh_type == elfcpp::SHT_RELA);

  typedef gold::Default_scan_relocatable_relocs<elfcpp::SHT_RELA,
    Relocatable_size_for_reloc> Scan_relocatable_relocs;

  gold::scan_relocatable_relocs<size, big_endian, elfcpp::SHT_RELA,
      Scan_relocatable_relocs>(
    symtab,
    layout,
    object,
    data_shndx,
    prelocs,
    reloc_count,
    output_section,
    needs_special_offset_handling,
    local_symbol_count,
    plocal_symbols,
    rr);
}

// Relocate a section during a relocatable link.

template<int size, bool big_endian>
void
Target_apex<size, big_endian>::relocate_relocs(
    const Relocate_info<size, big_endian>* relinfo,
    unsigned int sh_type,
    const unsigned char* prelocs,
    size_t reloc_count,
    Output_section* output_section,
    typename elfcpp::Elf_types<size>::Elf_Off offset_in_output_section,
    const Relocatable_relocs* rr,
    unsigned char* view,
    typename elfcpp::Elf_types<size>::Elf_Addr view_address,
    section_size_type view_size,
    unsigned char* reloc_view,
    section_size_type reloc_view_size)
{
  gold_assert(sh_type == elfcpp::SHT_RELA);

  gold::relocate_relocs<size, big_endian, elfcpp::SHT_RELA>(
    relinfo,
    prelocs,
    reloc_count,
    output_section,
    offset_in_output_section,
    rr,
    view,
    view_address,
    view_size,
    reloc_view,
    reloc_view_size);
}

// Finalize the sections.

template<int size, bool big_endian>
void
Target_apex<size, big_endian>::do_finalize_sections(
    Layout* layout,
    const Input_objects*,
    Symbol_table* /*symtab*/)
{
  // create .memstrtab output section and segment
  Stringpool *memstrtab = new Stringpool();
  memstrtab->add("PMh", false, NULL);
  memstrtab->add("DMb", false, NULL);
  memstrtab->add("VMb", false, NULL);
  memstrtab->set_string_offsets();

  Output_data_strtab* memstrtab_data = new Output_data_strtab(memstrtab);
  Output_section* memstrtab_os = 
    layout->add_output_section_data(".memstrtab",
                                    elfcpp::SHT_STRTAB, elfcpp::SHF_ALLOC,
                                    memstrtab_data, ORDER_INVALID,
                                    false);
  memstrtab_os->set_is_unique_segment();
  Output_segment* memstrtab_seg = 
    layout->make_output_segment(elfcpp::PT_LOPROC+0x123457, elfcpp::PF_R);
  memstrtab_seg->add_output_section_to_nonload(memstrtab_os, elfcpp::PF_R);

  
  // Create .tctmemtab section and  segment
  Output_segment* tctmemtab_seg = 
    layout->make_output_segment(elfcpp::PT_LOPROC+0x123456, elfcpp::PF_R);

  Output_data_space* tctmemtab_data = new Output_data_space(4 /*align*/, "** TCTMEMTAB");
  Apex_output_section_tctmemtab<size, big_endian>* tctmemtab_os = 
    Apex_output_section_tctmemtab<size, big_endian>::as_apex_output_section_tctmemtab(
       layout->add_output_section_data(".tctmemtab",
                                       elfcpp::SHT_LOPROC+0x123456, elfcpp::SHF_ALLOC,
                                       tctmemtab_data, ORDER_INVALID,
                                       false));
  tctmemtab_data->set_address(0);
  tctmemtab_os->set_entsize(8);
  // link to .memstrtab
  tctmemtab_os->set_link_section(memstrtab_os);
  tctmemtab_os->set_is_unique_segment();

  unsigned p_idx = 0;
  if (layout->script_options()->saw_sections_clause()) {
    // when using link script, segment are not finalized under late in the relaxation pass,
    // so pre populate tctmemtab according to the default section ordering here.
    tctmemtab_os->add_seg_str(0, 1);
    tctmemtab_os->add_seg_str(1, 5);
    tctmemtab_os->add_seg_str(2, 5);
    tctmemtab_os->add_seg_str(3, 5);
    tctmemtab_os->add_seg_str(4, 5);
  }
  else
  for (Layout::Segment_list::const_iterator p = layout->segment_list().begin();
         p != layout->segment_list().end(); ++p,++p_idx)
    {
      elfcpp::Elf_Word p_flag = (*p)->flags(); 
      elfcpp::Elf_Word p_type = (*p)->type();
      // use fixed str offset in memstrtab
      if ((p_type & elfcpp::PT_LOAD) && 
          (p_flag & elfcpp::PF_X) && (p_flag & elfcpp::PF_R))
        tctmemtab_os->add_seg_str(p_idx, 1);
      else if ((p_type & elfcpp::PT_LOAD) && 
               ((p_flag & elfcpp::PF_W) || (p_flag & elfcpp::PF_R)))
        tctmemtab_os->add_seg_str(p_idx, 5);
      //FIXME : differentiate between dmb vmb segment
    }
  tctmemtab_seg->add_output_section_to_nonload(tctmemtab_os, elfcpp::PF_R);
}

// Perform a relocation.
template<int size, bool big_endian>
inline bool
Target_apex<size, big_endian>::Relocate::relocate(
    const Relocate_info<size, big_endian>* relinfo,
    Target_apex<size, big_endian>* /*target*/,
    Output_section* os,
    size_t relnum,
    const elfcpp::Rela<size, big_endian>& rela,
    unsigned int r_type,
    const Sized_symbol<size>* /*gsym*/,
    const Symbol_value<size>* psymval,
    unsigned char* view,
    typename elfcpp::Elf_types<size>::Elf_Addr address,
    section_size_type)
{
  if (view == NULL)
    return true;

  typedef Apex_relocate_functions<size, big_endian> ApexReloc;

  const Sized_relobj_file<size, big_endian>* object = relinfo->object;
  Address value = 0;
  elfcpp::Elf_Xword addend = rela.get_r_addend();

  switch (r_type)
    {
    case elfcpp::R_APEX_NONE:
      break;
    case elfcpp::R_APEX_198: /*(Symbol + Addend) s64 */
      ApexReloc::addr32(view, object, psymval, addend);
      break;
    case elfcpp::R_APEX_0:   /* synopsys use dwarf relocation type 0, but should relocate like R_APEX_237 */
    case elfcpp::R_APEX_237:  /*(Symbol + Addend) s32 */
      if (strncmp(os->name(), ".debug", 6)==0)
	// debug relocations, don't swap endian
      	ApexReloc::d_addr32(view, object, psymval, addend, false);
      else
	ApexReloc::d_addr32(view, object, psymval, addend, true);
      break;
    case elfcpp::R_APEX_201: /*(Symbol + Addend) u15*/
      ApexReloc::addr15(view, object, psymval, addend);
     break;
    case elfcpp::R_APEX_75:  /*(Symbol + Addend)-PC-1 */
      ApexReloc::pc_addr25(view, object, psymval, addend, address, 1);
      break;
    case elfcpp::R_APEX_69:  /*(Symbol + Addend)-PC-2 */
      ApexReloc::pc_addr16(view, object, psymval, addend, address, 2);
      break;
    case elfcpp::R_APEX_71:  /*(Symbol + Addend)-PC-3 */
      ApexReloc::pc_addr16(view, object, psymval, addend, address, 3);
      break;
    default:
      gold_error_at_location(relinfo, relnum, rela.get_r_offset(),
                             _("unsupported reloc %u"),
                             r_type);
      break;
    }

  return true;
}

// Scan a relocation for a local symbol.
template<int size, bool big_endian>
inline void
Target_apex<size, big_endian>::Scan::local(Symbol_table*,
                                 Layout*,
                                 Target_apex<size, big_endian>*,
                                 Sized_relobj_file<size, big_endian>*,
                                 unsigned int,
                                 Output_section*,
                                 const elfcpp::Rela<size, big_endian>&,
                                 unsigned int,
                                 const elfcpp::Sym<size, big_endian>&,
                                 bool is_discarded)
{
  if (is_discarded)
    return;
  
  // do nothing; only support static link for now
}

// Scan a relocation for a global symbol.
template<int size, bool big_endian>
inline void
Target_apex<size, big_endian>::Scan::global(Symbol_table*,
                            Layout*,
                            Target_apex<size, big_endian>*,
                            Sized_relobj_file<size, big_endian>*,
                            unsigned int,
                            Output_section*,
                            const elfcpp::Rela<size, big_endian>&,
                            unsigned int,
                            Symbol*)
{
}

template<int size, bool big_endian>
inline bool
Target_apex<size, big_endian>::Scan::local_reloc_may_be_function_pointer(
  Symbol_table* ,
  Layout* ,
  Target_apex<size, big_endian>* ,
  Sized_relobj_file<size, big_endian>* ,
  unsigned int ,
  Output_section* ,
  const elfcpp::Rela<size, big_endian>& ,
  unsigned int,
  const elfcpp::Sym<size, big_endian>&)
{
  return false;
}

template<int size, bool big_endian>
inline bool
Target_apex<size, big_endian>::Scan::global_reloc_may_be_function_pointer(
  Symbol_table*,
  Layout* ,
  Target_apex<size, big_endian>* ,
  Sized_relobj_file<size, big_endian>* ,
  unsigned int ,
  Output_section* ,
  const elfcpp::Rela<size, big_endian>& ,
  unsigned int,
  Symbol*)
{
  return false;
}

template<>
Target::Target_info Target_apex<32, true>::apex_info =
{
  32,                   // size
  true,                 // is_big_endian
  elfcpp::EM_NONE,      // machine_code
  false,                // has_make_symbol
  false,                // has_resolve
  false,                // has_code_fill
  true,                 // is_default_stack_executable
  false,                // can_icf_inline_merge_sections
  '\0',                 // wrap_char
  "/usr/lib/ld.so.1",   // dynamic_linker
  0x0,                  // default_text_segment_address
  16,                   // abi_pagesize (overridable by -z max-page-size)
  16,                   // common_pagesize (overridable by -z common-page-size)
  true,                 // isolate_execinstr
  0,                    // rosegment_gap
  elfcpp::SHN_UNDEF,    // small_common_shndx
  elfcpp::SHN_UNDEF,    // large_common_shndx
  0,                    // small_common_section_flags
  0,                    // large_common_section_flags
  NULL,                 // attributes_section
  NULL,                 // attributes_vendor
  "_main_fsl"           // entry_symbol_name
};

template<int size, bool big_endian>
class Target_selector_apex : public Target_selector
{
public:
  Target_selector_apex()
    : Target_selector(elfcpp::EM_NONE /* until APEX has proper e_machine*/,
                      size, big_endian,
                      "elf32-big",
                      "" /* emulation*/) {}

  virtual Target*
  do_instantiate_target()
  { return new Target_apex<size, big_endian>(); }
};

/* elf,txt is big-endian; data is little-endian...*/
Target_selector_apex<32, true> target_selector_apex; 
} // End anonymous namespace
