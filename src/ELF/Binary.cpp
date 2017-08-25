/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <algorithm>
#include <iterator>
#include <numeric>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#else
#define getpagesize() 0x1000
#endif

#include <stdexcept>

#include "easylogging++.h"

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Builder.hpp"

#include "Binary.tcc"

namespace LIEF {
namespace ELF {
Binary::Binary(void)  = default;

Binary::Binary(const std::string& name, ELF_CLASS type) : type_{type} {
  this->name_ = name;
  if (type_ == ELF_CLASS::ELFCLASS32) {
  }
  else if (type_ == ELF_CLASS::ELFCLASS32) {
  }
}


Header& Binary::get_header(void) {
  return const_cast<Header&>(static_cast<const Binary*>(this)->get_header());
}


const Header& Binary::get_header(void) const {
  return this->header_;
}


ELF_CLASS Binary::type(void) const {
  return this->type_;
}

size_t Binary::hash(const std::string& name) {
  if (this->type_ == ELFCLASS32) {
    return hash32(name.c_str());
  } else {
    return hash32(name.c_str());
  }
}

LIEF::sections_t Binary::get_abstract_sections(void) {
  return {std::begin(this->sections_), std::end(this->sections_)};
}


// Sections
// ========

it_sections Binary::get_sections(void) {
  return it_sections{std::ref(this->sections_)};
}


it_const_sections Binary::get_sections(void) const {
  return it_const_sections{std::cref(this->sections_)};
}

// Segments
// ========

it_segments Binary::get_segments(void) {
  return it_segments{std::ref(this->segments_)};
}

it_const_segments Binary::get_segments(void) const {
  return it_const_segments{std::ref(this->segments_)};
}


std::vector<std::string> Binary::get_abstract_exported_functions(void) const {
  std::vector<std::string> result;
  for (const Symbol& symbol : this->get_exported_symbols()) {
    if (symbol.type() == ELF_SYMBOL_TYPES::STT_FUNC) {
      result.push_back(symbol.name());
    }
  }
  return result;
}


std::vector<std::string> Binary::get_abstract_imported_functions(void) const {
  std::vector<std::string> result;
  for (const Symbol& symbol : this->get_imported_symbols()) {
    if (symbol.type() == ELF_SYMBOL_TYPES::STT_FUNC) {
      result.push_back(symbol.name());
    }
  }
  return result;
}


std::vector<std::string> Binary::get_abstract_imported_libraries(void) const {
  std::vector<std::string> result;
  for (const DynamicEntry& entry : this->get_dynamic_entries()) {
    if (dynamic_cast<const DynamicEntryLibrary*>(&entry)) {
      result.push_back(dynamic_cast<const DynamicEntryLibrary*>(&entry)->name());
    }
  }
  return result;
}


// Dynamic Entries
// ===============

it_dynamic_entries Binary::get_dynamic_entries(void) {
  return it_dynamic_entries{std::ref(this->dynamic_entries_)};
}

it_const_dynamic_entries Binary::get_dynamic_entries(void) const {
  return it_const_dynamic_entries{std::cref(this->dynamic_entries_)};
}



// Symbols
// =======

// Statics
// -------

it_symbols Binary::get_static_symbols(void) {
  return this->static_symbols_;
}

it_const_symbols Binary::get_static_symbols(void) const {
  return this->static_symbols_;
}

// Dynamics
// --------

it_symbols Binary::get_dynamic_symbols(void) {
  return this->dynamic_symbols_;
}

it_const_symbols Binary::get_dynamic_symbols(void) const {
  return this->dynamic_symbols_;
}


it_symbols Binary::get_symbols(void) {
  symbols_t symbols;
  symbols.reserve(this->get_dynamic_symbols().size() + this->get_static_symbols().size());
  for (Symbol& s : this->get_dynamic_symbols()) {
    symbols.push_back(&s);
  }

  for (Symbol& s : this->get_static_symbols()) {
    symbols.push_back(&s);
  }

  return it_symbols{symbols};
}

it_const_symbols Binary::get_symbols(void) const {
  symbols_t symbols;

  symbols.reserve(this->get_dynamic_symbols().size() + this->get_static_symbols().size());

  for (const Symbol& s : this->get_dynamic_symbols()) {
    symbols.push_back(const_cast<Symbol*>(&s));
  }

  for (const Symbol& s : this->get_static_symbols()) {
    symbols.push_back(const_cast<Symbol*>(&s));
  }

  return it_const_symbols{symbols};
}

// Exported
// --------

it_exported_symbols Binary::get_exported_symbols(void) {
  return {this->dynamic_symbols_,
    [] (const Symbol* symbol) { return symbol->is_exported(); }
  };
}

it_const_exported_symbols Binary::get_exported_symbols(void) const {
  return {this->dynamic_symbols_,
    [] (const Symbol* symbol) { return symbol->is_exported(); }
  };
}



// Imported
// --------

it_imported_symbols Binary::get_imported_symbols(void) {
  return filter_iterator<symbols_t>{std::ref(this->dynamic_symbols_),
    [] (const Symbol* symbol) { return symbol->is_imported(); }
  };
}

it_const_imported_symbols Binary::get_imported_symbols(void) const {
  return const_filter_iterator<symbols_t>{std::cref(this->dynamic_symbols_),
    [] (const Symbol* symbol) { return symbol->is_imported(); }
  };
}


// Symbol version
// --------------

it_symbols_version Binary::get_symbols_version(void) {
  return it_symbols_version{std::ref(this->symbol_version_table_)};
}

it_const_symbols_version Binary::get_symbols_version(void) const {
  return it_const_symbols_version{std::cref(this->symbol_version_table_)};
}

// Symbol version definition
// -------------------------

it_symbols_version_definition Binary::get_symbols_version_definition(void) {
  return it_symbols_version_definition{std::ref(this->symbol_version_definition_)};
}

it_const_symbols_version_definition Binary::get_symbols_version_definition(void) const {
  return it_const_symbols_version_definition{std::cref(this->symbol_version_definition_)};
}

// Symbol version requirement
// --------------------------

it_symbols_version_requirement Binary::get_symbols_version_requirement(void) {
  return it_symbols_version_requirement{std::ref(this->symbol_version_requirements_)};
}

it_const_symbols_version_requirement Binary::get_symbols_version_requirement(void) const {
  return it_const_symbols_version_requirement{std::cref(this->symbol_version_requirements_)};
}

void Binary::remove_symbol(const std::string& name) {
  this->remove_static_symbol(name);
  this->remove_dynamic_symbol(name);
}


void Binary::remove_static_symbol(const std::string& name) {
  auto&& it_symbol = std::find_if(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      [&name] (const Symbol* symbol) {
        return symbol != nullptr and symbol->name() == name;
      });

  if (it_symbol == std::end(this->static_symbols_)) {
    throw not_found("Can't find '" + name + "'");
  }

  this->remove_static_symbol(*it_symbol);

}

void Binary::remove_static_symbol(Symbol* symbol) {
  auto&& it_symbol = std::find_if(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      [&symbol] (const Symbol* sym) {
        return sym != nullptr and sym != nullptr and *symbol == *sym;
      });

  if (it_symbol == std::end(this->static_symbols_)) {
    throw not_found("Can't find '" + symbol->name() + "'");
  }

  delete *it_symbol;
  this->dynamic_symbols_.erase(it_symbol);

  symbol = nullptr;

}



void Binary::remove_dynamic_symbol(const std::string& name) {
  auto&& it_symbol = std::find_if(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&name] (const Symbol* symbol) {
        return symbol != nullptr and symbol->name() == name;
      });

  if (it_symbol == std::end(this->dynamic_symbols_)) {
    throw not_found("Can't find '" + name + "'");
  }

  this->remove_dynamic_symbol(*it_symbol);

}

void Binary::remove_dynamic_symbol(Symbol* symbol) {
  auto&& it_symbol = std::find_if(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&symbol] (const Symbol* sym) {
        return symbol != nullptr and sym != nullptr and *symbol == *sym;
      });

  if (it_symbol == std::end(this->dynamic_symbols_)) {
    throw not_found("Can't find '" + symbol->name() + "'");
  }


  // Update relocations
  auto&& it_relocation = std::find_if(
      std::begin(this->relocations_),
      std::end(this->relocations_),
      [&symbol] (const Relocation* relocation) {
        return relocation != nullptr and
        relocation->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT and
        relocation->has_symbol() and
        relocation->symbol() == *symbol;
      });

  if (it_relocation != std::end(this->relocations_)) {
    delete *it_relocation;
    this->relocations_.erase(it_relocation);
  } else {
  }


  it_relocation = std::find_if(
      std::begin(this->relocations_),
      std::end(this->relocations_),
      [&symbol] (const Relocation* relocation) {
        return relocation != nullptr and
        relocation->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC and
        relocation->has_symbol() and
        relocation->symbol() == *symbol;
      });

  if (it_relocation != std::end(this->relocations_)) {
    delete *it_relocation;
    this->relocations_.erase(it_relocation);
  }

  // Update symbol versions
  if (symbol->has_version()) {
    this->symbol_version_table_.erase(
        std::remove(
          std::begin(this->symbol_version_table_),
          std::end(this->symbol_version_table_),
          symbol->symbol_version_));
    delete symbol->symbol_version_;

  }

  delete *it_symbol;
  this->dynamic_symbols_.erase(it_symbol);

  symbol = nullptr;

}


// Relocations
// ===========

// Dynamics
// --------

it_dynamic_relocations Binary::get_dynamic_relocations(void) {
  return filter_iterator<relocations_t>{std::ref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC;
    }
  };

}

it_const_dynamic_relocations Binary::get_dynamic_relocations(void) const {
  return const_filter_iterator<const relocations_t>{std::cref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_DYNAMIC;
    }
  };

}

// plt/got
// -------
it_pltgot_relocations Binary::get_pltgot_relocations(void) {
  return filter_iterator<relocations_t>{std::ref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT;
    }
  };
}

it_const_pltgot_relocations Binary::get_pltgot_relocations(void) const {
  return const_filter_iterator<const relocations_t>{std::cref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_PLTGOT;
    }
  };
}


// objects
// -------
it_object_relocations Binary::get_object_relocations(void) {
  return filter_iterator<relocations_t>{std::ref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT;
    }
  };
}

it_const_object_relocations Binary::get_object_relocations(void) const {
  return const_filter_iterator<const relocations_t>{std::cref(this->relocations_),
    [] (const Relocation* reloc) {
      return reloc->purpose() == RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT;
    }
  };
}

// All relocations
// ---------------
it_relocations Binary::get_relocations(void) {
  return this->relocations_;
}

it_const_relocations Binary::get_relocations(void) const {
  return this->relocations_;
}

LIEF::symbols_t Binary::get_abstract_symbols(void) {
  LIEF::symbols_t symbols;
  symbols.reserve(this->dynamic_symbols_.size() + this->static_symbols_.size());
  std::copy(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      std::back_inserter(symbols));

  std::copy(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      std::back_inserter(symbols));
  return symbols;

}


Section& Binary::get_section(const std::string& name) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->get_section(name));
}

const Section& Binary::get_section(const std::string& name) const {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&name] (const Section* section)
      {
        return section != nullptr and section->name() == name;
      });

  if (it_section == std::end(this->sections_)) {
    throw not_found("Unable to find section '" + name + "'");
  }
  return **it_section;

}

Section& Binary::get_text_section(void) {
  return this->get_section(".text");
}


Section& Binary::get_dynamic_section(void) {

  auto&& it_dynamic_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [] (const Section* section) {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_DYNAMIC;
      });

  if (it_dynamic_section == std::end(this->sections_)) {
    throw not_found("Unable to find the SHT_DYNAMIC section");
  }

  return **it_dynamic_section;

}

Section& Binary::get_hash_section(void) {
  auto&& it_hash_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [] (const Section* section) {
        return section != nullptr and (section->type() == ELF_SECTION_TYPES::SHT_HASH or
            section->type() == ELF_SECTION_TYPES::SHT_GNU_HASH);
      });

  if (it_hash_section == std::end(this->sections_)) {
    throw not_found("Unable to find the SHT_HASH / SHT_GNU_HASH section");
  }

  return **it_hash_section;

}

Section& Binary::get_static_symbols_section(void) {

  auto&& it_symtab_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [] (const Section* section)
      {
        return section != nullptr and section->type() == ELF_SECTION_TYPES::SHT_SYMTAB;
      });


  if (it_symtab_section == std::end(this->sections_)) {
    throw not_found("Unable to find a SHT_SYMTAB section");
  }

  return **it_symtab_section;
}

uint64_t Binary::get_imagebase(void) const {
  uint64_t imagebase = static_cast<uint64_t>(-1);
  for (const Segment* segment : this->segments_) {
    if (segment != nullptr and segment->type() == SEGMENT_TYPES::PT_LOAD) {
      imagebase = std::min(imagebase, segment->virtual_address() - segment->file_offset());
    }
  }
  return imagebase;
}

uint64_t Binary::get_virtual_size(void) const {
  uint64_t virtual_size = 0;
  for (const Segment* segment : this->segments_) {
    if (segment != nullptr and segment->type() == SEGMENT_TYPES::PT_LOAD) {
      virtual_size = std::max(virtual_size, segment->virtual_address() + segment->virtual_size());
    }
  }
  virtual_size = align(virtual_size, static_cast<uint64_t>(getpagesize()));
  return virtual_size - this->get_imagebase();
}


std::vector<uint8_t> Binary::raw(void) {
  Builder builder{this};
  builder.build();
  return builder.get_build();
}


uint64_t Binary::get_function_address(const std::string& func_name) const {
  try {
    return this->get_function_address(func_name, true);
  } catch(const not_found&) {
    return this->get_function_address(func_name, false);
  } catch(const not_supported&) {
    return this->get_function_address(func_name, false);
  }
}

uint64_t Binary::get_function_address(const std::string& func_name, bool demangled) const {
  auto&& it_symbol = std::find_if(
      std::begin(this->static_symbols_),
      std::end(this->static_symbols_),
      [&func_name, &demangled] (const Symbol* symbol) {
        if (symbol == nullptr) {
          return false;
        }

        if (demangled) {
          return (symbol->demangled_name() == func_name and
                  symbol->type() == ELF_SYMBOL_TYPES::STT_FUNC);
        } else {
          return (symbol->name() == func_name and
                  symbol->type() == ELF_SYMBOL_TYPES::STT_FUNC);
        }
      });

  if (it_symbol == std::end(this->static_symbols_)) {
    throw not_found("Can't find the function name");
  } else {
    return (*it_symbol)->value();
  }
}

Section& Binary::add_section(const Section& section, bool loaded) {
  Section* new_section = new Section{section};
  uint32_t new_section_index = 0;

  if (loaded) {
    // Find the first PROGBITS section
    // TODO: may not be the first one with if sections not sorted !!!!!
    auto&& it_progbit_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [] (const Section* s)
      {
        return s->type() == ELF_SECTION_TYPES::SHT_PROGBITS;
      });

    if (it_progbit_section == std::end(this->sections_)) {
      throw not_found("Can't find a SHT_PROGBITS section.");
    }
    VLOG(VDEBUG) << "First SHT_PROGBITS: " << **it_progbit_section << std::endl;

    new_section_index = static_cast<uint32_t>(std::distance(std::begin(this->sections_), it_progbit_section));
    const Section* progbit_section = *it_progbit_section;
    new_section->file_offset(progbit_section->file_offset());
  } else {
    uint64_t new_section_offset = 0;
    for (const Section* s : this->sections_) {
      if (s == nullptr) {
        continue;
      }

      if (s->type() != ELF_SECTION_TYPES::SHT_NOBITS) { // to avoid .bss section
        new_section_offset = std::max<uint64_t>(s->file_offset() + s->size(), new_section_offset);
      }
    }
    new_section_index = static_cast<uint32_t>(this->sections_.size());
    new_section->file_offset(new_section_offset);
  }

  VLOG(VDEBUG) << "New section offset: 0x" << std::hex << new_section->file_offset();
  VLOG(VDEBUG) << "New section index: " << std::dec << new_section_index;

  // The section size must align on a pagesize
  const uint64_t psize        = static_cast<uint64_t>(getpagesize());
  const uint64_t section_size = new_section->size() + (psize - (new_section->size() % psize));
  new_section->size(section_size);

  if (loaded) {
    // Patch segments
    for (Segment* segment : this->segments_) {
      if (segment->type() == SEGMENT_TYPES::PT_LOAD) {

        //segment->add(ELF_SEGMENT_FLAGS::PF_W);
        segment->virtual_size(segment->virtual_size()         + new_section->size());
        segment->virtual_address(segment->virtual_address()   - new_section->size());

        segment->physical_size(segment->physical_size()       + new_section->size());
        segment->physical_address(segment->physical_address() - new_section->size());

        DataHandler::Node& node = this->datahandler_->find(
            segment->file_offset(),
            segment->physical_size(),
            false, DataHandler::Node::SEGMENT);
        node.size(node.size() +  new_section->size());
      } else if (segment->type() == SEGMENT_TYPES::PT_PHDR) {
        segment->virtual_address(segment->virtual_address()   - new_section->size());
        segment->physical_address(segment->physical_address() - new_section->size());
        //after PHT
        new_section->virtual_address(segment->virtual_address() + segment->virtual_size());
      } else {
        DataHandler::Node& node = this->datahandler_->find(
            segment->file_offset(),
            segment->physical_size(),
            false,
            DataHandler::Node::SEGMENT);
        this->datahandler_->move(node, node.offset() + new_section->size());
        segment->file_offset(segment->file_offset() + new_section->size());
      }
    }
  }
  // Patch header
  this->get_header().numberof_sections(this->get_header().numberof_sections() + 1);

  if (new_section->file_offset() <= this->header_.section_headers_offset()) {
    this->header_.section_headers_offset(this->header_.section_headers_offset() + new_section->size());
  }


  new_section->datahandler_ = this->datahandler_;

  for (Section* s : this->sections_) {
    if (s->file_offset() >= new_section->file_offset()) {
      DataHandler::Node& node = this->datahandler_->find(
            s->file_offset(),
            s->size(),
            false,
            DataHandler::Node::SECTION);
      this->datahandler_->move(node, node.offset() + new_section->size());
      s->file_offset(s->file_offset() + new_section->size());
    }
  }

  std::vector<uint8_t> section_content = section.content();
  this->datahandler_->make_hole(new_section->file_offset(), new_section->size());
  section_content.resize(new_section->size(), 0);
  new_section->content(section_content);

  // increment the string section index if we add the section before it.
  // When we use INSERT and not PUSH_BACK
  if (new_section_index < this->get_header().section_name_table_idx() and not loaded) {
    this->get_header().section_name_table_idx(this->get_header().section_name_table_idx() + 1);
  }

  //this->sections_.insert(itProgbitSection, newSectionPtr);
  //TODO: use insert instead of push_back but probleme with readelf
  this->sections_.push_back(new_section);
  return *(this->sections_.back());

}



bool Binary::is_pie(void) const {
  auto&& it_segment = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* entry) {
        return entry != nullptr and entry->type() == SEGMENT_TYPES::PT_INTERP;
      });

  if (it_segment != std::end(this->segments_) and
      this->get_header().file_type() == E_TYPE::ET_DYN) {
    return true;
  } else {
    return false;
  }
}


bool Binary::has_nx(void) const {
  auto&& it_stack = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (Segment* segment) {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_GNU_STACK;
      });
  if (it_stack == std::end(this->segments_)) {
    return false;
  }

  return not (*it_stack)->has(ELF_SEGMENT_FLAGS::PF_X);

}

Segment& Binary::add_segment(const Segment& segment, uint64_t base, bool force_note) {
  uint64_t new_base = base;

  if (base == 0) {
    if (this->type() == ELF_CLASS::ELFCLASS32) {
      new_base = round<uint32_t>(std::accumulate(
            std::begin(this->segments_),
            std::end(this->segments_), 0llu,
            [] (uint32_t address, const Segment* segment) {
              return std::max<uint32_t>(segment->virtual_address() + segment->virtual_size(), address);
            }));
    }

    if (this->type() == ELF_CLASS::ELFCLASS64) {
      new_base = round<uint64_t>(std::accumulate(
            std::begin(this->segments_),
            std::end(this->segments_), 0llu,
            [] (uint64_t address, const Segment* segment) {
              return std::max<uint64_t>(segment->virtual_address() + segment->virtual_size(), address);
            }));
    }
  }

  switch(this->get_header().file_type()) {
    case E_TYPE::ET_EXEC:
      {
        if (force_note) {
          return this->add_segment<E_TYPE::ET_EXEC, true>(segment, new_base);
        } else {
          return this->add_segment<E_TYPE::ET_EXEC, false>(segment, new_base);
        }
        break;
      }

    case E_TYPE::ET_DYN:
      {
        return this->add_segment<E_TYPE::ET_DYN>(segment, new_base);
        break;
      }

    default:
      {
        //LOG(WARNING) << "Relocations for architecture " << to_string(this->get_header().file_type()) << " is not supported!";
        throw not_implemented(std::string("Adding segment for ") + to_string(this->get_header().file_type()) + " is not implemented");
      }
  }

}

// Patch
// =====

void Binary::patch_address(uint64_t address, const std::vector<uint8_t>& patch_value) {
  // Find the segment associated with the virtual address
  Segment& segment_topatch = this->segment_from_virtual_address(address);
  const uint64_t offset = address - segment_topatch.virtual_address();
  std::vector<uint8_t> content = segment_topatch.content();
  if ((offset + patch_value.size()) > content.size()) {
    content.resize(offset + patch_value.size());
  }
  std::copy(
      std::begin(patch_value),
      std::end(patch_value),
      content.data() + offset);
  segment_topatch.content(content);
}


void Binary::patch_address(uint64_t address, uint64_t patch_value, size_t size) {
  if (size > sizeof(patch_value)) {
    throw std::runtime_error("Invalid size (" + std::to_string(size) + ")");
  }

  Segment& segment_topatch = this->segment_from_virtual_address(address);
  const uint64_t offset = address - segment_topatch.virtual_address();
  std::vector<uint8_t> content = segment_topatch.content();

  std::copy(
      reinterpret_cast<uint8_t*>(&patch_value),
      reinterpret_cast<uint8_t*>(&patch_value) + size,
      content.data() + offset);
  segment_topatch.content(content);
}



void Binary::patch_pltgot(const Symbol& symbol, uint64_t address) {
  it_pltgot_relocations pltgot_relocations = this->get_pltgot_relocations();
  auto&& it_relocation = std::find_if(
      std::begin(pltgot_relocations),
      std::end(pltgot_relocations),
      [&symbol] (const Relocation& relocation) {
        return relocation.has_symbol() and relocation.symbol() == symbol;
      });

  if (it_relocation == std::end(pltgot_relocations)) {
    throw not_found("Unable to find the relocation associated with symbol '" + symbol.name() + "'");
  }

  uint64_t got_address = (*it_relocation).address();
  this->patch_address(got_address, address, sizeof(uint64_t));
  //(*it_relocation)->address(0);
  //delete *it_relocation;
  //this->pltgot_relocations_.erase(it_relocation);
}

void Binary::patch_pltgot(const std::string& symbol_name, uint64_t address) {
  std::for_each(
      std::begin(this->dynamic_symbols_),
      std::end(this->dynamic_symbols_),
      [&symbol_name, address, this] (const Symbol* s) {
        if (s->name() == symbol_name) {
          this->patch_pltgot(*s, address);
        }
      });
}


const Segment& Binary::segment_from_virtual_address(uint64_t address) const {
  auto&& it_segment = std::find_if(
      this->segments_.cbegin(),
      this->segments_.cend(),
      [&address] (const Segment* segment) {
        if (segment == nullptr) {
          return false;
        }
        return ((segment->virtual_address() <= address) and
            (segment->virtual_address() + segment->virtual_size()) >= address);
      });

  if (it_segment == this->segments_.cend()) {
    std::stringstream adr_str;
    adr_str << "0x" << std::hex << address;
    throw not_found("Unable to find the segment associated with the address: " + adr_str.str());
  }

  return **it_segment;

}

Segment& Binary::segment_from_virtual_address(uint64_t address) {
  return const_cast<Segment&>(static_cast<const Binary*>(this)->segment_from_virtual_address(address));
}


const Segment& Binary::segment_from_offset(uint64_t offset) const {
  auto&& it_segment = std::find_if(
      this->segments_.cbegin(),
      this->segments_.cend(),
      [&offset] (const Segment* segment) {
        if (segment == nullptr) {
          return false;
        }

        return ((segment->file_offset() <= offset) and
            (segment->file_offset() + segment->physical_size()) > offset);
      });

  if (it_segment == this->segments_.cend()) {
    throw not_found("Unable to find the segment");
  }

  return **it_segment;
}

Segment& Binary::segment_from_offset(uint64_t offset) {
  return const_cast<Segment&>(static_cast<const Binary*>(this)->segment_from_offset(offset));
}

void Binary::remove_section(const std::string& name) {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&name] (const Section* section) {
        return section != nullptr and section->name() == name;
      });

  if (it_section == std::end(this->sections_)) {
    throw not_found("Unable to find the section");
  }

  Section* section = *it_section;

  // First clear the content
  section->content(std::vector<uint8_t>(section->size(), 0));

  // Patch header
  this->get_header().numberof_sections(this->get_header().numberof_sections() - 1);

  // Remove from sections vector
  this->sections_.erase(it_section);
}

bool Binary::has_section(const std::string& name) const {
  return std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&name] (const Section* section) {
        return section != nullptr and section->name() == name;
      }) != std::end(this->sections_);
}

void Binary::strip(void) {
  this->static_symbols_ = {};
}


Symbol& Binary::add_static_symbol(const Symbol& symbol) {
  this->static_symbols_.push_back(new Symbol{symbol});
  return *(this->static_symbols_.back());
}

uint64_t Binary::virtual_address_to_offset(uint64_t virtual_address) const {
  auto&& it_segment = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [virtual_address] (const Segment* segment)
      {
        if (segment == nullptr) {
          return false;
        }
        return (
          segment->type() == SEGMENT_TYPES::PT_LOAD and
          segment->virtual_address() <= virtual_address and
          segment->virtual_address() + segment->virtual_size() >= virtual_address
          );
      });

  if (it_segment == std::end(this->segments_)) {
    VLOG(VDEBUG) << "Address: 0x" << std::hex << virtual_address;
    throw conversion_error("Invalid virtual address");
  }
  uint64_t baseAddress = (*it_segment)->virtual_address() - (*it_segment)->file_offset();
  uint64_t offset      = virtual_address - baseAddress;

  return offset;

}


bool Binary::has_interpreter(void) const {
  auto&& it_segment_interp = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* segment)
      {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_INTERP;
      });

  return it_segment_interp != std::end(this->segments_);
}

std::string Binary::get_interpreter(void) const {
  auto&& it_segment_interp = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* segment)
      {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_INTERP;
      });

  if (it_segment_interp == std::end(this->segments_)) {
    throw not_found("PT_INTERP not found");
  }

  const std::vector<uint8_t>& content = (*it_segment_interp)->content();
  return reinterpret_cast<const char*>(content.data());
}

void Binary::write(const std::string& filename) {
  Builder builder{this};
  builder.build();
  builder.write(filename);
}


uint64_t Binary::entrypoint() const {
  return this->get_header().entrypoint();
}


const Section& Binary::section_from_offset(uint64_t offset) const {
  auto&& it_section = std::find_if(
      this->sections_.cbegin(),
      this->sections_.cend(),
      [&offset] (const Section* section) {
        if (section == nullptr) {
          return false;
        }
        return ((section->offset() <= offset) and
            (section->offset() + section->size()) > offset);
      });

  if (it_section == this->sections_.cend()) {
    throw not_found("Unable to find the section");
  }

  return **it_section;
}

Section& Binary::section_from_offset(uint64_t offset) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->section_from_offset(offset));
}



const Section& Binary::section_from_virtual_address(uint64_t address) const {
  auto&& it_section = std::find_if(
      this->sections_.cbegin(),
      this->sections_.cend(),
      [&address] (const Section* section) {
        if (section == nullptr) {
          return false;
        }
        return ((section->virtual_address() <= address) and
            (section->virtual_address() + section->size()) > address);
      });

  if (it_section == this->sections_.cend()) {
    throw not_found("Unable to find the section");
  }

  return **it_section;
}

Section& Binary::section_from_virtual_address(uint64_t address) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->section_from_virtual_address(address));
}

std::vector<uint8_t> Binary::get_content_from_virtual_address(uint64_t virtual_address, uint64_t size) const {
  const Segment& segment = this->segment_from_virtual_address(virtual_address);
  const std::vector<uint8_t>& content = segment.content();
  const uint64_t offset = virtual_address - segment.virtual_address();
  uint64_t checked_size = size;
  if ((offset + checked_size) > content.size()) {
    checked_size = checked_size - (offset + checked_size - content.size());
  }

  return {content.data() + offset, content.data() + offset + checked_size};
}


const DynamicEntry& Binary::dynamic_entry_from_tag(DYNAMIC_TAGS tag) const {

  auto&& it_entry = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [tag] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == tag;
      });
  if (it_entry == std::end(this->dynamic_entries_)) {
    throw not_found("Unable to find the dynamic entry with tag '" + std::string(to_string(tag)) + "'.");
  }
  return **it_entry;
}

DynamicEntry& Binary::dynamic_entry_from_tag(DYNAMIC_TAGS tag) {
  return const_cast<DynamicEntry&>(static_cast<const Binary*>(this)->dynamic_entry_from_tag(tag));
}


bool Binary::has_dynamic_entry(DYNAMIC_TAGS tag) const {
  auto&& it_entry = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [tag] (const DynamicEntry* entry)
      {
        return entry != nullptr and entry->tag() == tag;
      });

  if (it_entry == std::end(this->dynamic_entries_)) {
    return false;
  }
  return true;
}


void Binary::permute_dynamic_symbols(const std::vector<size_t>& permutation) {
  std::set<size_t> done;
  for (size_t i = 0; i < permutation.size(); ++i) {
    if (permutation[i] == i or done.count(permutation[i]) > 0 or done.count(permutation[i]) > 0) {
      continue;
    }

    if (this->dynamic_symbols_[i]->has_version() and this->dynamic_symbols_[permutation[i]]->has_version()) {
      std::swap(this->symbol_version_table_[i], this->symbol_version_table_[permutation[i]]);
      std::swap(this->dynamic_symbols_[i], this->dynamic_symbols_[permutation[i]]);
      done.insert(permutation[i]);
      done.insert(i);
    } else if (not this->dynamic_symbols_[i]->has_version() and not this->dynamic_symbols_[permutation[i]]->has_version()) {
      std::swap(this->dynamic_symbols_[i], this->dynamic_symbols_[permutation[i]]);
      done.insert(permutation[i]);
      done.insert(i);
    } else {
      LOG(ERROR) << "Can't apply permutation at index " << std::dec << i;
    }

  }
}

LIEF::Header Binary::get_abstract_header(void) const {
  LIEF::Header header;
  const std::pair<ARCHITECTURES, std::set<MODES>>& am = this->get_header().abstract_architecture();
  header.architecture(am.first);
  header.modes(am.second);
  header.entrypoint(this->get_header().entrypoint());

  if (this->get_header().file_type() == E_TYPE::ET_DYN and this->has_interpreter()) { // PIE
    header.object_type(OBJECT_TYPES::TYPE_EXECUTABLE);
  } else {
    header.object_type(this->get_header().abstract_object_type());
  }

  header.endianness(this->get_header().abstract_endianness());

  return header;
}


bool Binary::has_notes(void) const {
  auto&& it_segment_note = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* segment) {
        return segment != nullptr and segment->type() == SEGMENT_TYPES::PT_NOTE;
      });

  return it_segment_note != std::end(this->segments_) and this->notes().size() > 0;
}

it_const_notes Binary::notes(void) const {
  return {this->notes_};
}

it_notes Binary::notes(void) {
  return {this->notes_};
}


void Binary::accept(LIEF::Visitor&) const {
}

bool Binary::use_gnu_hash(void) const {

  auto&& it_gnu_hash = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_GNU_HASH;
      });

  return it_gnu_hash != std::end(this->dynamic_entries_);
}


const GnuHash& Binary::get_gnu_hash(void) const {
  if (this->use_gnu_hash()) {
    return this->gnu_hash_;
  } else {
    throw not_found("GNU hash is not used!");
  }
}


bool Binary::use_sysv_hash(void) const {
  auto&& it_sysv_hash = std::find_if(
      std::begin(this->dynamic_entries_),
      std::end(this->dynamic_entries_),
      [] (const DynamicEntry* entry) {
        return entry != nullptr and entry->tag() == DYNAMIC_TAGS::DT_HASH;
      });

  return it_sysv_hash != std::end(this->dynamic_entries_);
}

const SysvHash& Binary::get_sysv_hash(void) const {
  if (this->use_sysv_hash()) {
    return this->sysv_hash_;
  } else {
    throw not_found("SYSV hash is not used!");
  }
}


void Binary::shift_sections(uint64_t from, uint64_t shift) {
  VLOG(VDEBUG) << "Shift Sections";
  /// TODO: ADDRESS ?????????? ///////////
  for (Section* section : this->sections_) {
    // Use >= if you don't want to **include** data in the section
    VLOG(VDEBUG) << "[BEFORE] " << *section;
    if (section->file_offset() >= from) {
      DataHandler::Node& node = this->datahandler_->find(
          section->file_offset(),
          section->size(),
          false,
          DataHandler::Node::SECTION);
      this->datahandler_->move(node, node.offset() + shift);
      section->file_offset(section->file_offset() + shift);
      section->virtual_address(section->virtual_address() + shift);
    }
    VLOG(VDEBUG) << "[AFTER] " << *section << std::endl;
  }

}

void Binary::shift_segments(uint64_t from, uint64_t shift) {

  VLOG(VDEBUG) << "Shift Segments";

  for (Segment* segment : this->segments_) {
    VLOG(VDEBUG) << "[BEFORE] " << *segment;
    if (segment->file_offset() >= from) {
      DataHandler::Node& node = this->datahandler_->find(
          segment->file_offset(),
          segment->physical_size(),
          false,
          DataHandler::Node::SEGMENT);
      this->datahandler_->move(node, node.offset() + shift);

      segment->file_offset(segment->file_offset() + shift);
      segment->virtual_address(segment->virtual_address() + shift);
      segment->physical_address(segment->physical_address() + shift);
    }
    VLOG(VDEBUG) << "[AFTER] " << *segment << std::endl;

    // Patch segment size for the segment which contains the new section
    //if ((segment->file_offset() + segment->physical_size()) >= sectionOffset and
    //    sectionOffset >= segment->file_offset()) {

    //  DataHandler::Node& node = this->datahandler_->find(
    //      segment->file_offset(),
    //      segment->physical_size(),
    //      false,
    //      DataHandler::Node::SEGMENT);
    //  node.size(node.size() + new_section_size);

    //  segment->virtual_size(segment->virtual_size()   + new_section_size);
    //  segment->physical_size(segment->physical_size() + new_section_size);
    //  uint64_t relativeOffset = sectionOffset - segment->file_offset();
    //  std::vector<uint8_t> segmentData = segment->content();
    //  std::copy(
    //      std::begin(content),
    //      std::end(content),
    //      segmentData.data() + relativeOffset);
    //  segment->content(segmentData);

    //}
  }
}

void Binary::shift_dynamic_entries(uint64_t from, uint64_t shift) {
  VLOG(VDEBUG) << "Shift Dynamic entries";

  for (DynamicEntry* entry : this->dynamic_entries_) {
    VLOG(VDEBUG) << "[BEFORE] " << *entry;
    switch (entry->tag()) {
      case DYNAMIC_TAGS::DT_PLTGOT:
      case DYNAMIC_TAGS::DT_HASH:
      case DYNAMIC_TAGS::DT_GNU_HASH:
      case DYNAMIC_TAGS::DT_STRTAB:
      case DYNAMIC_TAGS::DT_SYMTAB:
      case DYNAMIC_TAGS::DT_RELA:
      case DYNAMIC_TAGS::DT_REL:
      case DYNAMIC_TAGS::DT_JMPREL:
      case DYNAMIC_TAGS::DT_INIT:
      case DYNAMIC_TAGS::DT_FINI:
      case DYNAMIC_TAGS::DT_VERSYM:
      case DYNAMIC_TAGS::DT_VERDEF:
      case DYNAMIC_TAGS::DT_VERNEED:
        {

          if (entry->value() >= from) {
            entry->value(entry->value() + shift);
          }
          break;
        }

      case DYNAMIC_TAGS::DT_INIT_ARRAY:
      case DYNAMIC_TAGS::DT_FINI_ARRAY:
      case DYNAMIC_TAGS::DT_PREINIT_ARRAY:
        {
          std::vector<uint64_t>& array = entry->array();
          for (uint64_t& address : array) {
            if (address >= from) {
              address += shift;
            }
          }

          if (entry->value() >= from) {
            entry->value(entry->value() + shift);
          }
          break;
        }

      default:
        {
          VLOG(VDEBUG) << to_string(entry->tag()) << " not patched";
        }
    }
    VLOG(VDEBUG) << "[AFTER] " << *entry << std::endl;
  }
}


void Binary::shift_symbols(uint64_t from, uint64_t shift) {
  VLOG(VDEBUG) << "Shift Symbols";
  for (Symbol& symbol : this->get_symbols()) {
    VLOG(VDEBUG) << "[BEFORE] " << symbol;
    if (symbol.value() >= from) {
      symbol.value(symbol.value() + shift);
    }
    VLOG(VDEBUG) << "[AFTER] " << symbol << std::endl;
  }
}


void Binary::shift_relocations(uint64_t from, uint64_t shift) {
  const ARCH arch = this->get_header().machine_type();

  VLOG(VDEBUG) << "Shift relocations for architecture: " << to_string(arch);

  switch(arch) {
    case ARCH::EM_ARM:
      {
        this->patch_relocations<ARCH::EM_ARM>(from, shift);
        break;
      }

    case ARCH::EM_AARCH64:
      {
        this->patch_relocations<ARCH::EM_AARCH64>(from, shift);
        break;
      }

    case ARCH::EM_X86_64:
      {
        this->patch_relocations<ARCH::EM_X86_64>(from, shift);
        break;
      }

    case ARCH::EM_386:
      {
        this->patch_relocations<ARCH::EM_386>(from, shift);
        break;
      }

    default:
      {
        LOG(WARNING) << "Relocations for architecture " << to_string(arch) << " is not supported!";
      }
  }
}


std::ostream& Binary::print(std::ostream& os) const {

  os << "Header" << std::endl;
  os << "======" << std::endl;

  os << this->get_header();
  os << std::endl;


  os << "Sections" << std::endl;
  os << "========" << std::endl;
  for (const Section& section : this->get_sections()) {
    os << section << std::endl;
  }
  os << std::endl;


  os << "Segments" << std::endl;
  os << "========" << std::endl;
  for (const Segment& segment : this->get_segments()) {
    os << segment << std::endl;
  }

  os << std::endl;


  os << "Dynamic entries" << std::endl;
  os << "===============" << std::endl;

  for (const DynamicEntry& entry : this->get_dynamic_entries()) {
    os << entry << std::endl;
  }

  os << std::endl;


  os << "Dynamic symbols" << std::endl;
  os << "===============" << std::endl;

  for (const Symbol& symbol : this->get_dynamic_symbols()) {
    os << symbol << std::endl;
  }

  os << std::endl;


  os << "Static symbols" << std::endl;
  os << "==============" << std::endl;

  for (const Symbol& symbol : this->get_static_symbols()) {
    os << symbol << std::endl;
  }

  os << std::endl;


  os << "Symbol versions" << std::endl;
  os << "===============" << std::endl;

  for (const SymbolVersion& sv : this->get_symbols_version()) {
    os << sv << std::endl;
  }

  os << std::endl;


  os << "Symbol versions definition" << std::endl;
  os << "==========================" << std::endl;

  for (const SymbolVersionDefinition& svd : this->get_symbols_version_definition()) {
    os << svd << std::endl;
  }

  os << std::endl;


  os << "Symbol version requirement" << std::endl;
  os << "==========================" << std::endl;

  for (const SymbolVersionRequirement& svr : this->get_symbols_version_requirement()) {
    os << svr << std::endl;
  }

  os << std::endl;


  os << "Dynamic relocations" << std::endl;
  os << "===================" << std::endl;

  for (const Relocation& relocation : this->get_dynamic_relocations()) {
    os << relocation << std::endl;
  }

  os << std::endl;


  os << ".plt.got relocations" << std::endl;
  os << "====================" << std::endl;

  for (const Relocation& relocation : this->get_pltgot_relocations()) {
    os << relocation << std::endl;
  }

  os << std::endl;

  if (this->notes().size() > 0) {
    os << "Notes" << std::endl;
    os << "=====" << std::endl;

    it_const_notes notes = this->notes();
    for (size_t i = 0; i < notes.size(); ++i) {
      std::string title = "Note #" + std::to_string(i);
      os << title << std::endl;
      os << std::string(title.size(), '-') << std::endl;
      os << notes[i] << std::endl;
    }
    os << std::endl;
  }

  os << std::endl;
  if (this->use_gnu_hash()) {
    os << "GNU Hash Table" << std::endl;
    os << "==============" << std::endl;

    os << this->get_gnu_hash() << std::endl;

    os << std::endl;
  }


  if (this->use_sysv_hash()) {
    os << "SYSV Hash Table" << std::endl;
    os << "===============" << std::endl;

    os << this->get_sysv_hash() << std::endl;

    os << std::endl;
  }



  return os;
}



Binary::~Binary(void) {

  for (Relocation* relocation : this->relocations_) {
    delete relocation;
  }

  for (Section* section : this->sections_) {
    delete section;
  }

  for (Segment* segment : this->segments_) {
    delete segment;
  }

  for (DynamicEntry* entry : this->dynamic_entries_) {
    delete entry;
  }

  for (Symbol* symbol : this->dynamic_symbols_) {
    delete symbol;
  }

  for (Symbol* symbol : this->static_symbols_) {
    delete symbol;
  }

  for (SymbolVersion* symbol_version : this->symbol_version_table_) {
    delete symbol_version;
  }

  for (SymbolVersionDefinition* svd : this->symbol_version_definition_) {
    delete svd;
  }

  for (SymbolVersionRequirement* svr : this->symbol_version_requirements_) {
    delete svr;
  }

  delete datahandler_;
}


}
}
