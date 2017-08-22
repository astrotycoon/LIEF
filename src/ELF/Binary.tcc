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
#include "easylogging++.h"

namespace LIEF {
namespace ELF {

// ===============
// ARM Relocations
// ===============
template<>
void Binary::patch_relocations<ARCH::EM_ARM>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : this->get_relocations()) {

    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    const RELOC_ARM type = static_cast<RELOC_ARM>(relocation.type());

    switch (type) {
      case RELOC_ARM::R_ARM_JUMP_SLOT:
      case RELOC_ARM::R_ARM_RELATIVE:
      case RELOC_ARM::R_ARM_GLOB_DAT:
      case RELOC_ARM::R_ARM_IRELATIVE:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
    }
  }
}


// ===================
// AARCH64 Relocations
// ===================
template<>
void Binary::patch_relocations<ARCH::EM_AARCH64>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : this->get_relocations()) {

    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    const RELOC_AARCH64 type = static_cast<RELOC_AARCH64>(relocation.type());

    switch (type) {
      case RELOC_AARCH64::R_AARCH64_JUMP_SLOT:
      case RELOC_AARCH64::R_AARCH64_RELATIVE:
      case RELOC_AARCH64::R_AARCH64_GLOB_DAT:
      case RELOC_AARCH64::R_AARCH64_IRELATIVE:
      case RELOC_AARCH64::R_AARCH64_ABS64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

      case RELOC_AARCH64::R_AARCH64_ABS32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      case RELOC_AARCH64::R_AARCH64_ABS16:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint16_t>(relocation, from, shift);
          break;
        }


      case RELOC_AARCH64::R_AARCH64_PREL64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

      case RELOC_AARCH64::R_AARCH64_PREL32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      case RELOC_AARCH64::R_AARCH64_PREL16:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint16_t>(relocation, from, shift);
          break;
        }

      default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
    }
  }
}

// ==================
// x86_32 Relocations
// ==================
template<>
void Binary::patch_relocations<ARCH::EM_386>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : this->get_relocations()) {
    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    const RELOC_i386 type = static_cast<RELOC_i386>(relocation.type());

    switch (type) {
      case RELOC_i386::R_386_RELATIVE:
      case RELOC_i386::R_386_JUMP_SLOT:
      case RELOC_i386::R_386_IRELATIVE:
      case RELOC_i386::R_386_GLOB_DAT:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
    }
  }
}

// ==================
// x86_64 Relocations
// ==================
template<>
void Binary::patch_relocations<ARCH::EM_X86_64>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : this->get_relocations()) {
    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    const RELOC_x86_64 type = static_cast<RELOC_x86_64>(relocation.type());
    switch (type) {
      case RELOC_x86_64::R_X86_64_RELATIVE:
      case RELOC_x86_64::R_X86_64_IRELATIVE:
      case RELOC_x86_64::R_X86_64_JUMP_SLOT:
      case RELOC_x86_64::R_X86_64_GLOB_DAT:
      case RELOC_x86_64::R_X86_64_64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

      case RELOC_x86_64::R_X86_64_32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      default:
        {
          VLOG(VDEBUG) << "Relocation '" << to_string(type) << "' not patched";
        }
    }
  }
}


template<class T>
void Binary::patch_addend(Relocation& relocation, uint64_t from, uint64_t shift) {

  if (static_cast<uint64_t>(relocation.addend()) >= from) {
    relocation.addend(relocation.addend() + shift);
  }

  const uint64_t address = relocation.address();
  VLOG(VDEBUG) << "Patch addend relocation at address: 0x" << std::hex << address;
  Section& section = this->section_from_virtual_address(address);
  const uint64_t relative_offset = this->virtual_address_to_offset(address) - section.offset();
  std::vector<uint8_t> section_content = section.content();
  const size_t section_size = section_content.size();

  if (section_content.size() == 0) {
    VLOG(VDEBUG) << "Section is empty nothing to do";
    return;
  }

  if (relative_offset >= section_size or (relative_offset + sizeof(T)) >= section_size) {
    VLOG(VDEBUG) << "Offset out of bound";
    return;
  }

  T* value = reinterpret_cast<T*>(section_content.data() + relative_offset);

  if (value != nullptr and *value >= from) {
    *value += shift;
  }

  section.content(section_content);
}



// ET_EXEC with PT_NOTE
// ====================
template<>
Segment& Binary::add_segment<E_TYPE::ET_EXEC, true>(const Segment& segment, uint64_t base) {
  std::vector<uint8_t> content = segment.content();
  Segment* new_segment = new Segment{segment};
  new_segment->datahandler_ = this->datahandler_;

  const uint64_t last_offset_sections = std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), 0,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      });

  const uint64_t last_offset_segments = std::accumulate(
      std::begin(this->segments_),
      std::end(this->segments_), 0,
      [] (uint64_t offset, const Segment* segment) {
        return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      });

  const uint64_t last_offset = std::max<uint64_t>(last_offset_sections, last_offset_segments);

  const uint64_t psize = static_cast<uint64_t>(getpagesize());
  const uint64_t last_offset_aligned = align(last_offset, psize);
  new_segment->file_offset(last_offset_aligned);

  if (segment.virtual_address() == 0) {
    new_segment->virtual_address(base + last_offset_aligned);
  }

  new_segment->physical_address(new_segment->virtual_address());

  uint64_t segmentsize = align(content.size(), psize);
  content.resize(segmentsize);

  new_segment->physical_size(segmentsize);
  new_segment->virtual_size(segmentsize);

  if (new_segment->alignment() == 0) {
    new_segment->alignment(psize);
  }

  this->datahandler_->make_hole(last_offset_aligned, new_segment->physical_size());
  new_segment->content(content);


  auto&& it_segment_phdr = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* s)
      {
        return s != nullptr and s->type() == SEGMENT_TYPES::PT_PHDR;
      });

  if (it_segment_phdr != std::end(this->segments_)) {
    Segment *phdr_segment = *it_segment_phdr;
    const size_t phdr_size = phdr_segment->content().size();
    phdr_segment->content(std::vector<uint8_t>(phdr_size, 0));
  }

  auto&& it_segment_note = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* s)
      {
        return s != nullptr and s->type() == SEGMENT_TYPES::PT_NOTE;
      });

  if (it_segment_note == std::end(this->segments_)) {
    throw not_found("Can't find 'PT_NOTE' segment");
  }

  delete *it_segment_note;
  this->segments_.erase(it_segment_note);

  // Patch shdr
  Header& header = this->get_header();
  const uint64_t new_section_hdr_offset = new_segment->file_offset() + new_segment->physical_size() + 1;
  header.section_headers_offset(new_section_hdr_offset);

  this->segments_.push_back(new_segment);
  return *this->segments_.back();
}

// =======================
// ET_EXEC without PT_NOTE
// =======================
template<>
Segment& Binary::add_segment<E_TYPE::ET_EXEC, false>(const Segment& segment, uint64_t base) {

  Header& header = this->get_header();

  // ------------------------------------------
  // Part 1: Move PHDR at the end of the binary
  // ------------------------------------------

  header.numberof_segments(header.numberof_segments() + 1);

  auto&& it_text_segment = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* s) {
        return s->type() == SEGMENT_TYPES::PT_LOAD and
               s->has(ELF_SEGMENT_FLAGS::PF_X) and s->has(ELF_SEGMENT_FLAGS::PF_R);
      });

  if (it_text_segment == std::end(this->segments_)) {
    throw not_found("Unable to find a LOAD segment with 'r-x' permissions");
  }

  Segment* text_segment = *it_text_segment;

  uint64_t last_offset_sections = std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), 0,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      });

  uint64_t last_offset_segments = std::accumulate(
      std::begin(this->segments_),
      std::end(this->segments_), 0,
      [] (uint64_t offset, const Segment* segment) {
        return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      });

  uint64_t last_offset     = std::max<uint64_t>(last_offset_sections, last_offset_segments);
  uint64_t new_phdr_offset = last_offset;

  header.program_headers_offset(new_phdr_offset);

  uint64_t phdr_size = 0;
  if (this->type() == ELF_CLASS::ELFCLASS32) {
    phdr_size = sizeof(ELF32::Elf_Phdr);
  }

  if (this->type() == ELF_CLASS::ELFCLASS64) {
    phdr_size = sizeof(ELF64::Elf_Phdr);
  }

  auto&& it_segment_phdr = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* s)
      {
        return s != nullptr and s->type() == SEGMENT_TYPES::PT_PHDR;
      });

  if (it_segment_phdr != std::end(this->segments_)) {
    Segment *phdr_segment = *it_segment_phdr;
    phdr_segment->file_offset(new_phdr_offset);
    phdr_segment->virtual_address(text_segment->virtual_address() - text_segment->file_offset() + phdr_segment->file_offset());

    phdr_segment->physical_address(phdr_segment->virtual_address());

    phdr_segment->physical_size(phdr_segment->physical_size() + phdr_size);
    phdr_segment->virtual_size(phdr_segment->physical_size() + phdr_size);

    uint64_t gap  = phdr_segment->file_offset() + phdr_segment->physical_size();
             gap -= text_segment->file_offset() + text_segment->physical_size();

    text_segment->physical_size(text_segment->physical_size() + gap);
    text_segment->virtual_size(text_segment->virtual_size() + gap);

    // Clear PHDR segment
    phdr_segment->content(std::vector<uint8_t>(phdr_segment->physical_size(), 0));
  } else {
    uint64_t gap  = new_phdr_offset + phdr_size * header.numberof_segments();
             gap -= text_segment->file_offset() + text_segment->physical_size();

    text_segment->physical_size(text_segment->physical_size() + gap);
    text_segment->virtual_size(text_segment->virtual_size() + gap);
  }

  // Extend the segment so that it wraps the PHDR segment
  this->datahandler_->make_hole(new_phdr_offset, phdr_size * header.numberof_segments());

  // --------------------------------------
  // Part 2: Add the segment
  // --------------------------------------

  std::vector<uint8_t> content = segment.content();
  Segment* new_segment = new Segment{segment};
  new_segment->datahandler_ = this->datahandler_;

  last_offset_sections = std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), 0,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      });

  last_offset_segments = std::accumulate(
      std::begin(this->segments_),
      std::end(this->segments_), 0,
      [] (uint64_t offset, const Segment* segment) {
        return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      });

  last_offset = std::max<uint64_t>(last_offset_sections, last_offset_segments);

  const uint64_t psize = static_cast<uint64_t>(getpagesize());
  const uint64_t last_offset_aligned = align(last_offset, psize);
  new_segment->file_offset(last_offset_aligned);

  if (segment.virtual_address() == 0) {
    new_segment->virtual_address(base + last_offset_aligned);
  }

  new_segment->physical_address(new_segment->virtual_address());

  uint64_t segmentsize = align(content.size(), psize);
  content.resize(segmentsize);

  new_segment->physical_size(segmentsize);
  new_segment->virtual_size(segmentsize);

  if (new_segment->alignment() == 0) {
    new_segment->alignment(psize);
  }

  this->datahandler_->make_hole(last_offset_aligned, new_segment->physical_size());
  new_segment->content(content);

  header.section_headers_offset(new_segment->file_offset() + new_segment->physical_size());

  this->segments_.push_back(new_segment);
  return *this->segments_.back();
}


// =======================
// ET_DYN (PIE/Libraryies)
// =======================
template<>
Segment& Binary::add_segment<E_TYPE::ET_DYN>(const Segment& segment, uint64_t base) {

  const uint64_t psize = static_cast<uint64_t>(getpagesize());

  // --------------------------------------
  // Part 1: Make spaces for a new PHDR
  // --------------------------------------
  const uint64_t phdr_offset = this->get_header().program_headers_offset();
  uint64_t phdr_size         = 0;

  if (this->type() == ELF_CLASS::ELFCLASS32) {
    phdr_size = sizeof(ELF32::Elf_Phdr);
  }

  if (this->type() == ELF_CLASS::ELFCLASS64) {
    phdr_size = sizeof(ELF64::Elf_Phdr);
  }

  this->datahandler_->make_hole(phdr_offset + phdr_size * this->segments_.size(), psize);

  uint64_t from  = phdr_offset + phdr_size * this->segments_.size();
  // TODO: Improve (It takes too much spaces)
  uint64_t shift = psize;

  VLOG(VDEBUG) << "Header shift: " << std::hex << shift;

  this->get_header().section_headers_offset(this->get_header().section_headers_offset() + shift);

  this->shift_sections(from, shift);
  this->shift_segments(from, shift);

  // Patch segment size for the segment which contains the new section
  for (Segment* segment : this->segments_) {
    if ((segment->file_offset() + segment->physical_size()) >= from and
        from >= segment->file_offset()) {

      DataHandler::Node& node = this->datahandler_->find(
          segment->file_offset(),
          segment->physical_size(),
          false,
          DataHandler::Node::SEGMENT);
      node.size(node.size() + shift);

      segment->virtual_size(segment->virtual_size()   + shift);
      segment->physical_size(segment->physical_size() + shift);
    }
  }

  this->shift_dynamic_entries(from, shift);
  this->shift_symbols(from, shift);
  this->shift_relocations(from, shift);

  if (this->get_header().entrypoint() >= from) {
    this->get_header().entrypoint(this->get_header().entrypoint() + shift);
  }

  // --------------------------------------
  // Part 2: Add the segment
  // --------------------------------------
  std::vector<uint8_t> content = segment.content();
  Segment* new_segment = new Segment{segment};
  new_segment->datahandler_ = this->datahandler_;

  const uint64_t last_offset_sections = std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), 0,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->file_offset() + section->size(), offset);
      });

  const uint64_t last_offset_segments = std::accumulate(
      std::begin(this->segments_),
      std::end(this->segments_), 0,
      [] (uint64_t offset, const Segment* segment) {
        return std::max<uint64_t>(segment->file_offset() + segment->physical_size(), offset);
      });

  const uint64_t last_offset         = std::max<uint64_t>(last_offset_sections, last_offset_segments);
  const uint64_t last_offset_aligned = align(last_offset, psize);

  new_segment->file_offset(last_offset_aligned);
  new_segment->virtual_address(new_segment->file_offset() + base);
  new_segment->physical_address(new_segment->virtual_address());

  uint64_t segmentsize = align(content.size(), psize);
  content.resize(segmentsize);

  new_segment->physical_size(segmentsize);
  new_segment->virtual_size(segmentsize);

  if (new_segment->alignment() == 0) {
    new_segment->alignment(psize);
  }

  // Patch SHDR
  Header& header = this->get_header();
  const uint64_t new_section_hdr_offset = new_segment->file_offset() + new_segment->physical_size() + 1;
  header.section_headers_offset(new_section_hdr_offset);

  this->datahandler_->make_hole(last_offset_aligned, new_segment->physical_size());

  new_segment->content(content);

  auto&& it_segment_phdr = std::find_if(
      std::begin(this->segments_),
      std::end(this->segments_),
      [] (const Segment* s)
      {
        return s != nullptr and s->type() == SEGMENT_TYPES::PT_PHDR;
      });

  // Clear PHDR
  if (it_segment_phdr != std::end(this->segments_)) {
    Segment *phdr_segment = *it_segment_phdr;
    const size_t phdr_size = phdr_segment->content().size();
    phdr_segment->content(std::vector<uint8_t>(phdr_size, 0));
  }

  header.numberof_segments(header.numberof_segments() + 1);

  this->segments_.push_back(new_segment);
  return *this->segments_.back();
}

}
}
