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
#include "pyELF.hpp"

#include "LIEF/visitors/Hash.hpp"

#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (DynamicEntryArray::*)(void) const;

template<class T>
using setter_t = void (DynamicEntryArray::*)(T);

void init_ELF_DynamicEntryArray_class(py::module& m) {

  // Dynamic Entry Array object
  py::class_<DynamicEntryArray, DynamicEntry>(m, "DynamicEntryArray")
    .def(py::init<>())

    .def(py::init<DYNAMIC_TAGS, uint64_t>(),
        "Constructor with " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " and value",
        "tag"_a, "value"_a)

    .def_property("array",
        static_cast<std::vector<uint64_t>& (DynamicEntryArray::*) (void)>(&DynamicEntryArray::array),
        static_cast<setter_t<const std::vector<uint64_t>&>>(&DynamicEntryArray::array),
        "Return the array")

    .def("__eq__", &DynamicEntryArray::operator==)
    .def("__ne__", &DynamicEntryArray::operator!=)
    .def("__hash__",
        [] (const DynamicEntryArray& entry) {
          return LIEF::Hash::hash(entry);
        })


    .def("__str__",
        [] (const DynamicEntryArray& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str =  stream.str();
          return str;
        });
}
