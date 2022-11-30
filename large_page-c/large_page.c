// Copyright (C) 2018 Intel Corporation
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom
// the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
// OR OTHER DEALINGS IN THE SOFTWARE.
//
// SPDX-License-Identifier: MIT

#define _GNU_SOURCE
#include "large_page.h"
#include <link.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <regex.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>


#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000 /* arch specific */
#endif

typedef struct {
  void*     from;
  void*     to;
  void*     from_aligned;
  void*     to_aligned;
  char      name[64];
} mem_range;

typedef struct {
  uintptr_t start;
  uintptr_t end;
  regex_t regex;
  bool have_regex;
  map_status status;
} FindParams;

typedef struct {
  uintptr_t *start;
  uintptr_t *end;
  char      **name;
  regex_t regex;
  bool have_regex;
  map_status status;
  int nb_segs;
} FindParamsAll;

int iodlr_number_of_ehp_avail = 0;
char *iodlr_use_ehp = NULL;
#define HPS (2L * 1024 * 1024)
#define PS (4L * 1024)

static inline uintptr_t page_align_down(uintptr_t addr) {
  return (addr & ~(PS - 1));
}

static inline uintptr_t page_align_up(uintptr_t addr) {
  return page_align_down(addr + PS - 1);
}

static inline uintptr_t largepage_align_down(uintptr_t addr) {
  return (addr & ~(HPS - 1));
}

static inline uintptr_t largepage_align_up(uintptr_t addr) {
  return largepage_align_down(addr + HPS - 1);
}

static map_status FindSection(const char* fname, ElfW(Shdr)** section, char** names, int* nb_segs) {
  FILE* bin = fopen(fname, "r");
  if (bin == NULL) return map_open_exe_failed;

#define CLEAN_EXIT(code)                        \
  do {                                          \
    int status = 0;                             \
    if (errno == 0) {                           \
      status = fclose(bin);                     \
    }                                           \
    return ((((code) == map_ok) && status != 0) \
      ? map_see_errno_close_exe_failed          \
      : (code));                                \
  } while (0)
  // Read the header.
  ElfW(Ehdr) ehdr;
  if (fread(&ehdr, sizeof(ehdr), 1, bin) != 1)
    CLEAN_EXIT(map_read_exe_header_failed);

  // Read the section headers.
  ElfW(Shdr) shdrs[ehdr.e_shnum];
  if (fseek(bin, ehdr.e_shoff, SEEK_SET) != 0)
    CLEAN_EXIT(map_see_errno_seek_exe_sheaders_failed);
  if (fread(shdrs, sizeof(shdrs[0]), ehdr.e_shnum, bin) != ehdr.e_shnum)
    CLEAN_EXIT(map_read_exe_sheaders_failed);

  // Read the string table.
  ElfW(Shdr)* sh_strab = &shdrs[ehdr.e_shstrndx];
  char section_names[sh_strab->sh_size];
  if (fseek(bin, sh_strab->sh_offset, SEEK_SET) != 0)
    CLEAN_EXIT(map_see_errno_seek_exe_string_table_failed);
  if (fread(section_names, sh_strab->sh_size, 1, bin) != 1)
    CLEAN_EXIT(map_read_exe_string_table_failed);

  // Find the sections.
  char to_find[][20] = { ".text\0", ".text.cold\0", ".plt\0", ".plt.got\0", ".trampoline\0", ".init\0", ".fini\0"};
  for (size_t i = 0; i < sizeof(to_find) / sizeof(to_find[0]); i++) {
    syslog(LOG_WARNING, "iodlr: searching %s\n", to_find[i]);
    for (uint32_t idx = 0; idx < ehdr.e_shnum; idx++) {
      ElfW(Shdr)* sh = &shdrs[idx];
      if(strlen(&section_names[sh->sh_name]) == 0)
        continue;
      if (!memcmp(&section_names[sh->sh_name], to_find[i], strnlen(to_find[i], 20))) {
        syslog(LOG_WARNING, "iodlr: found %s at %p\n", &section_names[sh->sh_name], sh);
        section[*nb_segs] = sh;
        names[*nb_segs] = &section_names[sh->sh_name];
        *nb_segs +=1;
        break;
      };
    }
  }
  CLEAN_EXIT(map_ok);

#undef CLEAN_EXIT
}

static map_status FindTextSection(const char* fname, ElfW(Shdr)* text_section) {
  FILE* bin = fopen(fname, "r");
  if (bin == NULL) return map_open_exe_failed;

#define CLEAN_EXIT(code)                        \
  do {                                          \
    int status = 0;                             \
    if (errno == 0) {                           \
      status = fclose(bin);                     \
    }                                           \
    return ((((code) == map_ok) && status != 0) \
      ? map_see_errno_close_exe_failed          \
      : (code));                                \
  } while (0)

  // Read the header.
  ElfW(Ehdr) ehdr;
  if (fread(&ehdr, sizeof(ehdr), 1, bin) != 1)
    CLEAN_EXIT(map_read_exe_header_failed);

  // Read the section headers.
  ElfW(Shdr) shdrs[ehdr.e_shnum];
  if (fseek(bin, ehdr.e_shoff, SEEK_SET) != 0)
    CLEAN_EXIT(map_see_errno_seek_exe_sheaders_failed);
  if (fread(shdrs, sizeof(shdrs[0]), ehdr.e_shnum, bin) != ehdr.e_shnum)
    CLEAN_EXIT(map_read_exe_sheaders_failed);

  // Read the string table.
  ElfW(Shdr)* sh_strab = &shdrs[ehdr.e_shstrndx];
  char section_names[sh_strab->sh_size];
  if (fseek(bin, sh_strab->sh_offset, SEEK_SET) != 0)
    CLEAN_EXIT(map_see_errno_seek_exe_string_table_failed);
  if (fread(section_names, sh_strab->sh_size, 1, bin) != 1)
    CLEAN_EXIT(map_read_exe_string_table_failed);

  // Find the ".text" section.
  for (uint32_t idx = 0; idx < ehdr.e_shnum; idx++) {
    ElfW(Shdr)* sh = &shdrs[idx];
    if (!memcmp(&section_names[sh->sh_name], ".text", 5)) {
      *text_section = *sh;
      CLEAN_EXIT(map_ok);
    }
  }

  CLEAN_EXIT(map_region_not_found);
#undef CLEAN_EXIT
}

static int FindAllMapping(struct dl_phdr_info* hdr, size_t size, void* data) {
  FindParamsAll* find_params = (FindParamsAll*)data;
  ElfW(Shdr) *section;

  section = malloc(sizeof(ElfW(Shdr)) * 64);
  memset(section, 0, sizeof(ElfW(Shdr)) * 64);

  // We are only interested in the information matching the regex or, if no
  // regex was given, the mapping matching the main executable. This latter
  // mapping has the empty string for a name.
  if ((find_params->have_regex &&
        regexec(&find_params->regex, hdr->dlpi_name, 0, NULL, 0) == 0) ||
      (hdr->dlpi_name[0] == 0 && !find_params->have_regex)) {
    const char* fname = (hdr->dlpi_name[0] == 0 ? "/proc/self/exe" : hdr->dlpi_name);

    find_params->status = FindSection(fname, &section, find_params->name, &find_params->nb_segs);
    // check if there are enough number of hugepages available
    // i.e. bytes available in HP is more than total_bytes needed
    // if not set the status = not_enough_pages, otherwise okay
    if (find_params->status == map_ok && find_params->nb_segs > 0) {
      for (int i=0; i<find_params->nb_segs; i++) {
          find_params->start[i] = hdr->dlpi_addr + section[i].sh_addr;
          find_params->end[i] = find_params->start[i] + section[i].sh_size;
      }
    }
  }

  return 0;
}

static int FindMapping(struct dl_phdr_info* hdr, size_t size, void* data) {
  FindParams* find_params = (FindParams*)data;
  ElfW(Shdr) text_section;

  // We are only interested in the information matching the regex or, if no
  // regex was given, the mapping matching the main executable. This latter
  // mapping has the empty string for a name.
  if ((find_params->have_regex &&
        regexec(&find_params->regex, hdr->dlpi_name, 0, NULL, 0) == 0) ||
      (hdr->dlpi_name[0] == 0 && !find_params->have_regex)) {
    const char* fname = (hdr->dlpi_name[0] == 0 ? "/proc/self/exe" : hdr->dlpi_name);

    // Once we have found the info structure for the desired linked-in object,
    // we open it on disk to find the location of its .text section. We use the
    // base address given to calculate the .text section offset in memory.
    text_section.sh_size=0;
    find_params->status = FindTextSection(fname, &text_section);
    // check if there are enough number of hugepages available
    // i.e. bytes available in HP is more than total_bytes needed
    // if not set the status = not_enough_pages, otherwise okay
    if (find_params->status == map_ok) {
      if (iodlr_use_ehp) {
        int pages_need = text_section.sh_size / HPS;
        int bytes_remaining = text_section.sh_size % HPS;
        if (bytes_remaining > 0) {
          pages_need += 1;
        }
        if (iodlr_number_of_ehp_avail < pages_need) {
          fprintf(stderr, "INFO: Need %d explicit pages.\n", pages_need);
          fflush(stderr);
          find_params->status = map_not_enough_explicit_hugepages_are_allocated;
          return 0;
        } else {
          iodlr_number_of_ehp_avail -= pages_need;
        }
      }
      find_params->start = hdr->dlpi_addr + text_section.sh_addr;
      fprintf(stderr, "Base address: %lx.", hdr->dlpi_addr);
      find_params->end = find_params->start + text_section.sh_size;
      return 1;
    }
  }

  return 0;
}

// Identify and return the text region in the currently mapped memory regions.
static map_status FindTextRegion(const char* lib_regex, mem_range* region) {
  FindParams find_params = { 0, 0, { 0 }, false, map_region_not_found };

  if (lib_regex != NULL) {
    if (regcomp(&find_params.regex, lib_regex, 0) != 0) {
      return map_invalid_regex;
    }
    find_params.have_regex = true;
  }

  // We iterate over all the mappings created for the main executable and any of
  // its linked-in dependencies. The return value of `FindMapping` will become
  // the return value of `dl_iterate_phdr`.
  dl_iterate_phdr(FindMapping, &find_params);
  if (find_params.status != map_ok) {
    regfree(&find_params.regex);
    return find_params.status;
  }

  region->from = (void*)find_params.start;
  region->to = (void*)find_params.end;

  regfree(&find_params.regex);
  return map_ok;
}

// Identify and return the text region in the currently mapped memory regions.
static map_status FindRegion(const char* lib_regex, mem_range* region) {
  uintptr_t *start = malloc(64 * sizeof(uintptr_t));
  uintptr_t *stop = malloc(64 * sizeof(uintptr_t));
  char **names = malloc(64 * sizeof(char*));

  memset(start, 0, sizeof(uintptr_t) * 64);
  memset(stop, 0, sizeof(uintptr_t) * 64);
  memset(names, 0, sizeof(char*) * 64);
  FindParamsAll find_params = { start, stop, names, { 0 }, false, map_region_not_found };

  if (lib_regex != NULL) {
    if (regcomp(&find_params.regex, lib_regex, 0) != 0) {
      return map_invalid_regex;
    }
    find_params.have_regex = true;
  }

  // We iterate over all the mappings created for the main executable and any of
  // its linked-in dependencies. The return value of `FindMapping` will become
  // the return value of `dl_iterate_phdr`.
  dl_iterate_phdr(FindAllMapping, &find_params);

  if (find_params.status != map_ok) {
    regfree(&find_params.regex);
    return find_params.status;
  }

  for (int i=0; i < find_params.nb_segs; i++) {
    region[i].from = (void*)find_params.start[i];
    region[i].to = (void*)find_params.end[i];
    strncpy(region[i].name, find_params.name[i], 64);
  }

  regfree(&find_params.regex);
  free(start);
  free(stop);
  return map_ok;
}

static map_status IsExplicitHugePagesEnabled(bool* result) {
  *result = false;
  FILE* ifs;
  ifs = fopen("/proc/sys/vm/nr_hugepages", "r");
  if (!ifs) {
    return map_failed_to_open_ehp_file;
  }

  int matched = fscanf(ifs, "%d", &iodlr_number_of_ehp_avail);
  if (matched != 1) {
    return map_malformed_thp_file;
  }
  fclose(ifs);
  if (iodlr_number_of_ehp_avail <= 0) {
    fprintf(stderr, "WARNING: No explicit hugepages are allocated\n");
    fflush(stderr);
    *result = true;
  } else {
    *result = true;
  }
  return map_ok;
}

static map_status IsTransparentHugePagesEnabled(bool* result) {
#if defined(ENABLE_LARGE_CODE_PAGES) && ENABLE_LARGE_CODE_PAGES
  *result = false;
  FILE* ifs;
  char always[16] = {0};
  char madvise[16] = {0};
  char never[16] = {0};
  int matched;

  ifs = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "rt");
  if (!ifs) {
    return map_failed_to_open_thp_file;
  }

  matched = fscanf(ifs, "%s %s %s", always, madvise, never);
  fclose(ifs);

  if (matched != 3) {
    return map_malformed_thp_file;
  }

  if (strcmp(always, "[always]") == 0) {
    *result = true;
  } else if (strcmp(madvise, "[madvise]") == 0) {
    *result = true;
  } else if (strcmp(never, "[never]") == 0) {
    *result = false;
  }

  return map_ok;
#else
  return map_unsupported_platform;
#endif  // ENABLE_LARGE_CODE_PAGES
}

static void print_page(void* start_address, void* end_address) {
#define PAGE_SIZE 0x1000

    char filename[BUFSIZ];
    int j=0;

    snprintf(filename, sizeof filename, "/proc/%d/pagemap", getpid());

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
    }
    for (uint64_t i = (uint64_t)start_address; i < (uint64_t)end_address; i += 0x1000) {
        uint64_t data;
        uint64_t index = (i / PAGE_SIZE) * sizeof(data);
        if (pread(fd, &data, sizeof(data), index) != sizeof(data)) {
            perror("pread");
            break;
        }

        syslog(LOG_INFO, "iodlr: %-16lx : pfn %-16lx soft-dirty %ld file/shared %ld "
               "swapped %ld present %ld\n",
               i, data & 0x7fffffffffffff, (data >> 55) & 1, (data >> 61) & 1, (data >> 62) & 1, (data >> 63) & 1);
          j++;
          if (j>4)
            break;
    }
}

// Move specified region to large pages. We need to be very careful.
// 1: This function itself should not be moved.
// We use a gcc attributes
// (__section__) to put it outside the ".text" section
// (__aligned__) to align it at 2M boundary
// (__noline__) to not inline this function
// 2: This function should not call any function(s) that might be moved.
// a. map a new area and copy the original code there
// b. mmap using the start address with MAP_FIXED so we get exactly
//    the same virtual address
// c. madvise with MADV_HUGE_PAGE
// d. If successful copy the code there and unmap the original region
static map_status
__attribute__((__section__("lpstub")))
__attribute__((__aligned__(HPS)))
__attribute__((__noinline__))
MoveRegionToLargePages(const mem_range* r) {
  void* nmem = NULL;
  void* tmem = NULL;
  int ret = 0;
  map_status status = map_ok;
  void* start = r->from_aligned;
  size_t size = r->to_aligned - r->from_aligned;

  // Allocate temporary region preparing for copy
  nmem = mmap(NULL, size,
              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (nmem == MAP_FAILED) {
    return map_see_errno;
  }

  memcpy(nmem, r->from, size);

  // We already know the original page is r-xp
  // (PROT_READ, PROT_EXEC, MAP_PRIVATE)
  // We want PROT_WRITE because we are writing into it.
  // We want it at the fixed address and we use MAP_FIXED.
#define CLEAN_EXIT_CHECK(oper)                          \
  if (tmem == MAP_FAILED) {                             \
    status = oper##_failed;                             \
    ret = munmap(nmem, size);                           \
    if (ret < 0) {                                      \
      status = oper##_munmap_nmem_failed;               \
    }                                                   \
    return status;                                      \
  }

  if (iodlr_use_ehp) {
    // map to explicit hugepages
    tmem = mmap(start, size,
              PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_HUGETLB,
              -1, 0);
  } else {
    tmem = mmap(start, size,
              PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1 , 0);
  }

  CLEAN_EXIT_CHECK(map_see_errno_mmap_tmem);

#undef CLEAN_EXIT_CHECK

#define CLEAN_EXIT_CHECK(oper)                          \
  if (ret < 0) {                                        \
    status = oper##_failed;                             \
    ret = munmap(tmem, size);                           \
    if (ret < 0) {                                      \
      status = oper##_munmap_tmem_failed;               \
    }                                                   \
    ret = munmap(nmem, size);                           \
    if (ret < 0) {                                      \
      status = (status == oper##_munmap_tmem_failed)    \
        ? oper##_munmaps_failed                         \
        : oper##_munmap_nmem_failed;                    \
    }                                                   \
    return status;                                      \
  }

  if (!iodlr_use_ehp) {
    ret = madvise(tmem, size, MADV_HUGEPAGE);
    CLEAN_EXIT_CHECK(map_see_errno_madvise_tmem);
  }

  memcpy(start, nmem, size);
  ret = mprotect(start, size, PROT_READ | PROT_EXEC);
  CLEAN_EXIT_CHECK(map_see_errno_mprotect);

#undef CLEAN_EXIT_CHECK

  // Release the old/temporary mapped region
  ret = munmap(nmem, size);
  if (ret < 0) {
    status = map_see_errno_munmap_nmem_failed;
  }

  return status;
}

// Align the region to to be mapped to 2MB page boundaries.
static void AlignRegionToPageBoundary(mem_range* r, size_t pagesize) {
  if (pagesize == HPS) {
    r->from_aligned = (void*)(largepage_align_up((uintptr_t)r->from));
    r->to_aligned = (void*)(largepage_align_down((uintptr_t)r->to));
  } else {
    r->from_aligned = (void*)(page_align_up((uintptr_t)r->from));
    r->to_aligned = (void*)(page_align_down((uintptr_t)r->to));
  }
}

static map_status CheckMemRange(mem_range* r, size_t page_size) {
  if (r->from_aligned == NULL || r->to_aligned == NULL) {
    return map_invalid_region_address;
  }

  if ((r->to_aligned - r->from_aligned) < page_size || r->from_aligned > r->to_aligned) {
    return map_region_too_small;
  }

  return map_ok;
}


// XXX: implement multiple device support
static off_t last_offset = 0x0;

static map_status
__attribute__((__section__("lpstub")))
__attribute__((__aligned__(PS)))
__attribute__((__noinline__))
MoveRegionToFixedPages(const mem_range* r, const char* device) {
  void* nmem = NULL;
  void* tmem = NULL;
  int ret = 0;
  map_status status = map_ok;
  void* start = r->from_aligned;
  size_t size = r->to_aligned - r->from_aligned;

  // Allocate temporary region preparing for copy
  nmem = mmap(NULL, size,
              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (nmem == MAP_FAILED) {
    return map_see_errno;
  }

  memcpy(nmem, start, size);
#define CLEAN_EXIT_CHECK(oper)                          \
  if (tmem == MAP_FAILED) {                             \
    status = oper##_failed;                             \
    ret = munmap(nmem, size);                           \
    if (ret < 0) {                                      \
      status = oper##_munmap_nmem_failed;               \
    }                                                   \
    return status;                                      \
  }

  int fd = open(device, O_RDWR | O_SYNC);
  if (fd < 0) {
      perror("Can't open device");
      return 1;
  }
  syslog(LOG_INFO, "iodlr: dump before remapping");
  print_page(start, start + size);

  tmem = mmap(start, size,
             PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_SHARED | MAP_FIXED, fd, last_offset);


  if (tmem == MAP_FAILED) {
      perror("Oops, mmap failed");
      return 1;
  }

  CLEAN_EXIT_CHECK(map_see_errno_mmap_tmem);

#undef CLEAN_EXIT_CHECK

#define CLEAN_EXIT_CHECK(oper)                          \
  if (ret < 0) {                                        \
    status = oper##_failed;                             \
    ret = munmap(tmem, size);                           \
    if (ret < 0) {                                      \
      status = oper##_munmap_tmem_failed;               \
    }                                                   \
    ret = munmap(nmem, size);                           \
    if (ret < 0) {                                      \
      status = (status == oper##_munmap_tmem_failed)    \
        ? oper##_munmaps_failed                         \
        : oper##_munmap_nmem_failed;                    \
    }                                                   \
    return status;                                      \
  }

  memcpy(start, nmem, size);
  mlock(start, size);
  ret = mprotect(start, size, PROT_READ | PROT_EXEC);
  CLEAN_EXIT_CHECK(map_see_errno_mprotect);

#undef CLEAN_EXIT_CHECK

  // Release the old/temporary mapped region
  ret = munmap(nmem, size);
  if (ret < 0) {
    status = map_see_errno_munmap_nmem_failed;
  }
  syslog(LOG_INFO, "iodlr: dump after remapping");
  print_page(start, start + size);
  last_offset += size;
  close(fd);
  return status;
}

// Align the region to to be mapped to 2MB page boundaries and then move the
// region to large pages.
static map_status AlignMoveRegionToLargePages(mem_range* r) {
  map_status status;
  AlignRegionToPageBoundary(r, HPS);

  status = CheckMemRange(r, HPS);
  if (status != map_ok) {
    return status;
  }

  return MoveRegionToLargePages(r);
}

static map_status AlignMoveRegionToFixedPages(mem_range* r, const char* device) {
  map_status status;
  AlignRegionToPageBoundary(r, PS);
  syslog(LOG_INFO, "iodlr: SEGMENT=%s realigned @ %p -> %p /  %p -> %p \n", r->name, r->from, r->from_aligned, r->to, r->to_aligned);
  status = CheckMemRange(r, PS);
  if (status != map_ok) {
    return status;
  }
  return MoveRegionToFixedPages(r, device);
}

// Map the .text segment of the linked application into 2MB pages.
// The algorithm is simple:
// 1. Find the text region of the executing binary in memory
//    * Examine the /proc/self/maps to determine the currently mapped text
//      region and obtain the start and end addresses.
//    * Modify the start address to point to the very beginning of .text segment
//      (from variable textsegment setup in ld.script).
//    * Align the address of start and end addresses to large page boundaries.
//
// 2: Move the text region to large pages
//    * Map a new area and copy the original code there.
//    * Use mmap using the start address with MAP_FIXED so we get exactly the
//      same virtual address.
//    * Use madvise with MADV_HUGE_PAGE to use anonymous 2M pages.
//    * If successful, copy the code to the newly mapped area and unmap the
//      original region.
map_status MapStaticCodeToLargePages() {
  mem_range r = {0};
  map_status status = FindTextRegion(NULL, &r);
  if (status != map_ok) {
    return status;
  }
  return AlignMoveRegionToLargePages(&r);
}

map_status MapDSOToLargePages(const char* lib_regex) {
  mem_range r = {0};
  map_status status;

  if (lib_regex == NULL) {
    return map_null_regex;
  }

  status = FindTextRegion(lib_regex, &r);
  if (status != map_ok) {
    return status;
  }
  return AlignMoveRegionToLargePages(&r);
}

map_status MapAllDSOToFixedPages(const char* lib_regex, const char* device) {
  mem_range *r;
  map_status status;

  r = malloc(sizeof(mem_range) * 64);
  memset(r, 0, sizeof(mem_range) * 64);

  if (lib_regex == NULL) {
    return map_null_regex;
  }

  status = FindRegion(lib_regex, r);

  if (status != map_ok) {
    return status;
  }
  for (int i=0; r[i].from != 0; i++) {
    syslog(LOG_INFO, "iodlr: PREPARE TO REMAP SEGMENT=%s @ %p -> %p\n", r[i].name, r[i].from, r[i].to);
    status = AlignMoveRegionToFixedPages(&r[i], device);
    if (status != map_ok)
      syslog(LOG_WARNING, "iodlr: Cannot remap segment %s : %s\n", r[i].name, MapStatusStr(status, true));
  }
  return status;
}

// This function is similar to the function above. However, the region to be
// mapped to 2MB pages is specified for this version as hotStart and hotEnd.
map_status MapStaticCodeRangeToLargePages(void* from, void* to) {
  mem_range r = {from, to};
  return AlignMoveRegionToLargePages(&r);
}

// Return true if transparent huge pages is enabled on the system. Otherwise,
// return false.
map_status IsLargePagesEnabled(bool* result) {
  iodlr_use_ehp = getenv("IODLR_USE_EXPLICIT_HP");
  if (iodlr_use_ehp) {
    fprintf(stderr, "- experimental: using explicit hugepages -  \n");
    fflush(stderr);
    return IsExplicitHugePagesEnabled(result);
  } else {
    return IsTransparentHugePagesEnabled(result);
  }
}

const char* MapStatusStr(map_status status, bool fulltext) {
  static const char* map_status_text[] = {
    "map_ok",
      "ok",
    "map_failed_to_open_thp_file",
      "failed to open hugepage enablement status file",
    "map_invalid_regex",
      "invalid regex",
    "map_invalid_region_address",
      "invalid region boundaries",
    "map_malformed_thp_file",
      "malformed thp enablement status file",
    "map_null_regex",
      "regex was NULL",
    "map_region_not_found",
      "map region not found",
    "map_region_too_small",
      "map region too small",
    "map_see_errno",
      "see errno",
    "map_see_errno_madvise_tmem_failed",
      "madvise for destination failed",
    "map_see_errno_madvise_tmem_munmap_nmem_failed",
      "madvise for destination and unmapping of temporary failed",
    "map_see_errno_madvise_tmem_munmaps_failed",
      "madvise for destination and unmappings failed",
    "map_see_errno_madvise_tmem_munmap_tmem_failed",
      "madvise for destination and unmapping of destination failed",
    "map_see_errno_mmap_tmem_failed",
      "mapping of destination failed",
    "map_see_errno_mmap_tmem_munmap_nmem_failed",
      "mapping of destination and unmapping of temporary failed",
    "map_see_errno_mprotect_failed",
      "mprotect failed",
    "map_see_errno_mprotect_munmap_nmem_failed",
      "mprotect and unmapping of temporary failed",
    "map_see_errno_mprotect_munmaps_failed",
      "mprotect and unmappings failed",
    "map_see_errno_mprotect_munmap_tmem_failed",
      "mprotect and unmapping of destination failed",
    "map_see_errno_munmap_nmem_failed",
      "unmapping of temporary failed",
    "map_unsupported_platform",
      "mapping to large pages is not supported on this platform",
    "map_open_exe_failed",
      "opening executable file failed",
    "map_see_errno_close_exe_failed",
      "closing executable file failed",
    "map_see_errno_seek_exe_sheaders_failed",
      "seeking to executable file section headers failed",
    "map_read_exe_header_failed",
      "reading executable file header failed",
    "map_read_exe_sheaders_failed",
      "reading executable file section headers failed",
    "map_see_errno_seek_exe_string_table_failed",
      "seeking to executable file string table failed",
    "map_read_exe_string_table_failed",
      "reading executable file string table failed",
    "map_failed_to_open_ehp_file",
      "failed to open nr_hugepages file",
    "map_not_enough_explicit_hugepages_are_allocated",
      "not enough explicit hugepages are available"
  };
  return map_status_text[((int)status << 1) + (fulltext & 1)];
}
