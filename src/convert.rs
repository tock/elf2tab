//! Convert ELF to TBF.

use crate::header;
use crate::util::{self, align_to, amount_alignment_needed};
use ring::{rand, signature};
use rsa_der;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::cmp;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::path::{Path, PathBuf};
use std::{fs, io};

/// Helper function for reading RSA DER key files.
fn read_rsa_file(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

/// Helper function to determine if any nonzero length section is inside a
/// given segment.
///
/// This is necessary because we sometimes run into loadable segments that
/// shouldn't really exist (they are at addresses outside of what was
/// specified in the linker script), and we want to be able to skip them.
fn section_exists_in_segment(
    shdrs: &[(String, elf::section::SectionHeader)],
    segment: &elf::segment::ProgramHeader,
) -> bool {
    for (_, shdr) in shdrs.iter() {
        if shdr.sh_size > 0 && section_in_segment(shdr, segment) {
            return true;
        }
    }
    false
}

/// Helper function to determine if a section is within a specific segment.
///
/// Based on the function `section_in_segment` in
/// https://github.com/eliben/pyelftools
fn section_in_segment(
    section: &elf::section::SectionHeader,
    segment: &elf::segment::ProgramHeader,
) -> bool {
    let segtype = segment.p_type;
    let sectype = section.sh_type;
    let secflags = section.sh_flags as u32;

    // Only PT_LOAD, PT_GNU_RELRO and PT_TLS segments can contain SHF_TLS
    // sections.
    if (secflags & elf::abi::SHF_TLS > 0)
        && (segtype == elf::abi::PT_TLS
            || segtype == elf::abi::PT_GNU_RELRO
            || segtype == elf::abi::PT_LOAD)
    {
        // OK
    } else if (secflags & elf::abi::SHF_TLS == 0)
        && !(segtype == elf::abi::PT_TLS || segtype == elf::abi::PT_GNU_RELRO)
    {
        // OK
    } else {
        return false;
    }

    // PT_LOAD and similar segments only have SHF_ALLOC sections.
    if (secflags & elf::abi::SHF_ALLOC == 0)
        && (segtype == elf::abi::PT_LOAD
            || segtype == elf::abi::PT_DYNAMIC
            || segtype == elf::abi::PT_GNU_EH_FRAME
            || segtype == elf::abi::PT_GNU_RELRO
            || segtype == elf::abi::PT_GNU_STACK)
    {
        return false;
    }

    // In ELF_SECTION_IN_SEGMENT_STRICT the flag check_vma is on, so if this
    // is an alloc section, check whether its VMA is in bounds.
    if secflags & elf::abi::SHF_ALLOC > 0 {
        let secaddr = section.sh_addr;
        let vaddr = segment.p_vaddr;

        // This checks that the section is wholly contained in the segment.
        // The third condition is the 'strict' one - an empty section will
        // not match at the very end of the segment (unless the segment is
        // also zero size, which is handled by the second condition).
        if !(secaddr >= vaddr
            && secaddr - vaddr + section.sh_size <= segment.p_memsz
            && secaddr - vaddr <= segment.p_memsz - 1)
        {
            return false;
        }
    }

    // If we've come this far and it's a NOBITS section, it's in the
    // segment.
    if sectype == elf::abi::SHT_NOBITS {
        return true;
    }

    let secoffset = section.sh_offset;
    let poffset = segment.p_offset;

    // Same logic as with secaddr vs. vaddr checks above, just on offsets in
    // the file.
    secoffset >= poffset
        && secoffset - poffset + section.sh_size <= segment.p_filesz
        && secoffset - poffset <= segment.p_filesz - 1
}

/// Convert an ELF file to a TBF (Tock Binary Format) binary file.
///
/// This will place all segments from the ELF file into a binary and prepend a
/// TBF header to it. For all writeable sections in the included segments, if
/// there is a .rel.X section it will be included at the end with a 32 bit
/// length parameter first.
///
/// Assumptions:
/// - Any segments that are writable and set to be loaded into flash but with a
///   different virtual address will be in RAM and should count towards minimum
///   required RAM.
/// - Sections that are writeable flash regions include .wfr in their name.
pub fn elf_to_tbf(
    input_file: &mut fs::File,
    output: &mut Vec<u8>,
    package_name: Option<String>,
    verbose: bool,
    stack_len: Option<u32>,
    app_heap_len: u32,
    kernel_heap_len: u32,
    protected_region_size_arg: Option<u32>,
    permissions: Vec<(u32, u32)>,
    storage_ids: (Option<u32>, Option<Vec<u32>>, Option<Vec<u32>>),
    kernel_version: Option<(u16, u16)>,
    disabled: bool,
    minimum_footer_size: u32,
    app_version: u32,
    sha256: bool,
    sha384: bool,
    sha512: bool,
    rsa4096_private_key: Option<PathBuf>,
    rsa4096_public_key: Option<PathBuf>,
) -> io::Result<()> {
    let package_name = package_name.unwrap_or_default();

    // Load and parse ELF.
    let mut elf_file_buf = Vec::<u8>::default();
    input_file.read_to_end(&mut elf_file_buf)?;
    let elf_file = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(elf_file_buf.as_slice())
        .expect("Could not parse the .elf file.");

    let (shdr_tab, strtab) = match elf_file.section_headers_with_strtab() {
        Ok((Some(shdr_tab), Some(strtab))) => (shdr_tab, strtab),
        _ => {
            // We use the section headers to find sections like .symtab, .stack, and *.wfr
            panic!("Cannot convert ELF file with no section headers");
        }
    };

    let elf_sections: Vec<(String, elf::section::SectionHeader)> = shdr_tab
        .iter()
        .map(|shdr| {
            (
                strtab
                    .get(shdr.sh_name as usize)
                    .expect("Failed to parse section name")
                    .to_string(),
                shdr,
            )
        })
        .collect();

    let elf_phdrs: Vec<elf::segment::ProgramHeader> = elf_file
        .segments()
        .expect("Failed to locate ELF program headers")
        .iter()
        .collect();

    /// Specify how elf2tab should add trailing padding to the end of the TBF
    /// file.
    enum TrailingPadding {
        /// Make sure the entire TBF is a power of 2 in size, so add any
        /// necessary padding to make that happen.
        TotalSizePowerOfTwo,
        /// Make sure the entire TBF is a multiple of a specific value.
        TotalSizeMultiple(usize),
    }

    // Add trailing padding for certain architectures.
    //
    // - ARM: make sure the entire TBF is a power of 2 to make configuring the
    //   MPU easy.
    // - x86: use 4k padding to match page size.
    //
    // RISC-V apps do not need any additional padding.
    let trailing_padding = match elf_file.ehdr.e_machine {
        elf::abi::EM_ARM => Some(TrailingPadding::TotalSizePowerOfTwo),
        elf::abi::EM_386 => Some(TrailingPadding::TotalSizeMultiple(4096)),
        _ => None,
    };

    ////////////////////////////////////////////////////////////////////////////
    // Determine the amount of RAM this app needs.
    ////////////////////////////////////////////////////////////////////////////

    // Set the size of the stack, either as specified by command line arguments,
    // based on a section set by the linker, or if all else fails to a default
    // value.
    let stack_len = stack_len
        // not provided, read from binary
        .or_else(|| {
            elf_sections.iter().find_map(|(sh_name, shdr)| {
                if sh_name == ".stack" {
                    Some(shdr.sh_size as u32)
                } else {
                    None
                }
            })
        })
        // nothing in binary, use default
        .unwrap_or(2048);

    // Keep track of how much RAM this app will need.
    let mut minimum_ram_size: u32 = 0;

    // Find all segments destined for the RAM section that are stored in flash.
    // These are set in the linker file to consume memory, and we need to
    // account for them when we set the minimum amount of memory this app
    // requires.
    for segment in &elf_phdrs {
        // To filter, we need segments that are:
        // - Set to be LOADed.
        // - Have different virtual and physical addresses, meaning they are
        //   loaded into flash but actually reside in memory.
        // - Are not zero size in memory.
        // - Are writable (RAM should be writable).
        if segment.p_type == elf::abi::PT_LOAD
            && segment.p_vaddr != segment.p_paddr
            && segment.p_memsz > 0
            && ((segment.p_flags & elf::abi::PF_W) > 0)
        {
            minimum_ram_size += segment.p_memsz as u32;
        }
    }
    if verbose {
        println!(
            "Min RAM size from segments in ELF: {} bytes",
            minimum_ram_size
        );
    }

    // Add in room the app is asking us to reserve for the stack and heaps to
    // the minimum required RAM size.
    minimum_ram_size +=
        align_to(stack_len, 8) + align_to(app_heap_len, 4) + align_to(kernel_heap_len, 4);

    ////////////////////////////////////////////////////////////////////////////
    // Determine fixed addresses this app must be loaded at
    ////////////////////////////////////////////////////////////////////////////

    // Check for fixed addresses.
    //
    // We do this with different mechanisms for flash and ram. For flash, we
    // look at loadable segments in the ELF, and find the segment with the
    // lowest address that is both executable and non-zero in file size. Since
    // this is a segment that must be loaded to execute the application, we know
    // that this must be a flash address.
    //
    // For RAM, we can't quite use the ELF file in the same way as with flash.
    // Since nothing _actually_ has to be loaded into RAM, the ELF file does not
    // have to keep track of the first address in RAM. Further, Tock apps
    // typically put a .stack section at the beginning of RAM, and the stack is
    // just a memory holder and doesn't contain any actual data. The start of
    // RAM address will almost certainly exist somewhere in the ELF, but
    // reliably extracting it from different ELFs linked with different
    // toolchains from different linker scripts would I think require resorting
    // to a bit of heuristics and guessing. To avoid the potential issues there,
    // we instead require that a `_sram_origin` symbol be present to explicitly
    // mark the start of RAM.
    //
    // In both cases we check to see if the address matches our expected PIC
    // addresses:
    // - RAM: 0x00000000
    // - flash: 0x80000000
    //
    // These addresses are a Tock convention and enables PIC fixups to be done
    // by the app when it first starts. If for some reason an app is PIC and
    // wants to use different dummy PIC addresses, then this logic will have to
    // be updated.
    let mut fixed_address_flash: Option<u32> = None;
    let mut fixed_address_ram: Option<u32> = None;
    let mut fixed_address_flash_pic: bool = false;

    // Do flash address.
    for segment in &elf_phdrs {
        // Only consider nonzero segments which are set to be loaded.
        if segment.p_type != elf::abi::PT_LOAD || segment.p_filesz == 0 {
            continue;
        }

        // Flash segments have to be marked executable, and we only care about
        // segments that actually contain data to be loaded into flash.
        if (segment.p_flags & elf::abi::PF_X) > 0
            && section_exists_in_segment(&elf_sections, segment)
        {
            // If this is standard Tock PIC, then this virtual address will be
            // at 0x80000000. Otherwise, we interpret this to mean that the
            // binary was compiled for a fixed address in flash. Once we confirm
            // this we do not need to keep checking.
            if segment.p_vaddr == 0x80000000 || fixed_address_flash_pic {
                fixed_address_flash_pic = true;
            } else {
                // We need to see if this segment represents the lowest address
                // in flash that we are going to specify this app needs to be
                // loaded at. To do this we compare this segment to any previous
                // and keep track of the lowest address.
                let segment_start = segment.p_paddr as u32;

                fixed_address_flash = match fixed_address_flash {
                    Some(prev_addr) => {
                        if segment_start < prev_addr {
                            Some(segment_start)
                        } else {
                            Some(prev_addr)
                        }
                    }
                    None => {
                        // We found our first valid segment and haven't set our
                        // lowest address yet, so we do that now.
                        Some(segment_start)
                    }
                };
            }
        }
    }

    // Use the flags to see if we got PIC sections, and clear any other fixed
    // addresses we may have found.
    if fixed_address_flash_pic {
        fixed_address_flash = None;
    }

    // Do RAM address.
    // Get the symbol table section if it exists.
    if let Ok(Some((symtab, sym_strtab))) = elf_file.symbol_table() {
        // We are looking for the `_sram_origin` symbol and its value.
        // If it exists, we try to use it. Otherwise, we just do not try
        // to find a fixed RAM address.
        if let Some(sram_origin) = symtab.iter().find(|sym| {
            let name = sym_strtab
                .get(sym.st_name as usize)
                .expect("Failed to parse symbol name");
            name == "_sram_origin"
        }) {
            let sram_origin_address = sram_origin.st_value as u32;
            if sram_origin_address != 0x00000000 {
                fixed_address_ram = Some(sram_origin_address);
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Create the TBF header
    ////////////////////////////////////////////////////////////////////////////

    // We need to reserve space for the writeable flash region information in
    // the header, so we need to know how many writeable flash regions are in
    // this app. Iterate the segments of the ELF file and then iterate sections
    // within that segment to find sections with ".wfr" in the name.
    let mut writeable_flash_regions_count: usize = 0;
    for segment in &elf_phdrs {
        // Only consider segments which are set to be loaded.
        if segment.p_type != elf::abi::PT_LOAD || segment.p_filesz == 0 {
            continue;
        }

        // We only want nonzero sections within a segment.
        for (sh_name, shdr) in elf_sections.iter() {
            if shdr.sh_size > 0 && section_in_segment(shdr, segment) && sh_name.contains(".wfr") {
                writeable_flash_regions_count += 1;
            }
        }
    }
    if verbose {
        println!(
            "Number of writeable flash regions: {}",
            writeable_flash_regions_count
        );
    }

    // Additional debug information.
    if verbose {
        if let Some((major, minor)) = kernel_version {
            println!("Kernel version: {}.{}", major, minor);
        }
    }

    // Now we can create the first pass TBF header. This is mostly to get the
    // size of the header since we have to fill in some of the offsets later.
    let mut tbfheader = header::TbfHeader::new();

    // Set the binary end offset here because it will cause a program header to
    // be inserted. This ensures the length calculations for the binary will be
    // correct.
    tbfheader.set_binary_end_offset(0);
    tbfheader.set_app_version(app_version);

    let header_length = tbfheader.create(
        minimum_ram_size,
        writeable_flash_regions_count,
        package_name,
        fixed_address_ram,
        fixed_address_flash,
        permissions,
        storage_ids,
        kernel_version,
        disabled,
    );

    ////////////////////////////////////////////////////////////////////////////
    // Adjust the protected region size to make fixed address work
    ////////////////////////////////////////////////////////////////////////////

    // If a protected region size was passed, confirm the header will fit.
    // Otherwise, use the header size as the protected region size.
    let protected_region_size =
        if let Some(fixed_protected_region_size) = protected_region_size_arg {
            if fixed_protected_region_size < header_length as u32 {
                // The header doesn't fit in the provided protected region size;
                // throw an error.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                    "protected_region_size = {} is too small for the TBF headers. Header size: {}",
                    fixed_protected_region_size, header_length),
                ));
            }
            // Update the header's protected size, as the protected region may
            // be larger than the header size.
            tbfheader.set_protected_size(fixed_protected_region_size - header_length as u32);

            fixed_protected_region_size
        } else {
            // The protected region was not specified on the command line.
            // Normally, we default to an additional size of 0 for the protected
            // region beyond the header. However, if we are _not_ doing PIC, we
            // might want to choose a nonzero sized protected region. Without
            // PIC, the application binary must be at specific address. In
            // addition, boards have a fixed address where they start looking
            // for applications. To make both of those addresses match, we can
            // expand the protected region.
            //
            // |----------------------|-------------------|---------------------
            // | TBF Header           | Protected Region  | Application Binary
            // |----------------------|-------------------|---------------------
            // ^                                ^         ^
            // |                                |         |-- Fixed binary address
            // |-- Start of apps address        |-- Flexible size
            //
            // However, we don't actually know the start of apps address.
            // Additionally, an app may be positioned after another app in
            // flash, and so the start address is actually the start of apps
            // address plus the size of the first app. Tockloader when it goes
            // to actually load the app can check for these addresses and expand
            // the protected region as needed. But, in some cases it is easier
            // to just be able to flash the TBF directly onto the board without
            // needing Tockloader. So, we at least try to pick a reasonable
            // protected size in the non-PIC case to give the TBF a chance of
            // working as created.
            //
            // So, we put the start address of the TBF header at an alignment of
            // 256 if the application binary is at the expected address.
            if !fixed_address_flash_pic {
                // Non-PIC case. As a reasonable guess we try to get our TBF
                // start address to be at a 256 byte alignment.
                let app_binary_address = fixed_address_flash.unwrap_or(0); // Already checked for `None`.
                let tbf_start_address = util::align_down(app_binary_address, 256);
                let protected_region_size = app_binary_address - tbf_start_address;
                if protected_region_size > header_length as u32 {
                    // We do want to set the protected size past the header to
                    // something nonzero.
                    if verbose {
                        println!(
                            "Inserting nonzero protected region of length: {} bytes",
                            protected_region_size - header_length as u32
                        );
                    }
                    tbfheader.set_protected_size(protected_region_size - header_length as u32);
                    protected_region_size
                } else {
                    header_length as u32
                }
            } else {
                // Normal PIC case, no need to insert extra protected region.
                header_length as u32
            }
        };

    ////////////////////////////////////////////////////////////////////////////
    // Create the actual binary to include in the TBF
    ////////////////////////////////////////////////////////////////////////////

    // Need a place to put the app sections before we know the true TBF header.
    // This includes everything after the TBF header.
    let mut binary: Vec<u8> = Vec::new();

    // Keep track of an index from the beginning of the TBF binary of where we
    // are in creating the TBF binary.
    let mut binary_index = 0;

    // Add in padding for the protected region size beyond the actual TBF header
    // size and increment our index counter past the protected region.
    binary.extend(vec![0; protected_region_size as usize - header_length]);
    binary_index += protected_region_size as usize;

    // The init function is where the app will start executing, defined as an
    // offset from the end of protected region at the beginning of the app in
    // flash. Typically the protected region only includes the TBF header. To
    // calculate the offset we need to find which section includes the entry
    // function and then determine its offset relative to the end of the
    // protected region.
    let mut init_fn_offset: Option<u32> = None;

    // Need a place to put relocation data.
    let mut relocation_binary: Vec<u8> = Vec::new();

    // Keep track of the end address of the last segment (once we have a first
    // segment). This allows us to insert padding between segments as necessary.
    let mut last_segment_address_end: Option<usize> = None;

    // Iterate over ELF's Program Headers to assemble the binary image as a
    // contiguous memory block. Only take into consideration segments where
    // filesz is greater than 0.
    for segment in &elf_phdrs {
        // Only consider segments which are set to be loaded.
        if segment.p_type != elf::abi::PT_LOAD {
            continue;
        }

        // Do not include segments with zero size, as these likely go in memory,
        // not flash.
        if segment.p_filesz == 0 {
            continue;
        }

        // Insert padding between segments if needed.
        if let Some(last_segment_address_end) = last_segment_address_end {
            // We have a previous segment. Now, check if there is any padding
            // between the segments in the .elf.
            let chk_padding = (segment.p_paddr as usize).checked_sub(last_segment_address_end);

            if let Some(padding) = chk_padding {
                if padding > 0 {
                    if verbose {
                        println!("  Including padding between segments size={}", padding);
                    }

                    if padding >= 4096 {
                        // Warn the user that we're inserting a large amount of
                        // padding (>= 4096, which is the ELF file segment padding)
                        // into the binary. This can be a sign of an incorrect /
                        // broken ELF file (where not all LOADed non-zero sized
                        // sections are marked to be loaded from flash).
                        println!("  Warning! Inserting a large amount of padding.");
                    }

                    // Insert the padding into the generated binary.
                    binary.extend(vec![0; padding]);
                    binary_index += padding;
                }
            } else {
                println!(
                    "  Warning! Expecting ELF sections to be in physical (load) address order."
                );
                println!("           Not inserting padding, the resulting TBF may be broken.");
            }
        }

        if verbose {
            println!(
                "  Adding segment. Offset: {0} ({0:#x}). Length: {1} ({1:#x}) bytes.",
                binary_index, segment.p_filesz
            );
        }

        // Read the segment from the ELF and append to the output binary.
        let mut content: Vec<u8> = vec![0; (segment.p_filesz) as usize];
        input_file
            .seek(SeekFrom::Start(segment.p_offset))
            .expect("unable to seek input ELF file");
        input_file
            .read_exact(&mut content)
            .expect("failed to read segment data");

        let start_segment = segment.p_paddr;
        let end_segment = segment.p_paddr + segment.p_filesz;

        // Check if this segment contains the entry point, and calculate the
        // offset we need to store in the TBF header if so.
        if elf_file.ehdr.e_entry >= start_segment && elf_file.ehdr.e_entry < end_segment {
            if init_fn_offset.is_some() {
                // If the app is disabled just report a warning if we find two
                // entry points. OTBN apps will contain two entry points, so
                // this allows us to load them.
                if disabled {
                    if verbose {
                        println!("Duplicate entry point in Program Segments");
                    }
                } else {
                    panic!("Duplicate entry point in Program Segments");
                }
            } else {
                // Get the position of the entry point in the segment.
                let entry_offset = (elf_file.ehdr.e_entry - start_segment) as usize;
                // `init_fn_offset` is the offset from the end of the TBF header
                // to the entry point within the application binary.
                let tbf_entry_offset = (binary_index + entry_offset - header_length) as u32;
                // Set the init_fn in the header.
                tbfheader.set_init_fn_offset(tbf_entry_offset);
                // Save it in case we find multiple entry points.
                init_fn_offset = Some(tbf_entry_offset);
            }
        }

        // Iterate all sections that are in the segment we just loaded.
        //
        // We need two things:
        // 1. To find all relevant relocation data we need to add.
        // 2. To find if there are any writeable flash regions we need to set in
        //    the TBF header.
        for (sh_name, shdr) in elf_sections.iter() {
            // Skip zero size sections.
            if shdr.sh_size == 0 {
                continue;
            }

            // Check if this section is within the segment.
            if section_in_segment(shdr, segment) {
                // This section is in this segment.
                if verbose {
                    println!(
                        "    Contains section {0}. Offset: {1} ({1:#x}). Length: {2} ({2:#x}) bytes.",
                        sh_name,
                        binary_index + (shdr.sh_offset - segment.p_offset) as usize,
                        shdr.sh_size
                    );
                }

                // First, determine if we need to check for relocation data for
                // this section. The section must be marked `SHF_WRITE`, as to
                // use the relocations at runtime requires being able to update
                // the contents of the section.
                if shdr.sh_flags as u32 & elf::abi::SHF_WRITE > 0 {
                    // Then check if there is a ".rel.<section name>" section
                    // that we need to include in the relocation data.

                    // relocation_section_name = ".rel" + section_name
                    let mut relocation_section_name: String = ".rel".to_owned();
                    relocation_section_name.push_str(sh_name);

                    // Get the contents of the relocation data if it exists and
                    // add that data to a buffer of relocation data.
                    let rel_data = elf_sections
                        .iter()
                        .find(|(sh_name, _)| *sh_name == relocation_section_name)
                        .map_or(&[] as &[u8], |(_, shdr)| {
                            elf_file.section_data(shdr).map_or(&[], |(data, _)| data)
                        });
                    relocation_binary.extend(rel_data);

                    if verbose && !rel_data.is_empty() {
                        println!(
                            "      Including relocation data ({0}). Length: {1} ({1:#x}) bytes.",
                            relocation_section_name,
                            rel_data.len(),
                        );
                    }
                }

                // Second, check if this is a writeable flash region and if so,
                // include its details in the TBF header.
                if sh_name.contains(".wfr") {
                    // Calculate where this .wfr section is in the segment.
                    let wfr_offset = (shdr.sh_addr - segment.p_vaddr) as usize;
                    // Calculate the position of the writeable flash region in
                    // the TBF binary.
                    let wfr_position = binary_index + wfr_offset;

                    // Use these values to update the TBF header.
                    tbfheader.set_writeable_flash_region_values(
                        wfr_position as u32,
                        shdr.sh_size as u32,
                    );
                }
            }
        }

        // Save the end of this segment so we can check if padding is required
        // between segments.
        last_segment_address_end = Some(end_segment as usize);

        binary.extend(content);
        binary_index += segment.p_filesz as usize;
    }

    // Now that we know where the end of the section data is, we can check for
    // alignment.
    if !relocation_binary.is_empty() && amount_alignment_needed(binary_index as u32, 4) != 0 {
        println!(
            "Warning! Placing relocation data at {:#x}, which is not 4-byte aligned.",
            binary_index
        );
    }

    // Add 4 bytes for the relocation data length and the size of the relocation
    // data to our total length.
    binary_index += mem::size_of::<u32>() + relocation_binary.len();

    ////////////////////////////////////////////////////////////////////////////
    // Create the TBF footer
    ////////////////////////////////////////////////////////////////////////////

    // Next up is the footer. Since we know where the footer starts, we can
    // record that now. Also insert app version number.
    tbfheader.set_binary_end_offset(binary_index as u32);
    tbfheader.set_app_version(app_version);

    // Process optional footers
    if sha256 {
        binary_index += mem::size_of::<header::TbfHeaderTlv>();
        binary_index += mem::size_of::<header::TbfFooterCredentialsType>();
        binary_index += 32; // SHA256 is 32 bytes long
    }

    if sha384 {
        binary_index += mem::size_of::<header::TbfHeaderTlv>();
        binary_index += mem::size_of::<header::TbfFooterCredentialsType>();
        binary_index += 48; // SHA384 is 48 bytes long
    }

    if sha512 {
        binary_index += mem::size_of::<header::TbfHeaderTlv>();
        binary_index += mem::size_of::<header::TbfFooterCredentialsType>();
        binary_index += 64; // SHA512 is 64 bytes long
    }

    if rsa4096_private_key.is_some() {
        binary_index += mem::size_of::<header::TbfHeaderTlv>();
        binary_index += mem::size_of::<header::TbfFooterCredentialsType>();
        binary_index += 1024;
    }

    let footers_initial_len = binary_index - tbfheader.binary_end_offset() as usize;

    // Make sure the footer is at least the minimum requested size.
    if (minimum_footer_size as usize) > footers_initial_len {
        let mut needed_footer_reserved_space = (minimum_footer_size as usize) - footers_initial_len;

        // We can only add reserved space to the footer with a minimum of 8
        // bytes.
        needed_footer_reserved_space = cmp::max(
            needed_footer_reserved_space,
            mem::size_of::<header::TbfHeaderTlv>()
                + mem::size_of::<header::TbfFooterCredentialsType>(),
        );
        // We also must ensure that if there were to be a TLV after the
        // reserved TLV that it would start at a 4 byte alignment.
        needed_footer_reserved_space = align_to(needed_footer_reserved_space as u32, 4) as usize;

        // Add reserved space to the footer.
        binary_index += needed_footer_reserved_space;
    }

    // Optionally calculate the additional padding needed to ensure the app size
    // meets the padding requirements.
    //
    // This will be largely covered with a footer reservation. The
    // `post_content_pad` is any additional space that cannot be handled by
    // reserved space in the footer.
    let post_content_pad = trailing_padding.map_or(0, |padding_type| {
        // Calculate how many additional bytes we need to add to meet length
        // requirement.
        let pad = match padding_type {
            TrailingPadding::TotalSizePowerOfTwo => {
                // Pad binary to the next power of two, but not less than 512
                // bytes.
                if binary_index.count_ones() > 1 {
                    let power2len =
                        cmp::max(1 << (32 - (binary_index as u32).leading_zeros()), 512);
                    power2len - binary_index
                } else {
                    0
                }
            }
            TrailingPadding::TotalSizeMultiple(multiple) => {
                (multiple - (binary_index % multiple)) % multiple
            }
        };

        // Increment to include the padding.
        binary_index += pad;

        // If there is room for a TbfFooterCredentials we will use that.
        if pad
            >= (mem::size_of::<header::TbfHeaderTlv>()
                + mem::size_of::<header::TbfFooterCredentialsType>())
        {
            0
        } else {
            // Otherwise need to include the padding.
            pad
        }
    });

    let total_size = binary_index;

    // Now set the total size of the app in the header.
    tbfheader.set_total_size(total_size as u32);

    if verbose {
        print!("{}", tbfheader);
    }

    // Write the header and actual app to a binary file.
    output.write_all(tbfheader.generate().unwrap().get_ref())?;
    output.write_all(binary.as_ref())?;

    let rel_data_len: [u8; 4] = (relocation_binary.len() as u32).to_le_bytes();
    output.write_all(&rel_data_len)?;
    output.write_all(relocation_binary.as_ref())?;

    // That is everything that we are going to include in the app binary
    // that is covered by integrity. Now add footers.

    let footers_len = total_size - tbfheader.binary_end_offset() as usize;
    let mut footer_space_remaining = footers_len;
    if sha256 {
        // Total length
        let sha256_len = mem::size_of::<header::TbfHeaderTlv>()
            + mem::size_of::<header::TbfFooterCredentialsType>()
            + 32; // SHA256 is 32 bytes long
                  // Length in the TLV field
        let sha256_tlv_len = sha256_len - mem::size_of::<header::TbfHeaderTlv>();

        let mut hasher = Sha256::new();
        hasher.update(&output[0..tbfheader.binary_end_offset() as usize]);
        let result = hasher.finalize();
        let sha_credentials = header::TbfFooterCredentials {
            base: header::TbfHeaderTlv {
                tipe: header::TbfHeaderTypes::Credentials,
                length: sha256_tlv_len as u16,
            },
            format: header::TbfFooterCredentialsType::SHA256,
            data: result.to_vec(),
        };
        output.write_all(sha_credentials.generate().unwrap().get_ref())?;
        footer_space_remaining -= sha256_len;
        if verbose {
            println!("Added SHA256 credential.");
        }
    }

    if sha384 {
        // Total length
        let sha384_len = mem::size_of::<header::TbfHeaderTlv>()
            + mem::size_of::<header::TbfFooterCredentialsType>()
            + 48; // SHA384 is 48 bytes long
                  // Length in the TLV field
        let sha384_tlv_len = sha384_len - mem::size_of::<header::TbfHeaderTlv>();

        let mut hasher = Sha384::new();
        hasher.update(&output[0..tbfheader.binary_end_offset() as usize]);
        let result = hasher.finalize();
        let sha_credentials = header::TbfFooterCredentials {
            base: header::TbfHeaderTlv {
                tipe: header::TbfHeaderTypes::Credentials,
                length: sha384_tlv_len as u16,
            },
            format: header::TbfFooterCredentialsType::SHA384,
            data: result.to_vec(),
        };
        output.write_all(sha_credentials.generate().unwrap().get_ref())?;
        footer_space_remaining -= sha384_len;
        if verbose {
            println!("Added SHA384 credential.");
        }
    }

    if sha512 {
        // Total length
        let sha512_len = mem::size_of::<header::TbfHeaderTlv>()
            + mem::size_of::<header::TbfFooterCredentialsType>()
            + 64; // SHA512 is 64 bytes long
                  // Length in the TLV field
        let sha512_tlv_len = sha512_len - mem::size_of::<header::TbfHeaderTlv>();

        let mut hasher = Sha512::new();
        hasher.update(&output[0..tbfheader.binary_end_offset() as usize]);
        let result = hasher.finalize();
        let sha_credentials = header::TbfFooterCredentials {
            base: header::TbfHeaderTlv {
                tipe: header::TbfHeaderTypes::Credentials,
                length: sha512_tlv_len as u16,
            },
            format: header::TbfFooterCredentialsType::SHA512,
            data: result.to_vec(),
        };
        output.write_all(sha_credentials.generate().unwrap().get_ref())?;
        footer_space_remaining -= sha512_len;
        if verbose {
            println!("Added SHA512 credential.");
        }
    }

    if rsa4096_private_key.is_some() && rsa4096_public_key.is_none() {
        panic!("RSA4096 private key provided but no corresponding public key provided.");
    }
    if rsa4096_private_key.is_none() && rsa4096_public_key.is_some() {
        panic!("RSA4096 public key provided but no corresponding private key provided.");
    } else if rsa4096_private_key.is_some() && rsa4096_private_key.is_some() {
        let rsa4096_len = mem::size_of::<header::TbfHeaderTlv>()
            + mem::size_of::<header::TbfFooterCredentialsType>()
            + 1024; // Signature + key is 1024 bytes long
                    // Length in the TLV field
        let rsa4096_tlv_len = rsa4096_len - mem::size_of::<header::TbfHeaderTlv>();

        let private_buf = rsa4096_private_key.unwrap();
        let private_key_path = Path::new(&private_buf);
        let public_buf = rsa4096_public_key.unwrap();
        let public_key_path = Path::new(&public_buf);

        let private_key_der = read_rsa_file(private_key_path)
            .map_err(|e| {
                panic!(
                    "Failed to read private key from {:?}: {:?}",
                    private_key_path, e
                );
            })
            .unwrap();

        let public_key_der = read_rsa_file(public_key_path)
            .map_err(|e| {
                panic!(
                    "Failed to read public key from {:?}: {:?}",
                    public_key_path, e
                );
            })
            .unwrap();

        let key_pair = signature::RsaKeyPair::from_der(&private_key_der)
            .map_err(|e| {
                panic!("RSA4096 could not be parsed: {:?}", e);
            })
            .unwrap();

        let public_key = rsa_der::public_key_from_der(&public_key_der);

        let public_modulus = match public_key {
            Ok((n, _)) => n,
            Err(_) => {
                panic!("RSA4096 signature requested but provided public key could not be parsed.");
            }
        };

        if key_pair.public_modulus_len() != 512 {
            // A 4096-bit key should have a 512-byte modulus
            panic!(
                "RSA4096 signature requested but key {:?} is not 4096 bits, it is {} bits",
                private_key_path,
                private_key_der.len() * 8
            );
        }
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; key_pair.public_modulus_len()];
        let _res = key_pair
            .sign(
                &signature::RSA_PKCS1_SHA512,
                &rng,
                &output[0..tbfheader.binary_end_offset() as usize],
                &mut signature,
            )
            .map_err(|e| {
                panic!("Could not generate RSA4096 signature: {:?}", e);
            });
        let mut credentials = vec![0; 1024];
        for i in 0..key_pair.public_modulus_len() {
            credentials[i] = public_modulus[i];
        }
        for i in 0..signature.len() {
            let index = i + key_pair.public_modulus_len();
            credentials[index] = signature[i];
        }

        let rsa4096_credentials = header::TbfFooterCredentials {
            base: header::TbfHeaderTlv {
                tipe: header::TbfHeaderTypes::Credentials,
                length: rsa4096_tlv_len as u16,
            },
            format: header::TbfFooterCredentialsType::Rsa4096Key,
            data: credentials,
        };

        output.write_all(rsa4096_credentials.generate().unwrap().get_ref())?;
        footer_space_remaining -= rsa4096_len;
        if verbose {
            println!("Added PKCS#1v1.5 RSA4096 signature credential.");
        }
    }

    let padding_len = footer_space_remaining;

    // Need at least space for the base Credentials TLV.
    if padding_len
        >= (mem::size_of::<header::TbfHeaderTlv>()
            + mem::size_of::<header::TbfFooterCredentialsType>())
    {
        let padding_tlv_len = padding_len - mem::size_of::<header::TbfHeaderTlv>();
        let reserved_len = padding_tlv_len - mem::size_of::<header::TbfFooterCredentialsType>();
        let reserved_vec = vec![0u8; reserved_len];
        let padding_credentials = header::TbfFooterCredentials {
            base: header::TbfHeaderTlv {
                tipe: header::TbfHeaderTypes::Credentials,
                length: padding_tlv_len as u16,
            },
            format: header::TbfFooterCredentialsType::Reserved,
            data: reserved_vec,
        };
        let creds = padding_credentials.generate().unwrap();
        output.write_all(creds.get_ref())?;
    }

    // Pad to get a power of 2 sized flash app, if requested.
    util::do_pad(output, post_content_pad as usize)?;

    Ok(())
}
