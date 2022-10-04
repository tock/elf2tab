use crate::header;
use crate::util::{self, align_to, amount_alignment_needed};
use ring::{rand, signature};
use rsa_der;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::cmp;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::path::{Path, PathBuf};

/// Helper function for reading RSA DER key files.
fn read_rsa_file(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

/// Convert an ELF file to a TBF (Tock Binary Format) binary file.
///
/// This will place all writeable and executable sections from the ELF file
/// into a binary and prepend a TBF header to it. For all writeable sections,
/// if there is a .rel.X section it will be included at the end with a 32 bit
/// length parameter first.
///
/// Assumptions:
/// - Any segments that are writable and set to be loaded into flash but with a
///   different virtual address will be in RAM and should count towards minimum
///   required RAM.
/// - Sections that are writeable flash regions include .wfr in their name.
pub fn elf_to_tbf(
    input: &elf::File,
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
    trailing_padding: bool,
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

    // Get an array of the sections sorted so we place them in the proper order
    // in the binary.
    let mut sections_sort: Vec<(usize, usize)> = Vec::new();
    for (i, section) in input.sections.iter().enumerate() {
        sections_sort.push((i, section.shdr.offset as usize));
    }
    sections_sort.sort_by_key(|s| s.1);

    let stack_len = stack_len
        // not provided, read from binary
        .or_else(|| {
            input.sections.iter().find_map(|section| {
                if section.shdr.name == ".stack" {
                    Some(section.shdr.size as u32)
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
    for segment in &input.phdrs {
        // To filter, we need segments that are:
        // - Set to be LOADed.
        // - Have different virtual and physical addresses, meaning they are
        //   loaded into flash but actually reside in memory.
        // - Are not zero size in memory.
        // - Are writable (RAM should be writable).
        if segment.progtype == elf::types::PT_LOAD
            && segment.vaddr != segment.paddr
            && segment.memsz > 0
            && ((segment.flags.0 & elf::types::PF_W.0) > 0)
        {
            minimum_ram_size += segment.memsz as u32;
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

    /// Helper function to determine if any nonzero length section is inside a
    /// given segment.
    ///
    /// This is necessary because we sometimes run into loadable segments that
    /// shouldn't really exist (they are at addresses outside of what was
    /// specified in the linker script), and we want to be able to skip them.
    fn section_exists_in_segment(input: &elf::File, segment: &elf::types::ProgramHeader) -> bool {
        let segment_start = segment.offset as u32;
        let segment_size = segment.filesz as u32;
        let segment_end = segment_start + segment_size;

        for section in input.sections.iter() {
            let section_start = section.shdr.offset as u32;
            let section_size = section.shdr.size as u32;
            let section_end = section_start + section_size;

            if section_start >= segment_start && section_end <= segment_end && section_size > 0 {
                return true;
            }
        }
        false
    }

    /// Helper function to find the address of the first section inside a given
    /// segment.
    ///
    /// This is necessary because the flash segment is not guaranteed
    /// to start at the same address as the first section.
    fn find_first_section_address_in_segment<'a>(
        input: &'a elf::File,
        segment: &elf::types::ProgramHeader,
    ) -> Option<u32> {
        let segment_start = segment.offset as u32;
        let segment_size = segment.filesz as u32;
        let segment_end = segment_start + segment_size;

        let mut first_section_address: Option<u32> = None;
        for section in input.sections.iter() {
            let section_start = section.shdr.offset as u32;
            let section_size = section.shdr.size as u32;
            let section_end = section_start + section_size;

            if section_start >= segment_start && section_end <= segment_end && section_size > 0 {
                first_section_address = match first_section_address {
                    Some(first_address) => Some(cmp::min(first_address, section.shdr.addr as u32)),
                    None => Some(section.shdr.addr as u32),
                };
            }
        }
        first_section_address
    }

    // Do flash address.
    for segment in &input.phdrs {
        match segment.progtype {
            elf::types::PT_LOAD => {
                // Look for segments based on their flags, size, and whether
                // they actually contain any valid sections. Flash segments have
                // to be marked executable, and we only care about segments that
                // actually contain data to be loaded into flash.
                if (segment.flags.0 & elf::types::PF_X.0) > 0
                    && segment.filesz > 0
                    && section_exists_in_segment(input, segment)
                {
                    // If this is standard Tock PIC, then this virtual address
                    // will be at 0x80000000. Otherwise, we interpret this to
                    // mean that the binary was compiled for a fixed address in
                    // flash. Once we confirm this we do not need to keep
                    // checking.
                    if segment.vaddr == 0x80000000 || fixed_address_flash_pic {
                        fixed_address_flash_pic = true;
                    } else {
                        // We need to see if this segment represents the lowest
                        // address in flash that we are going to specify this
                        // app needs to be loaded at. To do this we compare this
                        // segment to any previous and keep track of the lowest
                        // address. However, we need to use the address of the
                        // first _section_ in the segment, not just the address
                        // of the segment, because a linker may insert padding.
                        let segment_start = find_first_section_address_in_segment(input, segment);

                        fixed_address_flash = match (fixed_address_flash, segment_start) {
                            (Some(prev_addr), Some(segment_start)) => {
                                // We already found a candidate, and we found a
                                // new candidate. Keep looking for the lowest
                                // address.
                                Some(cmp::min(prev_addr, segment_start))
                            }
                            (None, Some(segment_start)) => {
                                // We found our first valid segment and haven't set our
                                // lowest address yet, so we do that now.
                                Some(segment_start)
                            }
                            (prev_addr, None) => {
                                // We can't use this segment, so skip.
                                prev_addr
                            }
                        };
                    }
                }
            }

            _ => {}
        }
    }
    // Use the flags to see if we got PIC sections, and clear any other fixed
    // addresses we may have found.
    if fixed_address_flash_pic {
        fixed_address_flash = None;
    }

    // Do RAM address.
    // Get all symbols in the symbol table section if it exists.
    let section_symtab = input.sections.iter().find(|s| s.shdr.name == ".symtab");
    section_symtab.map(|s_symtab| {
        let symbols = input.get_symbols(s_symtab);
        symbols.ok().map(|syms| {
            // We are looking for the `_sram_origin` symbol and its value.
            // If it exists, we try to use it. Otherwise, we just do not try
            // to find a fixed RAM address.
            let sram_origin_symbol = syms.iter().find(|sy| sy.name == "_sram_origin");
            sram_origin_symbol.map(|sram_origin| {
                let sram_origin_address = sram_origin.value as u32;
                // If address does not match our dummy address for PIC, then we
                // say this app has a fixed address for memory.
                if sram_origin_address != 0x00000000 {
                    fixed_address_ram = Some(sram_origin_address);
                }
            });
        });
    });

    // Need an array of sections to look for relocation data to include.
    let mut rel_sections: Vec<String> = Vec::new();

    // Iterate the sections in the ELF file to find properties of the app that
    // are required to go in the TBF header.
    let mut writeable_flash_regions_count = 0;

    for s in &sections_sort {
        let section = &input.sections[s.0];

        // Count write only sections as writeable flash regions.
        if section.shdr.name.contains(".wfr") && section.shdr.size > 0 {
            writeable_flash_regions_count += 1;
        }

        // Check write+alloc sections for possible .rel.X sections.
        if section.shdr.flags.0 == elf::types::SHF_WRITE.0 + elf::types::SHF_ALLOC.0 {
            // This section is also one we might need to include relocation
            // data for.
            rel_sections.push(section.shdr.name.clone());
        }
    }
    if verbose {
        println!(
            "Number of writeable flash regions: {}",
            writeable_flash_regions_count
        );
    }

    if verbose {
        if let Some((major, minor)) = kernel_version {
            println!("Kernel version: {}.{}", major, minor);
        }
    }

    // Keep track of an index of where we are in creating the app binary.
    let mut binary_index = 0;

    // Now we can create the first pass TBF header. This is mostly to get the
    // size of the header since we have to fill in some of the offsets later.
    let mut tbfheader = header::TbfHeader::new();

    // Set the binary end offset here because it will cause a program
    // header to be inserted. This ensures the length calculations for
    // the binary will be correct.
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
    binary_index += protected_region_size as usize;

    // The init function is where the app will start executing, defined as an
    // offset from the end of protected region at the beginning of the app in
    // flash. Typically the protected region only includes the TBF header. To
    // calculate the offset we need to find which section includes the entry
    // function and then determine its offset relative to the end of the
    // protected region.
    let mut init_fn_offset: u32 = 0;

    // Need a place to put the app sections before we know the true TBF header.
    let mut binary: Vec<u8> = vec![0; protected_region_size as usize - header_length];

    let mut entry_point_found = false;

    let mut last_section_address_end: Option<usize> = None;

    let mut start_address: u64 = 0;

    // Iterate over ELF's Program Headers to assemble the binary image as a contiguous
    // memory block. Only take into consideration segments where filesz is greater than 0
    for segment in &input.phdrs {
        match segment.progtype {
            elf::types::PT_LOAD => {
                if segment.filesz > 0 {
                    if last_section_address_end.is_some() {
                        // We have a previous section. Now, check if there is any
                        // padding between the sections in the .elf.
                        let padding = segment.paddr as usize - last_section_address_end.unwrap();
                        if padding < 1024 {
                            if padding > 0 {
                                if verbose {
                                    println!("Padding between Program Segments of {}", padding);
                                }
                            }

                            let zero_buf = [0_u8; 1024];
                            binary.extend(&zero_buf[..padding]);
                            binary_index += padding;
                        } else {
                            println!(
                                "Warning! Padding to Program segment is too large ({} bytes).",
                                padding
                            );
                        }
                    } else {
                        // This is the first segment, take the Physical Address as the starting
                        // point to compute offsets from
                        start_address = segment.paddr;
                    }

                    // read the input file and append to the output binary
                    input_file
                        .seek(SeekFrom::Start(segment.offset))
                        .expect("unable to seek input file");

                    let mut content: Vec<u8> = vec![0; segment.filesz as usize];
                    input_file
                        .read_exact(&mut content)
                        .expect("failed to read segment data");
                    binary.extend(content);

                    // verify if this segment contains the entry point
                    let start_segment = segment.paddr;
                    let end_segment = segment.paddr + segment.filesz;

                    if input.ehdr.entry >= start_segment && input.ehdr.entry < end_segment {
                        if entry_point_found {
                            // If the app is disabled just report a warning if we find
                            // two entry points. OTBN apps will contain two entry
                            // points, so this allows us to load them.
                            if disabled {
                                if verbose {
                                    println!("Duplicate entry point in Program Segments");
                                }
                            } else {
                                panic!("Duplicate entry point in Program Segments");
                            }
                        } else {
                            init_fn_offset = (input.ehdr.entry - start_address) as u32
                                + (binary_index - header_length) as u32;
                            entry_point_found = true;
                        }
                    }

                    last_section_address_end = Some(end_segment as usize);
                    binary_index += segment.filesz as usize;
                }
            }
            _ => {}
        }
    }

    // iterate over sections to look for writable flash regions
    for s in &sections_sort {
        let section = &input.sections[s.0];
        if (section.shdr.flags.0
            & (elf::types::SHF_WRITE.0 + elf::types::SHF_EXECINSTR.0 + elf::types::SHF_ALLOC.0)
            != 0)
            && section.shdr.shtype == elf::types::SHT_PROGBITS
            && section.shdr.size > 0
        {
            // Check if this is a writeable flash region. If so, we need to
            // set the offset and size in the header.
            if section.shdr.name.contains(".wfr") && section.shdr.size > 0 {
                tbfheader.set_writeable_flash_region_values(
                    binary_index as u32,
                    section.shdr.size as u32,
                );
            }
        }
    }

    // Now that we have checked all of the sections, we can set the
    // init_fn_offset.
    tbfheader.set_init_fn_offset(init_fn_offset);

    // Next we have to add in any relocation data.
    let mut relocation_binary: Vec<u8> = Vec::new();

    // For each section that might have relocation data, check if a .rel.X
    // section exists and if so include it.
    if verbose {
        println!("Searching for .rel.X sections to add.");
    }
    for relocation_section_name in &rel_sections {
        let mut name: String = ".rel".to_owned();
        name.push_str(relocation_section_name);

        let rel_data = input
            .sections
            .iter()
            .find(|section| section.shdr.name == name)
            .map_or(&[] as &[u8], |section| section.data.as_ref());

        relocation_binary.extend(rel_data);

        if verbose && !rel_data.is_empty() {
            println!(
                "  Adding {0} section. Offset: {1} ({1:#x}). Length: {2} ({2:#x}) bytes.",
                name,
                binary_index + mem::size_of::<u32>() + rel_data.len(),
                rel_data.len(),
            );
        }
        if !rel_data.is_empty() && amount_alignment_needed(binary_index as u32, 4) != 0 {
            println!(
                "Warning! Placing section {} at {:#x}, which is not 4-byte aligned.",
                name, binary_index
            );
        }
    }

    // Add the relocation data to our total length. Also include the
    // 4 bytes for the relocation data length.
    binary_index += relocation_binary.len() + mem::size_of::<u32>();

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
    // is a power of two. This will be largely covered with a footer
    // reservation. The `post_content_pad` is any additional space that cannot
    // be handled by reserved space in the footer.
    let post_content_pad = if trailing_padding {
        // If trailing padding is requested, we need to pad the binary to a
        // power of 2 in size, and make sure it is at least 512 bytes in size.
        let pad = if binary_index.count_ones() > 1 {
            let power2len = cmp::max(1 << (32 - (binary_index as u32).leading_zeros()), 512);
            power2len - binary_index
        } else {
            0
        };
        // Increment to include the padding.
        binary_index += pad;

        // If there is room for a TbfFooterCredentials we will use that
        if pad
            >= (mem::size_of::<header::TbfHeaderTlv>()
                + mem::size_of::<header::TbfFooterCredentialsType>())
        {
            0
        } else {
            // Otherwise need to include the padding.
            pad
        }
    } else {
        // No padding.
        0
    };

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
        let mut reserved_vec = Vec::<u8>::with_capacity(reserved_len);
        reserved_vec.resize(reserved_len, 0);
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
