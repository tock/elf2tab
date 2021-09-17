use crate::util;
use std::fmt;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::vec;
use util::amount_alignment_needed;

#[repr(u16)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum TbfHeaderTypes {
    Main = 1,
    WriteableFlashRegions = 2,
    PackageName = 3,
    PicOption1 = 4,
    FixedAddresses = 5,
    Permissions = 6,
    KernelVersion = 8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderTlv {
    tipe: TbfHeaderTypes,
    length: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderBase {
    version: u16,
    header_size: u16,
    total_size: u32,
    flags: u32,
    checksum: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderMain {
    base: TbfHeaderTlv,
    init_fn_offset: u32,
    protected_size: u32,
    minimum_ram_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderWriteableFlashRegion {
    base: TbfHeaderTlv,
    offset: u32,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderFixedAddresses {
    base: TbfHeaderTlv,
    start_process_ram: u32,
    start_process_flash: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderDriverPermission {
    driver_number: u32,
    offset: u32,
    allowed_commands: u64,
}

#[repr(C)]
#[derive(Debug)]
struct TbfHeaderPermissions {
    base: TbfHeaderTlv,
    length: u16,
    perms: Vec<TbfHeaderDriverPermission>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderKernelVersion {
    base: TbfHeaderTlv,
    major: u16,
    minor: u16,
}

impl fmt::Display for TbfHeaderBase {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
               version: {0:>8} {0:>#10X}
           header_size: {1:>8} {1:>#10X}
            total_size: {2:>8} {2:>#10X}
                 flags: {3:>8} {3:>#10X}",
            self.version, self.header_size, self.total_size, self.flags,
        )
    }
}

impl fmt::Display for TbfHeaderMain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
        init_fn_offset: {0:>8} {0:>#10X}
        protected_size: {1:>8} {1:>#10X}
      minimum_ram_size: {2:>8} {2:>#10X}",
            self.init_fn_offset, self.protected_size, self.minimum_ram_size,
        )
    }
}

impl fmt::Display for TbfHeaderWriteableFlashRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
    flash region:
                offset: {0:>8} {0:>#10X}
                  size: {1:>8} {1:>#10X}",
            self.offset, self.size,
        )
    }
}

impl fmt::Display for TbfHeaderFixedAddresses {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
     start_process_ram: {0:>8} {0:>#10X}
   start_process_flash: {1:>8} {1:>#10X}",
            self.start_process_ram, self.start_process_flash,
        )
    }
}

impl fmt::Display for TbfHeaderPermissions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "
    driver permissions: {0:>8}
           permissions:   Number   Offset  Allowed Bit Mask",
            self.length,
        )?;

        for perm in &self.perms {
            writeln!(
                f,
                "                      : {0:>#8X} {1:>#8} {2:>#17X}",
                perm.driver_number, perm.offset, perm.allowed_commands,
            )?;
        }
        Ok(())
    }
}

impl fmt::Display for TbfHeaderKernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // ^x.y means >= x.y, < (x+1).0
        writeln!(
            f,
            "
    kernel version: ^{}.{}",
            self.major, self.minor
        )
    }
}

pub struct TbfHeader {
    hdr_base: TbfHeaderBase,
    hdr_main: TbfHeaderMain,
    hdr_pkg_name_tlv: Option<TbfHeaderTlv>,
    hdr_wfr: Vec<TbfHeaderWriteableFlashRegion>,
    hdr_fixed_addresses: Option<TbfHeaderFixedAddresses>,
    hdr_permissions: Option<TbfHeaderPermissions>,
    hdr_kernel_version: Option<TbfHeaderKernelVersion>,
    package_name: String,
    package_name_pad: usize,
}

impl TbfHeader {
    pub fn new() -> Self {
        Self {
            hdr_base: TbfHeaderBase {
                version: 2, // Current version is 2.
                header_size: 0,
                total_size: 0,
                flags: 0,
                checksum: 0,
            },
            hdr_main: TbfHeaderMain {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::Main,
                    length: (mem::size_of::<TbfHeaderMain>() - mem::size_of::<TbfHeaderTlv>())
                        as u16,
                },
                init_fn_offset: 0,
                protected_size: 0,
                minimum_ram_size: 0,
            },
            hdr_pkg_name_tlv: None,
            hdr_wfr: Vec::new(),
            hdr_fixed_addresses: None,
            hdr_permissions: None,
            hdr_kernel_version: None,
            package_name: String::new(),
            package_name_pad: 0,
        }
    }

    /// Start creating the Tock Binary Format Header. This function expects
    /// a few parameters that should be known very easily. Other values that
    /// we need to create the header (like the location of things in the flash
    /// binary) can be passed in later after we know the size of the header.
    ///
    /// Returns: The length of the header in bytes. The length is guaranteed
    ///          to be a multiple of 4.
    pub fn create(
        &mut self,
        minimum_ram_size: u32,
        writeable_flash_regions: usize,
        package_name: String,
        fixed_address_ram: Option<u32>,
        fixed_address_flash: Option<u32>,
        permissions: Vec<(u32, u32)>,
        kernel_version: Option<(u16, u16)>,
    ) -> usize {
        // Need to calculate lengths ahead of time.
        // Need the base and the main section.
        let mut header_length = mem::size_of::<TbfHeaderBase>() + mem::size_of::<TbfHeaderMain>();

        // If we have a package name, add that section.
        self.package_name_pad = if !package_name.is_empty() {
            // Header increases by the TLV and name length.
            header_length += mem::size_of::<TbfHeaderTlv>() + package_name.len();
            // How much padding is needed to ensure we are aligned to 4?
            let pad = amount_alignment_needed(header_length as u32, 4);
            // Header length increases by that padding
            header_length += pad as usize;
            pad as usize
        } else {
            0
        };

        // Add room for the writeable flash regions header TLV.
        header_length += mem::size_of::<TbfHeaderWriteableFlashRegion>() * writeable_flash_regions;

        // Check if we are going to include the fixed address header. If so, we
        // need to make sure we include it in the length. If either address is
        // set we need to include the entire header.
        if fixed_address_ram.is_some() || fixed_address_flash.is_some() {
            header_length += mem::size_of::<TbfHeaderFixedAddresses>();
        }

        // Check if we have to include a kernel version header.
        if kernel_version.is_some() {
            header_length += mem::size_of::<TbfHeaderKernelVersion>();
        }

        // Flags default to app is enabled.
        let flags = 0x0000_0001;

        // Fill in the fields that we can at this point.
        self.hdr_base.header_size = header_length as u16;
        self.hdr_base.flags = flags;
        self.hdr_main.minimum_ram_size = minimum_ram_size;

        // If a package name exists, keep track of it and add it to the header.
        self.package_name = package_name;
        if !self.package_name.is_empty() {
            self.hdr_pkg_name_tlv = Some(TbfHeaderTlv {
                tipe: TbfHeaderTypes::PackageName,
                length: self.package_name.len() as u16,
            });
        }

        // If there is an app state region, start setting up that header.
        for _ in 0..writeable_flash_regions {
            self.hdr_wfr.push(TbfHeaderWriteableFlashRegion {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::WriteableFlashRegions,
                    length: 8,
                },
                offset: 0,
                size: 0,
            });
        }

        // If at least one RAM of flash address is fixed, include the header.
        if fixed_address_ram.is_some() || fixed_address_flash.is_some() {
            self.hdr_fixed_addresses = Some(TbfHeaderFixedAddresses {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::FixedAddresses,
                    length: 8,
                },
                start_process_ram: fixed_address_ram.unwrap_or(0xFFFFFFFF),
                start_process_flash: fixed_address_flash.unwrap_or(0xFFFFFFFF),
            });
        }

        let mut perms: Vec<TbfHeaderDriverPermission> = Vec::new();
        for perm in permissions {
            let offset = perm.1 / 64;
            let allowed_command = 1 << (perm.1 % 64);
            let mut complete = false;

            for p in &mut perms {
                if p.driver_number == perm.0 && p.offset == offset {
                    p.allowed_commands |= allowed_command;
                    complete = true;
                }
            }

            if !complete {
                perms.push(TbfHeaderDriverPermission {
                    driver_number: perm.0,
                    offset: perm.1 / 64,
                    allowed_commands: allowed_command,
                })
            }
        }

        if perms.len() > 0 {
            self.hdr_permissions = Some(TbfHeaderPermissions {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::Permissions,
                    length: (perms.len() * mem::size_of::<TbfHeaderDriverPermission>()) as u16 + 2,
                },
                length: perms.len() as u16,
                perms,
            });
        }

        // If the kernel version is set, we have to include the header.
        if let Some((kernel_major, kernel_minor)) = kernel_version {
            self.hdr_kernel_version = Some(TbfHeaderKernelVersion {
                base: TbfHeaderTlv {
                    tipe: TbfHeaderTypes::KernelVersion,
                    length: 4,
                },
                major: kernel_major,
                minor: kernel_minor,
            });
        }

        // Return the length by generating the header and seeing how long it is.
        self.generate()
            .expect("No header was generated")
            .get_ref()
            .len()
    }

    /// Update the header with the correct protected_size. protected_size should
    /// not include the size of the header itself (as defined in the Main TLV
    /// element type).
    pub fn set_protected_size(&mut self, protected_size: u32) {
        self.hdr_main.protected_size = protected_size;
    }

    /// Update the header with correct size for the entire app binary.
    pub fn set_total_size(&mut self, total_size: u32) {
        self.hdr_base.total_size = total_size;
    }

    /// Update the header with the correct offset for the _start function.
    pub fn set_init_fn_offset(&mut self, init_fn_offset: u32) {
        self.hdr_main.init_fn_offset = init_fn_offset;
    }

    /// Update the header with appstate values if appropriate.
    pub fn set_writeable_flash_region_values(&mut self, offset: u32, size: u32) {
        for wfr in &mut self.hdr_wfr {
            // Find first unused WFR header and use that.
            if wfr.size == 0 {
                wfr.offset = offset;
                wfr.size = size;
                break;
            }
        }
    }

    /// Create the header in binary form.
    pub fn generate(&self) -> io::Result<io::Cursor<vec::Vec<u8>>> {
        let mut header_buf = io::Cursor::new(Vec::new());

        // Write all bytes to an in-memory file for the header.
        header_buf.write_all(unsafe { util::as_byte_slice(&self.hdr_base) })?;
        header_buf.write_all(unsafe { util::as_byte_slice(&self.hdr_main) })?;
        if !self.package_name.is_empty() {
            header_buf.write_all(unsafe { util::as_byte_slice(&self.hdr_pkg_name_tlv) })?;
            header_buf.write_all(self.package_name.as_ref())?;
            util::do_pad(&mut header_buf, self.package_name_pad)?;
        }

        // Put all writeable flash region header elements in.
        for wfr in &self.hdr_wfr {
            header_buf.write_all(unsafe { util::as_byte_slice(wfr) })?;
        }

        // If there are fixed addresses, include that TLV.
        if self.hdr_fixed_addresses.is_some() {
            header_buf.write_all(unsafe { util::as_byte_slice(&self.hdr_fixed_addresses) })?;
        }

        // If the kernel version is set, include that TLV
        if self.hdr_kernel_version.is_some() {
            header_buf.write_all(unsafe { util::as_byte_slice(&self.hdr_kernel_version) })?;
        }

        let current_length = header_buf.get_ref().len();
        util::do_pad(
            &mut header_buf,
            amount_alignment_needed(current_length as u32, 4) as usize,
        )?;

        self.inject_checksum(header_buf)
    }

    /// Take a TBF header and calculate the checksum. Then insert that checksum
    /// into the actual binary.
    fn inject_checksum(
        &self,
        mut header_buf: io::Cursor<vec::Vec<u8>>,
    ) -> io::Result<io::Cursor<vec::Vec<u8>>> {
        // Start from the beginning and iterate through the buffer as words.
        header_buf.seek(SeekFrom::Start(0))?;
        let mut wordbuf = [0_u8; 4];
        let mut checksum: u32 = 0;
        loop {
            let count = header_buf.read(&mut wordbuf)?;
            // Combine the bytes back into a word, handling if we don't
            // get a full word.
            let mut word = 0;
            for (i, c) in wordbuf.iter().enumerate().take(count) {
                word |= u32::from(*c) << (8 * i);
            }
            checksum ^= word;
            if count != 4 {
                break;
            }
        }

        // Now we need to insert the checksum into the correct position in the
        // header.
        header_buf.seek(io::SeekFrom::Start(12))?;
        wordbuf[0] = (checksum & 0xFF) as u8;
        wordbuf[1] = ((checksum >> 8) & 0xFF) as u8;
        wordbuf[2] = ((checksum >> 16) & 0xFF) as u8;
        wordbuf[3] = ((checksum >> 24) & 0xFF) as u8;
        header_buf.write_all(&wordbuf)?;
        header_buf.seek(io::SeekFrom::Start(0))?;

        Ok(header_buf)
    }
}

impl fmt::Display for TbfHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TBF Header:")?;
        write!(f, "{}", self.hdr_base)?;
        write!(f, "{}", self.hdr_main)?;
        for wfr in &self.hdr_wfr {
            write!(f, "{}", wfr)?;
        }
        self.hdr_fixed_addresses
            .map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;
        self.hdr_permissions
            .as_ref()
            .map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;
        self.hdr_kernel_version
            .map_or(Ok(()), |hdr| write!(f, "{}", hdr))?;
        Ok(())
    }
}
