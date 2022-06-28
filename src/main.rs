use std::fmt::Write as fmtwrite;
use std::fs;
use std::io;
use std::io::{Seek, Write};
use structopt::StructOpt;

use elf2tab::convert;
use elf2tab::cmdline;



fn main() {
    let opt = cmdline::Opt::from_args();

    let package_name = opt
        .package_name
        .as_ref()
        .map_or("", |package_name| package_name.as_str());

    // If kernel_major is set, the app requires kernel ^kernel_major.0 (>=
    // kernel_major.0, < (kernel_major+1).0) Optionally, kernel_minor can be
    // set, making the app require ^kernel_major.kernel_minor (>=
    // kernel_major.kernel_minor, < (kernel_major+1).0).
    let minimum_tock_kernel_version = match opt.kernel_major {
        Some(major) => Some((major, opt.kernel_minor.unwrap_or(0))),
        None => None,
    };

    // Create the metadata.toml file needed for the TAB file.
    let mut metadata_toml = String::new();
    // TAB version is currently "1". This defines the general format, but
    // key-value pairs can be added (or removed) and still be version 1.
    writeln!(&mut metadata_toml, "tab-version = 1").unwrap();
    // Name is always set by elf2tab (even if it is empty).
    writeln!(&mut metadata_toml, "name = \"{}\"", package_name).unwrap();
    // We don't currently tell elf2tab if this app only runs on certain boards.
    writeln!(&mut metadata_toml, "only-for-boards = \"\"").unwrap();
    // Include "minimum-tock-kernel-version" key if a necessary kernel version
    // was specified.
    minimum_tock_kernel_version.map(|(major, minor)| {
        writeln!(
            &mut metadata_toml,
            "minimum-tock-kernel-version = \"{}.{}\"",
            major, minor
        )
        .unwrap();
    });
    // Add build-date metadata unless a deterministic build is desired.
    if !opt.deterministic {
        let build_date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        writeln!(&mut metadata_toml, "build-date = {}", build_date).unwrap();
    }

    // Start creating a tar archive which will be the .tab file.
    let tab_name = fs::File::create(&opt.output).expect("Could not create the output file.");
    let mut tab = tar::Builder::new(tab_name);
    tab.mode(tar::HeaderMode::Deterministic);

    // Add the metadata file without creating a real file on the filesystem.
    let mut header = tar::Header::new_gnu();
    header.set_size(metadata_toml.as_bytes().len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tab.append_data(&mut header, "metadata.toml", metadata_toml.as_bytes())
        .unwrap();

    // Iterate all input elfs. Convert them to Tock friendly binaries and then
    // add them to the TAB file.
    for elf_file in opt.input {
        let elffile = elf::File::open_path(&elf_file.path).expect("Could not open the .elf file.");

        // The TBF will be written to the same place as the ELF, with a .tbf
        // extension.
        let tbf_path = elf_file.path.with_extension("tbf");

        // Get the name of the architecture for the TBF. This will be used to
        // name the TBF in the TAB, as the file name is expected to be
        // `<architecture>.tbf`.
        let architecture = if let Some(ref architecture) = elf_file.architecture {
            // The caller of elf2tab explicitly told us the architecture via
            // command line arguments.
            architecture.clone()
        } else {
            // Otherwise, we must assume that the elf was named as
            // `<architecture>.elf` and use the base name as the architecture.
            elf_file
                .path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };
        // Use the architecture to name the TBF in the TAB.
        let tab_tbf_name = format!("{}.tbf", architecture);

        if opt.output.clone() == tbf_path.clone() {
            panic!(
                "tab file {} and output file {} cannot be the same file",
                opt.output.clone().to_str().unwrap(),
                tbf_path.to_str().unwrap()
            );
        }

        // Get output file as both read/write for creating the binary and
        // adding it to the TAB tar file.
        let mut outfile: fs::File = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(tbf_path.clone())
            .unwrap();

        // Adding padding to the end of cortex-m apps. Check for a cortex-m app
        // by inspecting the "machine" value in the elf header. 0x28 is ARM (see
        // https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header
        // for a list).
        //
        // RISC-V apps do not need to be sized to power of two.
        let add_trailing_padding = elffile.ehdr.machine.0 == 0x28;

        // Do the conversion to a tock binary.
        if opt.verbose {
            println!("Creating {:?}", tbf_path);
        }
        // First write the TBF into a vector, to allow each read access
        // for generating credentials; once it's written to the vector, flush
        // it to a file.
        let mut output_vector = Vec::<u8>::new();
        convert::elf_to_tbf(
            &elffile,
            &mut output_vector,
            opt.package_name.clone(),
            opt.verbose,
            opt.stack_size,
            opt.app_heap_size,
            opt.kernel_heap_size,
            opt.protected_region_size,
            opt.permissions.to_vec(),
            (opt.write_id, opt.read_ids.clone(), opt.access_ids.clone()),
            minimum_tock_kernel_version,
            add_trailing_padding,
            opt.program,
            opt.app_version,
            opt.sha256_enable,
            opt.sha512_enable,
            opt.rsa4096_private_key.clone(),
            opt.rsa4096_public_key.clone(),
        )
        .unwrap();
        if opt.verbose {
            println!("");
        }

        match outfile.write_all(output_vector.as_ref()) {
            Err(e) => {
                println!("Failed to write TBF: {:?}", e);
                return;
            }
            _ => {}
        }

        // Add the file to the TAB tar file.
        outfile.seek(io::SeekFrom::Start(0)).unwrap();

        tab.append_file(tab_tbf_name, &mut outfile).unwrap();
    }

}
