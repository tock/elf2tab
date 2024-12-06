//! Command line parser setup for elf2tab.

use std::error::Error;
use std::ffi::OsStr;
use std::path::PathBuf;

fn parse_perms(s: &str) -> Result<(u32, u32), Box<dyn Error + Send + Sync>> {
    let pos = s
        .find(',')
        .ok_or_else(|| format!("invalid number,option: no `,` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

/// Helper struct for keeping track of the ELF files to convert and an optional
/// architecture string.
#[derive(Debug, Clone)]
pub struct ElfFile {
    /// Caller must provide a path to the ELF.
    pub path: PathBuf,
    /// Callers may optionally include the target architecture for that ELF.
    /// Otherwise the architecture will be inferred from the name of the ELF
    /// file.
    pub architecture: Option<String>,
}

impl From<&OsStr> for ElfFile {
    fn from(value: &OsStr) -> Self {
        let mut elf_file = ElfFile {
            path: value.into(),
            architecture: None,
        };
        if let Some(s) = value.to_str() {
            if let Some(index) = s.rfind(',') {
                elf_file.path = PathBuf::from(&s[0..index]);
                elf_file.architecture = Some(String::from(&s[index + 1..]));
            }
        }
        elf_file
    }
}

#[derive(clap::Parser, Debug)]
#[command(
    about = "Convert Tock userland apps from .elf files to Tock Application Bundles (TABs or .tab files).",
    version
)]
pub struct Opt {
    #[arg(short = 'v', long = "verbose", help = "Be verbose")]
    pub verbose: bool,

    #[arg(long = "deterministic", help = "Produce a deterministic TAB file")]
    pub deterministic: bool,

    #[arg(long = "disable", help = "Mark the app as disabled in the TBF flags")]
    pub disabled: bool,

    #[arg(
        long = "app-version",
        help = "Set the version number",
        default_value = "0"
    )]
    pub app_version: u32,

    #[arg(
        long = "minimum-ram-size",
        id = "min-ram-size",
        help = "in bytes",
        conflicts_with = "stack-size",
        conflicts_with = "heap-size",
        conflicts_with = "kernel-heap-size"
    )]
    pub minimum_stack_size: Option<u32>,

    #[arg(
        long = "output-file",
        short = 'o',
        id = "filename",
        default_value = "TockApp.tab",
        help = "output file name"
    )]
    pub output: PathBuf,

    #[arg(
        long = "package-name",
        short = 'n',
        id = "pkg-name",
        help = "package name"
    )]
    pub package_name: Option<String>,

    #[arg(long = "stack", id = "stack-size", help = "in bytes")]
    pub stack_size: Option<u32>,

    #[arg(
        long = "app-heap",
        id = "heap-size",
        default_value = "1024",
        help = "in bytes"
    )]
    pub app_heap_size: u32,

    #[arg(
        long = "kernel-heap",
        id = "kernel-heap-size",
        default_value = "1024",
        help = "in bytes"
    )]
    pub kernel_heap_size: u32,

    #[arg(
        id = "elf[,architecture]",
        help = "application file(s) to package",
        num_args = 1..,
        required = true,
    )]
    pub input: Vec<ElfFile>,

    #[arg(
        long = "protected-region-size",
        id = "protected-region-size",
        help = "Size of the protected region (including headers)"
    )]
    pub protected_region_size: Option<u32>,

    #[arg(
        long = "permissions",
        id = "permissions",
        help = "A list of driver numbers and allowed commands",
        num_args = 1..,
        value_parser = parse_perms,
    )]
    pub permissions: Vec<(u32, u32)>,

    #[arg(
        long = "write_id",
        id = "write_id",
        help = "A storage ID used for writing data",
        value_parser=clap_num::maybe_hex::<u32>,
    )]
    pub write_id: Option<u32>,

    #[arg(
        long = "read_ids",
        id = "read_ids",
        help = "Storage IDs that this app is allowed to read",
        num_args = 1..,
        value_parser=clap_num::maybe_hex::<u32>,
    )]
    pub read_ids: Option<Vec<u32>>,

    #[arg(
        long = "access_ids",
        id = "access_ids",
        help = "Storage IDs that this app is allowed to write",
        num_args = 1..,
        value_parser=clap_num::maybe_hex::<u32>,
    )]
    pub access_ids: Option<Vec<u32>>,

    #[arg(
        long = "short-id",
        id = "short-id",
        help = "ShortId to request in the app's header",
        value_parser=clap_num::maybe_hex::<u32>,
    )]
    pub short_id: Option<u32>,

    #[arg(
        long = "kernel-major",
        id = "kernel-major-version",
        help = "The kernel version that the app requires"
    )]
    pub kernel_major: Option<u16>,

    #[arg(
        long = "kernel-minor",
        id = "kernel-minor-version",
        requires = "kernel-major-version",
        help = "The minimum kernel minor version that the app requires"
    )]
    pub kernel_minor: Option<u16>,

    #[arg(
        long = "supported-boards",
        id = "supported-boards",
        help = "comma separated list of boards this app is compatible with"
    )]
    pub supported_boards: Option<String>,

    #[arg(
        long = "minimum-footer-size",
        id = "min-footer-size",
        help = "Minimum number of bytes to reserve space for in the footer",
        default_value = "0"
    )]
    pub minimum_footer_size: u32,

    #[arg(
        long = "sha256",
        id = "sha256-add",
        help = "Add a SHA256 hash credential to each TBF"
    )]
    pub sha256_enable: bool,

    #[arg(
        long = "sha384",
        id = "sha384-add",
        help = "Add a SHA384 hash credential to each TBF"
    )]
    pub sha384_enable: bool,

    #[arg(
        long = "sha512",
        id = "sha512-add",
        help = "Add a SHA512 hash credential to each TBF"
    )]
    pub sha512_enable: bool,

    #[arg(
        long = "rsa4096-private",
        id = "rsa4096-private-key",
        help = "Add an 4096-bit RSA signature credential using this private key"
    )]
    pub rsa4096_private_key: Option<PathBuf>,
}

mod test {

    #[cfg(test)]
    use super::Opt;
    #[cfg(test)]
    use clap::Parser;

    #[test]
    // elf2tab [FLAGS] [--package-name=<pkg-name>] [--output-file=[<filename>]] <elf[,architecture]>...
    fn simple_invocations_succeed() {
        {
            let args = vec!["elf2tab", "app.elf"];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec!["elf2tab", "--package-name", "my-pkg", "app.elf"];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec!["elf2tab", "--output-file", "out.tab", "app.elf"];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec!["elf2tab", "--package-name", "my-pkg", "app.elf"];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec![
                "elf2tab",
                "--output-file",
                "out.tab",
                "--package-name",
                "pkg-name",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            println!("{:?}", result);
            assert!(result.is_ok());
        }
    }

    #[test]
    // elf2tab [FLAGS] [--package-name=<pkg-name>] [--output-file=[<filename>]] <elf[,architecture]>...
    fn simple_invocations_fail() {
        {
            let args = vec!["elf2tab", "app.elf", "--package-name"];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
    }

    #[test]
    // elf2tab [FLAGS] [--package-name=<pkg-name>] [--output-file=[<filename>]] [--minimum-stack-size=<min-stack-size>] <elf>...
    fn advanced_invocations_succeed() {
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--minimum-ram-size",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
    }

    #[test]
    // elf2tab [FLAGS] [--package-name=<pkg-name>] [--output-file=[<filename>]] [--minimum-stack-size=<min-stack-size>] <elf[,architecture]>...
    fn advanced_invocations_fail() {
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--minimum-ram-size",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--minimum-ram-size",
                "10",
                "--app-heap",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--minimum-ram-size",
                "10",
                "--stack",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--minimum-ram-size",
                "10",
                "--kernel-heap",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
    }

    #[test]
    // elf2tab [FLAGS] [--package-name=<pkg-name>] [--output-file=[<filename>]] [--app-heap[=<heap-size>]]
    //                [--kernel-heap[=<kernel-heap-size>]] [--stack[=<stack-size>]] <elf[,architecture]>..."
    fn expert_invocations_succeed() {
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--kernel-heap",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--app-heap",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--stack",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--stack",
                "10",
                "--app-heap",
                "10",
                "--kernel-heap",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_ok());
        }
    }

    #[test]
    // elf2tab [FLAGS] [--package-name=<pkg-name>] [--output-file=[<filename>]] [--app-heap[=<heap-size>]]
    //                [--kernel-heap[=<kernel-heap-size>]] [--stack[=<stack-size>]] <elf[,architecture]>..."
    fn expert_invocations_fail() {
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--kernel-heap",
                "10",
                "--minimum-ram-size",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--app-heap",
                "10",
                "--minimum-ram-size",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
        {
            let args = vec![
                "elf2tab",
                "--package-name",
                "my-pkg",
                "--stack",
                "10",
                "--minimum-ram-size",
                "10",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
    }

    #[test]
    // elf2tab [FLAGS] [--write_id=<write_id>] [--read_ids=<read_ids>] [--access_ids=<access_ids>]
    //                <elf[,architecture]>..."
    fn storage_ids() {
        {
            let args = vec![
                "elf2tab",
                "--write_id",
                "1234567",
                "--read_ids",
                "1 2",
                "--access_ids",
                "2 3",
                "app.elf",
            ];
            let result = Opt::try_parse_from(args.iter());
            assert!(result.is_err());
        }
    }
}
