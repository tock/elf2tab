//! Command line parser setup for elf2tab.

use std::error::Error;
use std::ffi::OsStr;
use std::path::PathBuf;
use structopt::StructOpt;

fn usage() -> &'static str {
    "elf2tab [FLAGS] [OPTIONS] ELF[,ARCHITECTURE]...
Converts Tock userspace programs from .elf files to Tock Application Bundles."
}

fn parse_perms<T, U>(s: &str) -> Result<(T, U), Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
    U: std::str::FromStr,
    U::Err: Error + 'static,
{
    let pos = s
        .find(',')
        .ok_or_else(|| format!("invalid number,option: no `,` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

/// Helper struct for keeping track of the ELF files to convert and an optional
/// architecture string.
#[derive(Debug)]
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

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Convert Tock userland apps from .elf files to Tock Application Bundles (TABs or .tab files).",
    usage = usage(),
    global_setting(structopt::clap::AppSettings::ColoredHelp)
)]
pub struct Opt {
    #[structopt(short = "v", long = "verbose", help = "Be verbose")]
    pub verbose: bool,

    #[structopt(long = "deterministic", help = "Produce a deterministic TAB file")]
    pub deterministic: bool,

    #[structopt(
        long = "app-version",
        help = "Set the version number",
        default_value = "0"
    )]
    pub app_version: u32,

    #[structopt(
        long = "minimum-ram-size",
        name = "min-ram-size",
        help = "in bytes",
        conflicts_with = "stack-size",
        conflicts_with = "heap-size",
        conflicts_with = "kernel-heap-size"
    )]
    pub minimum_stack_size: Option<u32>,

    #[structopt(
        long = "output-file",
        short = "o",
        name = "filename",
        default_value = "TockApp.tab",
        parse(from_os_str),
        help = "output file name"
    )]
    pub output: PathBuf,

    #[structopt(
        long = "package-name",
        short = "n",
        name = "pkg-name",
        help = "package name"
    )]
    pub package_name: Option<String>,

    #[structopt(long = "stack", name = "stack-size", help = "in bytes")]
    pub stack_size: Option<u32>,

    #[structopt(
        long = "app-heap",
        name = "heap-size",
        default_value = "1024",
        help = "in bytes"
    )]
    pub app_heap_size: u32,

    #[structopt(
        long = "kernel-heap",
        name = "kernel-heap-size",
        default_value = "1024",
        help = "in bytes"
    )]
    pub kernel_heap_size: u32,

    #[structopt(
        name = "elf[,architecture]",
        help = "application file(s) to package",
        parse(from_os_str),
        required = true
    )]
    pub input: Vec<ElfFile>,

    #[structopt(
        long = "protected-region-size",
        name = "protected-region-size",
        help = "Size of the protected region (including headers)"
    )]
    pub protected_region_size: Option<u32>,

    #[structopt(
        long = "permissions",
        name = "permissions",
        help = "A list of driver numbers and allowed commands",
        parse(try_from_str = parse_perms),
    )]
    pub permissions: Vec<(u32, u32)>,

    #[structopt(
        long = "write_id",
        name = "write_id",
        help = "A storage ID used for writing data"
    )]
    pub write_id: Option<u32>,

    #[structopt(
        long = "read_ids",
        name = "read_ids",
        help = "Storage IDs that this app is allowed to read"
    )]
    pub read_ids: Option<Vec<u32>>,

    #[structopt(
        long = "access_ids",
        name = "access_ids",
        help = "Storage IDs that this app is allowed to write"
    )]
    pub access_ids: Option<Vec<u32>>,

    #[structopt(
        long = "kernel-major",
        name = "kernel-major-version",
        help = "The kernel version that the app requires"
    )]
    pub kernel_major: Option<u16>,

    #[structopt(
        long = "kernel-minor",
        name = "kernel-minor-version",
        requires = "kernel-major-version",
        help = "The minimum kernel minor version that the app requires"
    )]
    pub kernel_minor: Option<u16>,

    #[structopt(
        long = "sha256",
        name = "sha256-add",
        help = "Add a SHA256 hash credential to each TAB"
    )]
    pub sha256_enable: bool,

    #[structopt(
        long = "sha512",
        name = "sha512-add",
        help = "Add a SHA512 hash credential to each TAB"
    )]
    pub sha512_enable: bool,

    #[structopt(
        long = "rsa4096-private",
        name = "rsa4096-private-key",
        help = "Add an 4096-bit RSA signature credential using this private key"
    )]
    pub rsa4096_private_key: Option<PathBuf>,

    #[structopt(
        long = "rsa4096-public",
        name = "rsa4096-public-key",
        help = "Add an 4096-bit RSA signature credential containing this public key"
    )]
    pub rsa4096_public_key: Option<PathBuf>,
}

mod test {

    #[cfg(test)]
    use super::Opt;
    #[cfg(test)]
    use structopt::StructOpt;

    #[test]
    // elf2tab [FLAGS] [--package-name=<pkg-name>] [--output-file=[<filename>]] <elf[,architecture]>...
    fn simple_invocations_succeed() {
        {
            let args = vec!["elf2tab", "app.elf"];
            let result = Opt::from_iter_safe(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec!["elf2tab", "--package-name", "my-pkg", "app.elf"];
            let result = Opt::from_iter_safe(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec!["elf2tab", "--output-file", "out.tab", "app.elf"];
            let result = Opt::from_iter_safe(args.iter());
            assert!(result.is_ok());
        }
        {
            let args = vec!["elf2tab", "--package-name", "my-pkg", "app.elf"];
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
            println!("{:?}", result);
            assert!(result.is_ok());
        }
    }

    #[test]
    // elf2tab [FLAGS] [--package-name=<pkg-name>] [--output-file=[<filename>]] <elf[,architecture]>...
    fn simple_invocations_fail() {
        {
            let args = vec!["elf2tab", "app.elf", "--package-name"];
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
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
            let result = Opt::from_iter_safe(args.iter());
            assert!(result.is_err());
        }
    }
}
