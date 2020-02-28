use std::path::PathBuf;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Convert Tock userland apps from .elf files to Tock Application Bundles (TABs or .tab files)."
)]
pub struct Opt {
    #[structopt(short = "v", long = "verbose", help = "Be verbose")]
    pub verbose: bool,

    #[structopt(short = "o", name = "TAB", parse(from_os_str), help = "Output file name")]
    pub output: PathBuf,

    #[structopt(short = "n", name = "PACKAGE_NAME", help = "Package Name")]
    pub package_name: Option<String>,

    #[structopt(
        short = "p",
        long = "permissions",
        name = "PERMISSIONS",
        help = "allow certain driver numbers (and disallow all others)"
    )]
    pub permissions: Vec<u32>,

    #[structopt(long = "stack", name = "STACK_SIZE", help = "Stack size in bytes")]
    pub stack_size: u32,

    #[structopt(long = "app-heap", name = "APP_HEAP_SIZE", help = "App heap size in bytes")]
    pub app_heap_size: u32,

    #[structopt(
        long = "kernel-heap", name = "KERNEL_HEAP_SIZE", help = "Kernel heap size in bytes"
    )]
    pub kernel_heap_size: u32,

    #[structopt(
        long = "protected-region-size",
        name = "PROTECTED_REGION_SIZE",
        help = "Size of the protected region (including headers)"
    )]
    pub protected_region_size: Option<u32>,

    #[structopt(name = "ELF", help = "App elf files", parse(from_os_str))]
    pub input: Vec<PathBuf>,
}
