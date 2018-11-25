use std::path::PathBuf;
use structopt;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Convert Tock userland apps from .elf files to Tock Application Bundles (TABs or .tab files)."
)]
#[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
pub struct Opt {
    #[structopt(short = "v", long = "verbose", help = "Be verbose")]
    pub verbose: bool,

    #[structopt(name = "TABFILE", parse(from_os_str), help = "output file name")]
    pub output: PathBuf,

    #[structopt(
        long = "package-name",
        short = "n",
        name = "NAME",
        help = "Package Name"
    )]
    pub package_name: Option<String>,

    #[structopt(name = "STACK_SIZE", help = "in bytes")]
    pub stack_size: u32,

    #[structopt(name = "APP_HEAP_SIZE", help = "in bytes")]
    pub app_heap_size: u32,

    #[structopt(name = "KERNEL_HEAP_SIZE", help = "in bytes")]
    pub kernel_heap_size: u32,

    #[structopt(
        name = "ELF",
        help = "application file(s) to package",
        parse(from_os_str)
    )]
    #[structopt(raw(required = "true"))]
    pub input: Vec<PathBuf>,
	
    #[structopt(
        long = "protected-region-size",
        name = "PROTECTED_REGION_SIZE",
        help = "Size of the protected region (including headers)"
    )]
    pub protected_region_size: Option<u32>,


}

mod test {

    use super::Opt;
    use super::*;

    #[test]
    fn succeeds_if_all_required_arguments_are_specified() {
        let args = vec!["elf2tab", "out.tab", "1024", "2048", "4098", "app.elf"];
        let result = Opt::from_iter_safe(args.iter());
        assert!(result.is_ok());
    }

    #[test]
    fn fails_if_required_arguments_are_missing() {
        let args = vec!["out.tab", "1024", "2048", "4098", "app.elf"];
        let result = Opt::from_iter_safe(args.iter());
        assert!(result.is_err());
    }
}
