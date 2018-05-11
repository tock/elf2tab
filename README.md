# ![elf2tbf](http://www.tockos.org/assets/img/elf2tbf.svg "elf2tbf Logo")

`elf2tab` is a tool that converts Tock userland apps from `.elf` files
to Tock Application Bundles (TABs or `.tab` files). TABs are Tock apps
that have been compiled for the various architectures that Tock runs on.


Usage
-----

```
Usage: elf2tab [-o OUTFILE] ELFFILE [ELFFILE...]

Options:
    -o OUTFILE                      set output file name
    -n PACKAGE_NAME                 set package name
    --stack STACK_SIZE              set stack size in bytes
    --app-heap APP_HEAP_SIZE        set app heap size in bytes
    --kernel-heap KERNEL_HEAP_SIZE  set kernel heap size in bytes
    -v, --verbose                   be verbose
```

For example, converting a "blink" app from a compiled .elf file (for a Cortex-M4
device) with this tool would look like:

    $ elf2tab -o blink.tab -n blink --stack 1024 --app-heap 1024 --kernel-heap 1024 cortex-m4.elf

It also supports (and encourages!) combing .elf files for multiple architectures
into a single tab:

	$ elf2tab -o blink.tab -n blink --stack 1024 --app-heap 1024 --kernel-heap 1024 cortex-m0.elf cortex-m3.elf cortex-m4.elf


Compiling elf2tab
-----------------

With rustup installed, simply run:

    cargo build


elf2tab Details
---------------

elf2tab tries to be as generic as possible for creating apps that can be
flashed onto a Tock board. It does three main things:

1. Extracts the various sections in each .elf file and creates a binary file
   per .elf from the sections.
2. Prepends a
   [Tock Binary Format](https://github.com/tock/tock/blob/master/doc/Compilation.md#tock-binary-format)
   header to each binary.
3. Creates the TAB file by creating a tar file with each of the Tock binaries.


### Creating binary files from .elf files

elf2tab tries to process .elf files in as generic of a way as possible. To
create the binary file, elf2tab iterates through the sections in the .elf file
in their offset order that are writeable, executable, or allocated, have nonzero
length, and are of type PROGBITS. The binary data for each of these sections
are concatenated into the output file.

Next, elf2tab appends to the binary all writeable or allocated sections that
contain the string `.rel` in their name. Because of how these sections are
created for PIC code by the linker, it seems these sections have to be special
cased and not grouped into the first step.

### Creating the TBF Header

All Tock apps must start with a Tock Binary Format header so that the kernel
knows how big the app is, how much memory it requires, and other important
properties. elf2tab handles creating this header automatically, and mostly
just requires the `--stack`, `--app-heap`, and `--kernel-heap` flags so it
knows the memory requirements.

However, the TBF header also contains information about "writeable flash
regions", or portions of the application's address space in flash that the app
intends to use to store persistent data. This information is added to the header
so that the kernel and other tools know that there is persistent that should be
maintained intact. To specify to elf2tab that a linker section is one of these
writeable flash regions, the name of the section should include the string
`.wfr`. Any sections in the .elf that include `.wfr` in their name will have
their relative address offset included in the TBF header via the
`TbfHeaderWriteableFlashRegions` TLV.

### Creating the TAB file

After generating the program binary and TBF header for each .elf file specified
in the command line, elf2tab will store those files along side the .elf files
(using the `.tbf` extension), and create a [TAB
file](https://github.com/tock/tock/blob/master/doc/Compilation.md#tock-application-bundle)
containing each .tbf file. These .tab files are used by tools like Tockloader to
load Tock apps on to boards.


Inspecting TABs
---------------

Tockloader can show some details of a .tab file. Simply:

    $ tockloader inspect-tab <tab file name>


