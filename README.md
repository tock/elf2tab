# ![elf2tab](http://www.tockos.org/assets/img/elf2tab.svg "elf2tab Logo")

`elf2tab` is a tool that converts [Tock](https://github.com/tock/tock) userland
apps from `.elf` files to Tock Application Bundles (TABs or `.tab` files). TABs
are Tock apps that have been compiled for the various architectures that Tock
runs on.


Usage
-----

```
USAGE:
    elf2tab [FLAGS] [OPTIONS] ELF[,ARCHITECTURE]...
Converts Tock userspace programs from .elf files to Tock Application Bundles.

FLAGS:
        --deterministic    Produce a deterministic TAB file
    -h, --help             Prints help information
        --sha256           Add a SHA256 hash credential to each TAB
        --sha384           Add a SHA384 hash credential to each TAB
        --sha512           Add a SHA512 hash credential to each TAB
    -V, --version          Prints version information
    -v, --verbose          Be verbose

OPTIONS:
        --access_ids <access_ids>...                       Storage IDs that this app is allowed to write
        --app-version <app-version>                        Set the version number [default: 0]
    -o, --output-file <filename>                           output file name [default: TockApp.tab]
        --app-heap <heap-size>                             in bytes [default: 1024]
        --kernel-heap <kernel-heap-size>                   in bytes [default: 1024]
        --kernel-major <kernel-major-version>              The kernel version that the app requires
        --kernel-minor <kernel-minor-version>              The minimum kernel minor version that the app requires
        --minimum-ram-size <min-ram-size>                  in bytes
        --permissions <permissions>...                     A list of driver numbers and allowed commands
    -n, --package-name <pkg-name>                          package name
        --protected-region-size <protected-region-size>    Size of the protected region (including headers)
        --read_ids <read_ids>...                           Storage IDs that this app is allowed to read
        --rsa4096-private <rsa4096-private-key>            Add an 4096-bit RSA signature credential using this private key
        --rsa4096-public <rsa4096-public-key>              Add an 4096-bit RSA signature credential containing this public key
        --stack <stack-size>                               in bytes
        --write_id <write_id>                              A storage ID used for writing data

ARGS:
    <elf[,architecture]>...    application file(s) to package
```

For example, converting a "blink" app from a compiled .elf file (for a Cortex-M4
device) with this tool would look like:

    $ elf2tab -o blink.tab -n blink --stack 1024 --app-heap 1024 --kernel-heap 1024 cortex-m4.elf

It also supports (and encourages!) combining .elf files for multiple architectures
into a single tab:

    $ elf2tab -o blink.tab -n blink --stack 1024 --app-heap 1024 --kernel-heap 1024 cortex-m0.elf cortex-m3.elf cortex-m4.elf


Compiling elf2tab
-----------------

With rustup installed, simply run:

    cargo build

Adding TBF Credentials
----------------------

elf2tab supports adding credentials to the TBF footer of the generated TBF
files. To add a hash, use one or more of these flags: `--sha256`, `--sha384`,
`--sha512`.

elf2tab can also sign the TBF with a public/private RSA key pair. To generate
compatible keys:

    $ openssl genrsa -aes256 -out tockkey.private.pem 4096
    $ openssl rsa -in tockkey.private.pem -outform der -out tockkey.private.der
    $ openssl rsa -in tockkey.private.pem -outform der -pubout -out tockkey.public.der

Then pass the keys to elf2tab:

    $ elf2tab --rsa4096-private tockkey.private.der --rsa4096-public tockkey.public.der ...

Example including multiple credentials:

    $ elf2tab --sha256 --sha384 --sha512 --rsa4096-private tockkey.private.der --rsa4096-public tockkey.public.der ...


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

elf2tab will also automatically add a TBF "fixed addresses" TLV header if it
finds that the .elf file was compiled for a fixed address in RAM or flash
instead of being position independent. To detect a fixed flash address, elf2tab
looks to see if the flash segment is at the dummy flash address for PIC apps or
not. To detect a fixed RAM address, elf2tab looks for a `_sram_origin` symbol,
and if it exists checks if the address matches the dummy RAM address for PIC
apps or not.

elf2tab has to choose a length for the protected region after the TBF header and
before the start of the actual application binary. Normally, this defaults to 0.
It can be fixed for all TBFs in the TAB using the command line argument
`--protected-region-size` (which takes as an argument entire size before the
application binary, including the TBF header). However, a TAB can include both
PIC apps and non-PIC apps, and setting the size for all TBFs isn't always
desirable. Therefore, if `--protected-region-size` is not used, for apps
compiled for fixed addresses (as determined above) elf2tab will estimate a
protected region size that tries to ensure the start of the TBF headers _and_
the application binary are placed at useful addresses in flash. elf2tab will try
to increase the size of the protected region to make the start of the TBF header
at an address aligned to 256 bytes when the application binary is at its correct
fixed address.

#### Syscall Permissions

elf2tab allows explicitly specifying the syscalls that an app is allowed to
call. This is done with the `--permissions` flag.
An example of allowing driver number `1` command `0` and command `1` looks like
this:

    $ elf2tab --permissions 1,0 1,1 ...

It is then up to the Tock kernel and board to apply the filters.

#### Storage IDs

elf2tab also allows specifying the storage IDs. These are used to access
nonvolatile data from userspace. You can specify a single write_id used
to store new data and multiple read_ids and access_ids used to enforce
read/write permissions on existing data.

An example looks like this
    $ elf2tab  --write_id 12345678 --read_ids 1 2 --access_ids 2 3 ...

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
