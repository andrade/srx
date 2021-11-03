The *usgx* library offers helpful functions for application and library development using Intel SGX.

## Building and Installation

### Prerequisites

* Intel SGX SDK and respective toolchain (needs `sgx_edger8r`)
	* The path to the framework (`$SGX_SDK`) should be set
* A C development environment
	* For compiling the source code and creating the library using the makefile

### Compiling

* Compile the library with `$ make`
* Clean all generated files with with `$ make clean`

### Installing

TODO

### Using

To use the library ~~without installing it~~:

1. Download and compile the library
2. In your makefile:
	- Add `$USGX/include` to the include path of trusted and untrusted code
	- Add `$USGX` to the library search path of trusted and untrusted code
	- Add `-lusgx-secure` to the trusted code
	- Add `-lusgx-normal` to the untrusted code
3. In your source code:
	- Add `from "usgx/util.edl" import *;` to the EDL file
	- Include `usgx/t/util.h` in trusted code to use the trusted functions
	- ~~Include `usgx/u/util.h` in untrusted code to use the untrusted functions~~ N/A

This assume the library is located at `$USGX`.

## Project Layout

```
.
├──── − include
│       └──── − usgx                    # public API
│               ├──── − t               # trusted headers
│                       └──── · *.h
│               ├──── + u               # untrusted headers
│               └──── · *.edl           # EDL interfaces
├──── − src
│       ├──── − t                       # trusted source code
│       │       ├──── · *.c             # implementation of trusted code
│       │       └──── · *.h             # internal trusted headers
│       └──── + u                       # untrusted source code
├──── · Makefile
└──── · README.md                       # this file
```

~~Could have common source code under `src/` and common public headers under `include/usgx/`.~~

## License

TODO
