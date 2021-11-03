# SRX – SGX Recovery Extension

## Compiling

### Prerequisites

- An Intel SGX working environment (SGX SDK 2.7.1, SGX SSL 2.5)

- OpenSSL v1.1.1a (set path in `environment`)

- asn1c 0.9.28 for development (set path in `environment`)

### Compiling the SRX library

1. Setup environment variables for using the library:

	```shell
	$ source $(SRX_HOME)/environment
	```

2. Generate a private key:

	```shell
	$ openssl genrsa -3 -out /tmp/key.pem 3072
	$ export SGX_KEY=/tmp/key.pem
	```

3. Compile all libraries:

	```shell
	$ make -C support-libs/usgx/
	$ make -C support-libs/foossl/
	$ make -C srx-libs/android-st/common/
	$ make -C srx-libs/android-st/protocol/ generate
	$ make -C srx-libs/android-st/protocol/
	$ make -C srx-libs/android-st/client/
	```

### Compiling the SRX library (alternative with flags)

```shell
$ make -C srx-libs/android-st/client/ RLOG=RLOG_INFO SRX_DEBUG=1 SRX_DEBUG_PRINT_VERIFICATION_CODE=1 PLATFORM_ID=0 SGX_DEBUG=0 SGX_PRERELEASE=1
```

† Compile the remaining modules as stated in the previous section.

### Compiling the server and applications

1. Compile the sample server and sample application, as well as both use cases:

	```shell
	$ make -C applications/server/
	$ make -C applications/sample-pst/

	$ make -C applications/password-manager/
	$ make -C applications/bitcoin-wallet/
	```

	For cleanup invoke the same set of commands adding `clean`. And manually remove the generated private key.

### Compiling the ~~server and~~ applications (alternative with flags)

```shell
$ make -C applications/sample-pst/ SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1

$ make -C applications/bitcoin-wallet/ DEBUG=0 SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 CSP_MODE=1

$ make -C applications/password-manager/ SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 CSP_MODE=1
```

† Compile the remaining modules as stated in the previous section.

## Running

### Prerequisites

- The SRX library is compiled and the environment variables are set

### Running the server

There is a sample server that is necessary for the operation of SRX. (This server would usually handle remote attestation but the prototype does not implement that part and assumes the RA to be successful.) The server should be started before running the applications.

```shell
$ cd $SRX_HOME/applications/server
$ ./server
```

### Running the applications

Sample application:

```shell
$ cd $SRX_HOME/applications/sample-pst
$ ./app_ex
```

Bitcoin wallet:

```shell
$ cd $SRX_HOME/applications/bitcoin-wallet/modules/yapitool
$ ./yapitool --help
```

Password manager:

```shell
$ cd $SRX_HOME/applications/password-manager
$ ./titan --help
```

TODO: how security token implementation in Android is related

## Using SRX

TODO (use of SRX with own application)

## Development

### Prerequisites

- asn1c (TODO)

## Repository

### Structure

```
.
├── applications/               Applications and samples using SRX
│   ├── bitcoin-wallet/
│   ├── password-manager/
│   ├── sample-pst/
│   └── server/
├── srx-api/                    The generic SRX interface
├── srx-libs/                   An implementation of the SRX interface
│   └── android-st/             using a smartphone as Security Token
│       ├── common/
│       ├── protocol/
│       └── Token16/
├── support-libs/               Internal supporting libraries
│   ├── foossl/
│   └── usgx/
├── environment                 Environment variables for SRX
└── README.md
```

## About

Data sealed on an Intel SGX platform is tied to that platform and cannot be unsealed in a different platform. This is a problem if the platform that sealed the data becomes unavailable.

This set of libraries enables a group of SGX-enabled platforms to form a group to securely share secret keys for sealing data.

This is achieved with the support of a remote attestation and signing server that attests the clients to ensure these are legitimate;¹ and of a security token, controlled by the end user, to authorize sensitive operations. Sensitive operations can be internal, such as adding new platforms to the group with access to the keys, or external such as those performed by the application enclave that uses SRX. For example, signing a transaction in a cryptocurrency wallet could be considered a sensitive operation thus requiring user authorization via security token before proceeding.

The remote attestation and signing server, and the security token, have no access to end-user data or secret keys.

¹ Attestation server is partially implemented: signs keys but does not attest with the Intel Attestation Service.
