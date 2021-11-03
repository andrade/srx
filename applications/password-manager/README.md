# Titan SRX

Titan is a text-based password manager. This version of Titan has been adapted to work with SGX and SRX.

## Compile

- Call `$ make` for debug and simulation mode. Clean with `$ make clean`.

- Call `$ make SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1` for pre-release.

SGX flags:

- `SGX_MODE=HW` or `SGX_MODE=SIM` (default)

- `SGX_DEBUG=0` or `SGX_DEBUG=1` (default)

- `SGX_PRERELEASE=1` or `SGX_PRERELEASE=0` (default)

### Measuring execution time

NOTE: Use either (1) or (2), do not enable both or will give inaccurate results.

(1) Flags to measure execution time:¹

- `EVAL_INCLUDE_LC=1` or `EVAL_INCLUDE_LC=0` (default)

- `EVAL_EXCLUDE_LC=1` or `EVAL_EXCLUDE_LC=0` (default)

¹ The two flags are exclusive, use one or the other. The difference is whether the enclave life cycle (creation and destruction) are included in the process CPU time.

(2) Flags to measure execution time (csysperf-based alternative, more detail):

- `CSP_MODE=1` or `CSP_MODE=0` (default)

## Run

```
./titan --help

Initializes a new database:
./titan --init my-database.db

Add new entry (asks for info):
./titan --add

List all entries (without passwords):
./titan -A

Lists first entry (without password):
./titan -l 1

Lists first entry with password:
./titan --show-passwords -l 1

Closes database:
./titan -e

Reopens database:
./titan -d my-database.db
```

__New DB:__ User authorization is requested (via Security Token) to initialize a new DB.

__Lock file:__ When initialized or opened, a database lock is created at `~/.titan.sgx.lock`. When we call `-e` this essentially removes the lock. (In a non-SGX version it closes the database, but with SGX the database is always open and closed on each command.) Only one DB can be open at a time; call `./titan -e` to close existing one. This lock can safely be removed manually (e.g. `$ trash ~/.titan.sgx.lock`) which causes the DB to be in closed state if you can call it as such.

__Display passwords:__ The command `-A` lists all entries and `-l <n>` lists entry `n`. Prefix the command with `--show-passwords` to actually display the password, otherwise it shows as `********`. User authorization is required (via Security Token) when asking to display the password.

__User authorization:__ User authorization is granted via Security Token. With the current SRX implementation: (1) a GUI pops up on the PC with a QR code, (2) the user reads it with the Security Token and validates the action on the ST, and (3) enters a successful response code to the PC GUI to *confirm authorization*. // This ensures malicious code cannot invoke the trusted interface behind the user's back. For example, attempt to display a password without the user's knowledge in order to capture that password. (In Titan SGX, a Titan version without SRX integration, this attack is possible.) // Note the password is displayed on the PC screen so it could potentially be captured after display. This is a weakness of the original password manager and could be solved, for example, by displaying the password directly on the Security Token (although this does not help if the purpose is entering the password on the PC).

# Original README

Titan - Command line password manager

Password management belongs to the command line, deep into the Unix heartland,
the shell. Titan is written in C.

~~Titan is more than "just a password manager". It also supports encrypting
individual files so Titan can be used as a file encryption program as well
as a password manager.~~
