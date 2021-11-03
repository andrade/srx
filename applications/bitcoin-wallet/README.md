# Yapi Wallet

Yet another partially incomplete bitcoin wallet

## Compilation

First set the `SGX_KEY` variable. For example:

```
$ openssl genrsa -3 -out /tmp/key.pem 3072
$ export SGX_KEY=/tmp/key.pem
```

Then compile the libraries and tool:

- For development:
	- HW mode: `$ make DEBUG=1 SGX_MODE=HW SGX_DEBUG=1 SGX_PRERELEASE=0`, or
	- SIM mode: `$ make DEBUG=1 SGX_MODE=SIM SGX_DEBUG=1 SGX_PRERELEASE=0`
		- `$ make` with nothing added is equivalent
- For performance evaluation:
	- HW mode: `$ make DEBUG=0 SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 CSP_MODE=1`

As an alternative to using the top-level makefile, go into each directory in `external` to compile the `libbtc` libraries, then compile the yapi library in `modules`, and finally the tool in `modules`.

After compilation, the `yapitool` should be located within its own module at `modules/yapitool/yapitool`.

## License

TODO
