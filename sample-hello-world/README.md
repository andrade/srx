**OBSOLETE** – Needs update

---

Minimal example. Initializes the Target Platform and then performs an update.

Links with the dummy implementation of the SRX by default. This should be done with e.g. a soft link by make (fetch from environment variable?) and then this security token is used. To change the ST, we set the env var to something else via terminal (and recompile).

```
SRX_IMPL ?= ../secure-token-dummy/libdummy.a
```

`SRX_IMPL` can be exported before make or set during make to something else, for example, to `../secure-token-phone/client`.

Idea is to have a minimal hello world that allows easy switching between dummy and others to have running example.

(Soft linking to ST not done.)
