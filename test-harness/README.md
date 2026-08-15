# NAT46 test harness

The harness boots a Linux kernel under QEMU, loads the freshly built
`nat46.ko`, injects JSONL packet fixtures, captures traffic on the NAT46
device, and checks the capture after the guest exits. The guest uses the pinned,
checksum-verified `myinit` v0.0.16 binary. Its network backend is restricted,
the checkout is mounted read-only, and only the capture and coverage directories
are writable.

## Requirements and local use

The full harness targets x86-64 Linux. It requires a bootable kernel image and
matching module tree, a built `nat46/modules/nat46.ko`, and these host tools:
QEMU, GNU `timeout`, `wget`, `sha256sum`, `cpio`, `gzip`, `python3`,
`jq`, `kmod`, `xz`, and `zstd`. Access to `/dev/kvm` is optional.

From the repository root:

```sh
make -C nat46/modules
TEST_FILTER=basic ./test-harness/run-test-harness
```

The relevant environment variables are:

- `KERNEL_VERSION`: exact kernel release to boot; defaults to `uname -r`.
- `KERNEL_FILE` and `KERNEL_MODULE_PATH`: explicit matching image and module
  tree; otherwise the harness resolves both from `KERNEL_VERSION`.
- `NAT46_MODULE_PATH`: exact module to place in the initramfs; defaults to the
  module in this checkout.
- `TEST_FILTER`: comma-separated substrings used to select planned tests.
  A filter that selects no tests is an error.
- `QEMU_MEM`: guest memory size; defaults to `512M`.
- `QEMU_TIMEOUT`: maximum QEMU runtime; defaults to `30m`.
- `MYINIT_PATH` and `MYINIT_SHA256`: alternate guest binary and its required
  checksum.

## Test plan and results

`test-plan` is the authoritative ordered list of test names. Every listed name
must have `tests/<name>/test.run`, and every directory containing a
`test.run` must appear in the plan. The host validates that relationship,
applies `TEST_FILTER`, and generates the guest run script before packing the
initramfs. The initial plan contains only `basic`.

Before every boot, the host removes only the selected tests' old captures and
injection logs plus the run-completion marker. A run succeeds only when the
guest writes a fresh completion marker, every selected capture is nonempty,
and every injection log reports the exact number of nonblank JSONL records.

Expected files live in `test-data/expected/<name>.jsonl`. Exact JSONL results
are compared after removing top-level timestamps. Structured packet assertions
start with `# packet assertion` and describe the required direction, receive
count, layers, fields, and optional serialized checksum validation. Custom jq
assertions must declare an exact receive count in a
`# jq assertion rx-count=N` header.
