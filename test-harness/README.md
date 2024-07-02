This is a (long overdue) test harness for the nat46.ko module.

The goal is to trivially run it in two modes:

- as a CI in github
- as a local test bench

The high-level setup is more or less how this module was originally written some years ago:
a kernel running under KVM, mounting the host filesystem via p9, and loading
the module from there.

However, as an experiment, I decided to do it in a much more lightweight fashion -
rather than going the classic route of building the disk image of the root device and
mounting that, with the help of LLM I built a custom /init, which gives enough of
a shell-like experience to do the system bring-up and tests within it.

In part it is done to test-drive another project of mine: https://github.com/ayourtch/oside,
whose purpose in life is to allow to relatively easily do packet manipulations from Rust.

Admittedly, it is a fair bit less feature-complete than Scapy at this point, but not having
to deal with installation and management of Python inside the disk image is arguably worth the hassle.

The init shell has a command "oside", which gives a rudimentary TUI to edit the jsonl files with
the packets. Also one can use "pcap2json" command inside the shell to convert the files inside the shell.

The tests are sitting under tests/ directory, and need to be executed one-by-one from startup.run - this
script is executed immediately at bootup. In the future the tests *may* be moved into autoexec.run, which
is also run at startup, but with a delay that allows the user to break into interactive shell.

Each test should configure nat46 device(s) as it sees fit, inject some packets, and capture the expected
packets into test-data/captured/*testname*.jsonl. After the VM run concludes, each captured file is compared
with its sibling file in test-data/expected/*testname*.jsonl, and is expected to be identical, modulo timestamps.

Admittedly this is not *too* much of a framework, but hopefully should allow for some relatively useful tests
to be done relatively easily.

