A simple, portable tool for measuring SMTP server delay, delay variation and throughput. Feel free to contact <support@halon.io>

[![Coverity Scan Build](https://img.shields.io/coverity/scan/7287.svg)](https://scan.coverity.com/projects/halonsecurity-smtpping)

Usage
-----
The two first examples measures delay, and the last example measures
throughput (`-r -w0`) using 50 threads (`-P50`).

```
$ smtpping test@halon.io
$ smtpping test@halon.io @10.2.0.31
$ smtpping -P50 -r -w0 test@halon.io @10.2.0.31
```

Building
--------
Building on *NIX can be done manually using a C++ compiler such as GNU's 
`g++` or by using `cmake`. It could be easily ported to a Makefile.

```
$ cmake .
$ make
```

Building on Windows
-------------------
A project file for Dev-C++ is included, should be quite portable to eg. VS.
