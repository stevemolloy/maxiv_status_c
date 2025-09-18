# About

Grabs data about the MAXIV accelerators from their publicly facing status page and prints the data to stdout.

Can be useful as part of a tmux status bar.

# Quick start
```console
$ cc -o build build.c
$ ./build
[INFO] created directory `bin`
[INFO] CMD: cc -Wall -Wextra -Wshadow -Wvla -ggdb -o bin/maxiv_status src/main.c -lssl -lcrypto
$ ./bin/maxiv_status
| R3 368.8 mA | R1 498.7 mA | SPF 143.8 pC
```
