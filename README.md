# p1ng

A utility that sends a single ICMP echo request with the following options:
* Additional payload data
* Spoofed source IP address
* ...and more!

**Note:** This software is intended for personal learning and testing purposes.

## Install

Clone the repository, `sh build.sh`, and then `sh install.sh`.

The install script creates a symlink to the binary, so you only need to install once even if you rebuild later.

## Usage

When using `p1ng`, I recommend running tcpdump or wireshark so you can check packet contents.

**Note:** `p1ng` creates raw sockets so you'll need to run it as root.

```
Usage: p1ng [OPTIONS] <DSTIP>

Options:
  -d  DATA     Payload data to send
  -h           Display this usage information
  -m           Set the More Fragments (MF) flag in the IP header
  -s  SRCIP    Spoof the source IP address
  -w  SECONDS  Seconds to wait for a reply, only relevant when source address isn't spoofed (default=5)
```

## Examples

### Send payload data

```
$ p1ng -d foobar 1.2.3.4

Got reply!
'foobar'
```

### Spoof source IP

```
$ p1ng -s 4.3.2.1 1.2.3.4
```
