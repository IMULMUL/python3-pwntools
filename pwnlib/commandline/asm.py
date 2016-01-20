#!/usr/bin/env python3
import argparse
import sys

from pwn import *

from . import common

parser = argparse.ArgumentParser(
    description='Assemble shellcode into bytes'
)

parser.add_argument(
    'lines',
    metavar='line',
    nargs='*',
    help='Lines to assemble. If none are supplied, use stdin'
)

parser.add_argument(
    "-f", "--format",
    help="Output format (defaults to hex for ttys, otherwise raw)",
    choices=['raw', 'hex', 'string']
)

parser.add_argument(
    "-o", "--output",
    metavar='file',
    help="Output file (defaults to stdout)",
    type=argparse.FileType('wb'),
    default=sys.stdout.buffer
)

parser.add_argument(
    '-c', '--context',
    metavar='context',
    action='append',
    type=common.context_arg,
    choices=common.choices,
    help='The os/architecture/endianness/bits the shellcode will run in (default: linux/i386), choose from: %s' % common.choices,
)


parser.add_argument(
    '-d',
    '--debug',
    help='Debug the shellcode with GDB',
    action='store_true'
)


def main():
    args = parser.parse_args()
    tty = args.output.isatty()

    data = '\n'.join(args.lines) or sys.stdin.read()
    output = asm(data.replace(';', '\n'))
    fmt = args.format or ('hex' if tty else 'raw')
    formatters = {
        'r': bytes,
        'h': enhex,
        's': lambda d: repr(d)[1:]
    }

    if args.debug:
        proc = gdb.debug_shellcode(output, arch=context.arch)
        proc.interactive()
        sys.exit(0)

    output = formatters[fmt[0]](output)
    if isinstance(output, str):
        output = output.encode('utf8')
    args.output.write(output)

    if tty and fmt is not 'raw':
        args.output.write(b'\n')

if __name__ == '__main__':
    main()
