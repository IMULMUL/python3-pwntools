#!/usr/bin/env python3
import argparse
import sys
from string import hexdigits
import codecs
import re

import pwnlib.log
from pwnlib import asm
from pwnlib.context import context

pwnlib.log.install_default_handler()

parser = argparse.ArgumentParser(
    description='Disassemble bytes into text format'
)

parser.add_argument(
    'hex',
    metavar='hex',
    nargs='*',
    help='Hex-string to disasemble. If none are supplied, then it uses stdin in non-hex mode.'
)

parser.add_argument(
    '-c', '--context',
    metavar='<opt>',
    choices=context.architectures,
    default='i386',
    help='The architecture of the shellcode (default: i386), choose from:\n%s' %
    ', '.join(
        context.architectures))


def main():
    args = parser.parse_args()

    if len(args.hex) > 0:
        dat = ''.join(args.hex)
        dat = re.sub(r'\s', '', dat)
        if not set(hexdigits) >= set(dat):
            print("This is not a hex string")
            exit(-1)
        dat = codecs.decode(dat, 'hex')
    else:
        dat = sys.stdin.buffer.read()

    print(asm.disasm(dat, arch=args.context))

if __name__ == '__main__':
    main()
