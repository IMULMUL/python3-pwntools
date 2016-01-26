<% from pwnlib.util import lists, packing, fiddling, misc %>\
<%page args="string, append_null=True"/>
<%docstring>
Pushes a string onto the stack without using
null bytes or newline characters.

Example:

    >>> print(shellcraft.i386.pushstr('').rstrip())
        /* push b'\x00' */
        push 0x1
        dec byte ptr [esp]
    >>> print(shellcraft.i386.pushstr('a').rstrip())
        /* push b'a\x00' */
        push 0x61
    >>> print(shellcraft.i386.pushstr('aa').rstrip())
        /* push b'aa\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x1016060
    >>> print(shellcraft.i386.pushstr('aaa').rstrip())
        /* push b'aaa\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x1606060
    >>> print(shellcraft.i386.pushstr('aaaa').rstrip())
        /* push b'aaaa\x00' */
        push 0x1
        dec byte ptr [esp]
        push 0x61616161
    >>> print(shellcraft.i386.pushstr('aaaaa').rstrip())
        /* push b'aaaaa\x00' */
        push 0x61
        push 0x61616161
    >>> print(shellcraft.i386.pushstr('aaaa', append_null=False).rstrip())
        /* push b'aaaa' */
        push 0x61616161
    >>> print(shellcraft.i386.pushstr(b'\xc3').rstrip())
        /* push b'\xc3\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x10101c2
    >>> print(shellcraft.i386.pushstr(b'\xc3', append_null=False).rstrip())
        /* push b'\xc3' */
        push 0x...c3
    >>> with context.local():
    ...    context.arch = 'i386'
    ...    print(enhex(asm(shellcraft.pushstr("/bin/sh"))))
    68010101018134242e726901682f62696e
    >>> with context.local():
    ...    context.arch = 'i386'
    ...    print(enhex(asm(shellcraft.pushstr(""))))
    6a01fe0c24
    >>> with context.local():
    ...    context.arch = 'i386'
    ...    print(enhex(asm(shellcraft.pushstr(b"\x00", False))))
    6a01fe0c24

Args:
  string (bytes, str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>
<%
    string = misc.force_bytes(string)

    if append_null:
        string += b'\x00'
    if not string:
        return

    def okay(s):
        return b'\n' not in s and b'\x00' not in s

    if string[-1] >= 128:
        extend = b'\xff'
    else:
        extend = b'\x00'

    def pretty(n):
        return hex(n & (2 ** 32 - 1))
%>\
    /* push ${repr(string)} */
% for word in lists.group(4, string, 'fill', extend)[::-1]:
<%
    sign = packing.u32(word, 'little', 'signed')
%>\
% if sign in [0, 0xa]:
    push ${pretty(sign + 1)}
    dec byte ptr [esp]
% elif -0x80 <= sign <= 0x7f and okay(word[0:1]):
    push ${pretty(sign)}
% elif okay(word):
    push ${pretty(sign)}
% else:
<%
    a, b = fiddling.xor_pair(word, avoid=b'\x00\n')
    a = packing.u32(a, 'little', 'unsigned')
    b = packing.u32(b, 'little', 'unsigned')
%>\
    push ${pretty(a)}
    xor dword ptr [esp], ${pretty(b)}
% endif
% endfor
