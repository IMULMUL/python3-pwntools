<% from pwnlib.util import lists, packing, fiddling, misc %>\
<%page args="string, append_null=True"/>
<%docstring>
Pushes a bytes or string onto the stack without using
null bytes or newline characters.

Example:

    >>> print(shellcraft.amd64.pushstr('').rstrip())
        /* push b'\x00' */
        push 0x1
        dec byte ptr [rsp]
    >>> print(shellcraft.amd64.pushstr('a').rstrip())
        /* push b'a\x00' */
        push 0x61
    >>> print(shellcraft.amd64.pushstr('aa').rstrip())
        /* push b'aa\x00' */
        push 0x...
        xor dword ptr [rsp], 0x...
    >>> print(shellcraft.amd64.pushstr('aaa').rstrip())
        /* push b'aaa\x00' */
        push 0x...
        xor dword ptr [rsp], 0x...
    >>> print(shellcraft.amd64.pushstr('aaaa').rstrip())
        /* push b'aaaa\x00' */
        push 0x61616161
    >>> print(shellcraft.amd64.pushstr(b'aaa\xc3').rstrip())
        /* push b'aaa\xc3\x00' */
        push 0x...
        xor dword ptr [rsp], 0x...
    >>> print(shellcraft.amd64.pushstr(b'aaa\xc3', append_null=False).rstrip())
        /* push b'aaa\xc3' */
        push 0x...
    >>> print(shellcraft.amd64.pushstr(b'\xc3').rstrip())
        /* push b'\xc3\x00' */
        push 0x...
        xor dword ptr [rsp], 0x...
    >>> print(shellcraft.amd64.pushstr(b'\xc3', append_null=False).rstrip())
        /* push b'\xc3' */
        push 0x...c3
    >>> with context.local():
    ...    context.arch = 'amd64'
    ...    print(enhex(asm(shellcraft.pushstr("/bin/sh"))))
    48b801010101010101015048b82e63686f2e72690148310424
    >>> with context.local():
    ...    context.arch = 'amd64'
    ...    print(enhex(asm(shellcraft.pushstr(""))))
    6a01fe0c24
    >>> with context.local():
    ...    context.arch = 'amd64'
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
        return hex(n & (2 ** 64 - 1))
%>\
    /* push ${repr(string)} */
% for word in lists.group(8, string, 'fill', extend)[::-1]:
<%
    sign = packing.u64(word, 'little', 'signed')
%>\
% if sign in (0, 0xa):
    push ${pretty(sign + 1)}
    dec byte ptr [rsp]
% elif -0x80 <= sign <= 0x7f and okay(word[0:1]):
    push ${pretty(sign)}
% elif -0x80000000 <= sign <= 0x7fffffff and okay(word[:4]):
    push ${pretty(sign)}
% elif okay(word):
    mov rax, ${hex(sign)}
    push rax
% elif word[4:] == b'\x00\x00\x00\x00':
<%
    a,b = fiddling.xor_pair(word[:4], avoid=b'\x00\n')
    a   = packing.u32(a, 'little', 'unsigned')
    b   = packing.u32(b, 'little', 'unsigned')
%>\
    push ${pretty(a)}
    xor dword ptr [rsp], ${pretty(b)}
% else:
<%
    a,b = fiddling.xor_pair(word, avoid=b'\x00\n')
    a   = packing.u64(a, 'little', 'unsigned')
    b   = packing.u64(b, 'little', 'unsigned')
%>\
    mov rax, ${pretty(a)}
    push rax
    mov rax, ${pretty(b)}
    xor [rsp], rax
% endif
% endfor
