# llws

A low level web socket parsing library. This library draws inspiration from the
[hffix](https://github.com/jamesdbrock/hffix) library for fast and efficient encoding and decoding of messages directly
on the I/O buffer.

This library is not a web socket engine, it is only a library to encode and
decode frames. There is no threading or network I/O.

