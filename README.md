A set of utilities and things i use to reverse engineer on mobile.

### Why

There are certain situations in which is hard to dig through memory due to target nature.
(I.E virtual functions, struct which holds structs, which hold more structs)

### TLDR of the plugin

* attach to a specific offset using frida
* dump the whole context (registers + segments involved with the function)
* sleep the process (we may need more segments later)
* map the segments dumped and registers into binja, allow to jump and dig maintaining real context virtual addresses
* once with the context, we can now emulate the whole function or certain instructions
* we can restore the context at any time
* each instruction emulated will be filled by a comment highlighting registers values and memory accesses (r/w)

### Note

Running an emulated context maintaining untouched it's memory layout it's not simple. The emulator uses Binary Ninja loaded binary to emulate instruction (alternatively, could be possible to emulate from the virtual address of the device knowing at prior the base of the module). 
This, have pros and cons. Taking as example the scenario i was facing while developing the plugin:

* emulating at virtual device addresses was a bad idea, data and segments could be manipulated before entering our target entry point
* assuming this, we can still map the module segment to our context and align addresses
* This solved all the problems but created another big one. When the emulated context attempt to read or write from/on a pointer of target module weird situations could happens.
* To avoid this problem, a dialog will appear every time the emulator attempt to **read** on an address which point to our target which will allow to choose what to use between binja offset (0x0), virtual address on the emulated context (0x??) or read that pointer on the device.
* In addition to this - the plugin is not mapping all the segments on the emulated context but only the one actually used. Anytime the emulator attempt to read to an unmapped region, those regions will be pulled and mapped dinamycalli from the device by keeping the same virtual address

### Some more goodies

* jump to pointer
* keystone patch for optimal B/BL/BLX


###  TODO

* everything is hardcoded to work on ARM arch / ARM mode
* remove emulated instructions highlight

### Built on top of
* Binary ninja
* Frida
* Unicorn emulator
* Capstone engine
* Keystone engine

### Video demo

[![IMAGE ALT TEXT](https://img.youtube.com/vi/WhgCi7pfO1w/hqdefault.jpg)](https://www.youtube.com/watch?v=WhgCi7pfO1w&feature=youtu.be)


```
MIT License

Copyright (c) 2018 Giovanni - iGio90 - Rocca

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```