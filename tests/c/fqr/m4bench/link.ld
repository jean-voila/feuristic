/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (C) 2026 The feuristic contributors */
/* QEMU mps2-an386 (Cortex-M4F): code+data in SSRAM1, stack/bss in SSRAM2/3. */
MEMORY
{
  ROM (rwx) : ORIGIN = 0x00000000, LENGTH = 4M
  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}
ENTRY(Reset_Handler)
SECTIONS
{
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } > ROM
  .data : { *(.data*) } > ROM
  .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(4); __bss_end = .; } > RAM
  __stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
