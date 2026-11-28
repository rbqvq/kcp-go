//go:build go1.28

package kcp

import "golang.org/x/sys/cpu"

var (
	hasAESAsmLOONG64 = cpu.Loong64.HasLSX
	hasAESAsmRISCV64 = cpu.RISCV64.HasV && cpu.RISCV64.HasZvkn && cpu.RISCV64.HasZbb && cpu.RISCV64.VLENB >= 16
)
