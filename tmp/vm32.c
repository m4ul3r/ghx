/*
 * Challenge 2: vm32
 *
 * A tiny stack-based bytecode VM. Exercises opcode-table recovery, switch
 * dispatch reading, callsites on operation handlers, field-xrefs on a
 * register-like struct (pc/sp/flags), and high p-code reading.
 *
 * Opcode encoding (each instruction 1 byte + optional 4-byte immediate):
 *
 *   0x01 PUSH_IMM  <imm32>   ; push 32-bit literal
 *   0x02 POP                 ; discard top of stack
 *   0x03 ADD                 ; pop a, pop b, push (b+a)
 *   0x04 SUB                 ; pop a, pop b, push (b-a)
 *   0x05 MUL                 ; pop a, pop b, push (b*a)
 *   0x06 DUP                 ; duplicate top of stack
 *   0x07 JMP      <off32>    ; pc += off32
 *   0x08 JZ       <off32>    ; pop a; if a == 0 then pc += off32
 *   0x09 PRINT               ; pop a, print as unsigned decimal
 *   0xFF HALT                ; set flags.halt = 1
 *
 * Build with:  gcc -O2 -fno-inline -o vm32 vm32.c
 * Strip with:  strip --strip-all vm32
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define VM_STACK_DEPTH 32
#define VM_FLAG_HALT   0x1u
#define VM_FLAG_STKOF  0x2u
#define VM_FLAG_STKUF  0x4u
#define VM_FLAG_BADOP  0x8u

struct VM {
    uint32_t stack[VM_STACK_DEPTH];
    uint32_t pc;
    uint32_t sp;
    uint32_t flags;
    const uint8_t *code;
    uint32_t code_len;
};

static void vm_init(struct VM *vm, const uint8_t *code, uint32_t code_len) {
    memset(vm, 0, sizeof(*vm));
    vm->code = code;
    vm->code_len = code_len;
}

static void vm_push(struct VM *vm, uint32_t v) {
    if (vm->sp >= VM_STACK_DEPTH) { vm->flags |= VM_FLAG_STKOF; return; }
    vm->stack[vm->sp++] = v;
}

static uint32_t vm_pop(struct VM *vm) {
    if (vm->sp == 0) { vm->flags |= VM_FLAG_STKUF; return 0; }
    return vm->stack[--vm->sp];
}

static uint32_t vm_read_imm32(struct VM *vm) {
    if (vm->pc + 4 > vm->code_len) { vm->flags |= VM_FLAG_BADOP; return 0; }
    uint32_t v =
        (uint32_t)vm->code[vm->pc]          |
        ((uint32_t)vm->code[vm->pc + 1] << 8) |
        ((uint32_t)vm->code[vm->pc + 2] << 16) |
        ((uint32_t)vm->code[vm->pc + 3] << 24);
    vm->pc += 4;
    return v;
}

static void vm_op_add(struct VM *vm) { uint32_t a = vm_pop(vm); uint32_t b = vm_pop(vm); vm_push(vm, b + a); }
static void vm_op_sub(struct VM *vm) { uint32_t a = vm_pop(vm); uint32_t b = vm_pop(vm); vm_push(vm, b - a); }
static void vm_op_mul(struct VM *vm) { uint32_t a = vm_pop(vm); uint32_t b = vm_pop(vm); vm_push(vm, b * a); }
static void vm_op_dup(struct VM *vm) {
    if (vm->sp == 0) { vm->flags |= VM_FLAG_STKUF; return; }
    vm_push(vm, vm->stack[vm->sp - 1]);
}
static void vm_op_print(struct VM *vm) { printf("%u\n", vm_pop(vm)); }

static int vm_step(struct VM *vm) {
    if (vm->flags & VM_FLAG_HALT) return 0;
    if (vm->pc >= vm->code_len) { vm->flags |= VM_FLAG_BADOP; return 0; }
    uint8_t op = vm->code[vm->pc++];
    switch (op) {
        case 0x01: vm_push(vm, vm_read_imm32(vm)); break;
        case 0x02: (void)vm_pop(vm); break;
        case 0x03: vm_op_add(vm); break;
        case 0x04: vm_op_sub(vm); break;
        case 0x05: vm_op_mul(vm); break;
        case 0x06: vm_op_dup(vm); break;
        case 0x07: {
            int32_t off = (int32_t)vm_read_imm32(vm);
            vm->pc = (uint32_t)((int32_t)vm->pc + off);
            break;
        }
        case 0x08: {
            int32_t off = (int32_t)vm_read_imm32(vm);
            uint32_t a = vm_pop(vm);
            if (a == 0) vm->pc = (uint32_t)((int32_t)vm->pc + off);
            break;
        }
        case 0x09: vm_op_print(vm); break;
        case 0xFF: vm->flags |= VM_FLAG_HALT; break;
        default:   vm->flags |= VM_FLAG_BADOP; break;
    }
    return (vm->flags & (VM_FLAG_HALT | VM_FLAG_BADOP | VM_FLAG_STKOF | VM_FLAG_STKUF)) == 0;
}

static void vm_run(struct VM *vm, uint32_t max_steps) {
    for (uint32_t i = 0; i < max_steps; ++i) {
        if (!vm_step(vm)) break;
    }
}

/* Program: compute (3 + 4) * 6, print, then halt. */
static const uint8_t bytecode_a[] = {
    0x01, 0x03, 0x00, 0x00, 0x00,   /* PUSH_IMM 3  */
    0x01, 0x04, 0x00, 0x00, 0x00,   /* PUSH_IMM 4  */
    0x03,                            /* ADD          */
    0x01, 0x06, 0x00, 0x00, 0x00,   /* PUSH_IMM 6  */
    0x05,                            /* MUL          */
    0x09,                            /* PRINT        */
    0xFF,                            /* HALT         */
};

/* Program: countdown loop from 5 to 0, printing each. */
static const uint8_t bytecode_b[] = {
    0x01, 0x05, 0x00, 0x00, 0x00,   /* [00] PUSH_IMM 5            */
    0x06,                            /* [05] DUP                   */
    0x09,                            /* [06] PRINT                 */
    0x01, 0x01, 0x00, 0x00, 0x00,   /* [07] PUSH_IMM 1            */
    0x04,                            /* [0c] SUB                   */
    0x06,                            /* [0d] DUP                   */
    0x08, 0x04, 0x00, 0x00, 0x00,   /* [0e] JZ +4  (jumps to HALT) */
    0x07, 0xef, 0xff, 0xff, 0xff,   /* [13] JMP -17 (back to DUP)  */
    0xFF,                            /* [18] HALT                  */
};

int main(int argc, char **argv) {
    const uint8_t *code = bytecode_a;
    uint32_t len = sizeof(bytecode_a);
    if (argc >= 2 && strcmp(argv[1], "--loop") == 0) {
        code = bytecode_b;
        len = sizeof(bytecode_b);
    }
    struct VM vm;
    vm_init(&vm, code, len);
    vm_run(&vm, 1000);
    if (vm.flags & VM_FLAG_BADOP)  fprintf(stderr, "vm: bad opcode\n");
    if (vm.flags & VM_FLAG_STKOF)  fprintf(stderr, "vm: stack overflow\n");
    if (vm.flags & VM_FLAG_STKUF)  fprintf(stderr, "vm: stack underflow\n");
    return vm.flags & VM_FLAG_BADOP ? 1 : 0;
}
