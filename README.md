# coredump-translator
Translate the coredump file to get register and call stack information
Usage: 
    python core_translator.py <coredump filepath>
   
Example:
[root@matrix coredump-translator]# python core_translator.py core.32716
Exception Information:
rax            0x400657 4195927
rbx            0x0      0
rcx            0x7ffffffa       2147483642
rdx            0x7f450fbbca00   139934593436160
rsi            0x400656 4195926
rdi            0x400657 4195927
rbp            0x7ffd0269f840   0x7ffd0269f840
rsp            0x7ffd0269f840   0x7ffd0269f840
r8             0x7f450f846988   139934589806984
r9             0x5      5
r10            0x0      0
r11            0x0      0
r12            0x400440 4195392
r13            0x7ffd0269f970   140724643953008
r14            0x0      0
r15            0x0      0
rip            0x400549 0x400549 <c+28>
eflags         0x10206  [ PF IF RF ]
cs             0x33     51
ss             0x2b     43
ds             0x0      0
es             0x0      0
fs             0x0      0
gs             0x0      0
#0  0x0000000000400549 in c ()
#1  0x000000000040057e in b ()
#2  0x000000000040059a in a ()
#3  0x00000000004005af in main ()
#4  0x00007f450f81fc05 in __libc_start_main (main=0x4005a1 <main>, argc=1, ubp_av=0x7ffd0269f978, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffd0269f968) at ../csu/libc-start.c:274
#5  0x0000000000400469 in _start ()
