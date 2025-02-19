# script to show a customized version of a wireshark trace. 
david.portabella@gmail.com, January 2025

use and modify this script to show a wireshark trace in your customized way.

first capture a trace with Wireshark and save it to a file named trace_capture.pcapng
this dir contains an example of a FTP trace, `example_trace_capture.pcapng`.

run:
```
$ pip install pyshark
$ python show_trace.py example_trace_capture.pcapng

packet_number	from	to	direction	payload
3	192.168.0.11:50605	192.168.0.11:2121	NEW CONNECTION
7	192.168.0.11:2121	192.168.0.11:50605	S->C	220 pyftpdlib 2.0.1 ready.

9	192.168.0.11:50605	192.168.0.11:2121	C->S	FEAT

11	192.168.0.11:2121	192.168.0.11:50605	S->C	211-Features supported:

12	192.168.0.11:2121	192.168.0.11:50605	S->C	 EPRT
 EPSV
 MDTM
 MFMT
 MLST type*;perm*;size*;modify*;unique*;unix.mode;unix.uid;unix.gid;
 REST STREAM
 SIZE
 TVFS
 UTF8

14	192.168.0.11:2121	192.168.0.11:50605	S->C	211 End FEAT.

17	192.168.0.11:50605	192.168.0.11:2121	C->S	AUTH TLS

19	192.168.0.11:2121	192.168.0.11:50605	S->C	500 Command "AUTH" not understood.

21	192.168.0.11:50605	192.168.0.11:2121	C->S	OPTS UTF8 ON

23	192.168.0.11:2121	192.168.0.11:50605	S->C	530 Log in with USER and PASS first.

25	192.168.0.11:50605	192.168.0.11:2121	C->S	USER bob

27	192.168.0.11:2121	192.168.0.11:50605	S->C	331 Username ok, send password.

29	192.168.0.11:50605	192.168.0.11:2121	C->S	PASS mypassword

31	192.168.0.11:2121	192.168.0.11:50605	S->C	230 Login successful.

33	192.168.0.11:50605	192.168.0.11:2121	C->S	OPTS UTF8 ON

35	192.168.0.11:2121	192.168.0.11:50605	S->C	501 Invalid argument.

37	192.168.0.11:50605	192.168.0.11:2121	C->S	OPTS MLST type;perm;size;modify;unix.mode;unix.uid;unix.gid;

39	192.168.0.11:2121	192.168.0.11:50605	S->C	200 MLST OPTS type;perm;size;modify;unix.mode;unix.uid;unix.gid;

41	192.168.0.11:50605	192.168.0.11:2121	C->S	PWD

43	192.168.0.11:2121	192.168.0.11:50605	S->C	257 "/" is the current directory.

45	192.168.0.11:50605	192.168.0.11:2121	C->S	PASV

47	192.168.0.11:2121	192.168.0.11:50605	S->C	227 Entering passive mode (192,168,0,11,197,175).

49	192.168.0.11:50608	192.168.0.11:50607	NEW CONNECTION
53	192.168.0.11:50605	192.168.0.11:2121	C->S	LIST

55	192.168.0.11:2121	192.168.0.11:50605	S->C	125 Data connection already open. Transfer starting.

57	192.168.0.11:50607	192.168.0.11:50608	S->C	-rw-r--r--   1 david    staff           6 Jan 12 20:29 hello.txt
-rwx------   1 david    staff      872423 Oct 14 08:52 screenshot.png

60	192.168.0.11:2121	192.168.0.11:50605	S->C	226 Transfer complete.

65	192.168.0.11:50605	192.168.0.11:2121	C->S	TYPE I

67	192.168.0.11:2121	192.168.0.11:50605	S->C	200 Type set to: Binary.

69	192.168.0.11:50605	192.168.0.11:2121	C->S	SIZE hello.txt

71	192.168.0.11:2121	192.168.0.11:50605	S->C	213 6

73	192.168.0.11:50605	192.168.0.11:2121	C->S	MDTM hello.txt

75	192.168.0.11:2121	192.168.0.11:50605	S->C	213 20250112202916

77	192.168.0.11:50605	192.168.0.11:2121	C->S	PASV

79	192.168.0.11:2121	192.168.0.11:50605	S->C	227 Entering passive mode (192,168,0,11,197,183).

81	192.168.0.11:50616	192.168.0.11:50615	NEW CONNECTION
85	192.168.0.11:50605	192.168.0.11:2121	C->S	RETR hello.txt

87	192.168.0.11:2121	192.168.0.11:50605	S->C	125 Data connection already open. Transfer starting.

89	192.168.0.11:50615	192.168.0.11:50616	S->C	world

93	192.168.0.11:2121	192.168.0.11:50605	S->C	226 Transfer complete.

97	192.168.0.11:50605	192.168.0.11:2121	C->S	QUIT

99	192.168.0.11:2121	192.168.0.11:50605	S->C	221 Goodbye.
```
