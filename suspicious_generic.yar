import "pe"

rule suspicious_Imphash_Confluence_Exploitation_Sep2021_1 : suspicious pedll cobaltstrike {
    meta:
        author = "Nils Kuhnert"
        description = "Triggers on imphash of DLL suspected for loading CobaltStrike on compromised Confluence instances."
    condition:
        pe.imphash() == "8cc5d88a302eb2bbae9b557e6bdabfd9"   
}

rule suspicious_Opcodes_Confluence_Exploitation_Sep2021_1 : suspicious pedll cobaltstrike {
    meta:
        author = "Nils Kuhnert"
        description = "Triggers on opcodes of DLL suspected for loading CobaltStrike on compromised Confluence instances."
    strings:
        /*
                                     LAB_6338159c                                    XREF[1]:     633815f9(j)  
        6338159c 8b 85 44        MOV        EAX,dword ptr [RBP + 0x744]
                 07 00 00
        633815a2 3b 85 3c        CMP        EAX,dword ptr [RBP + 0x73c]
                 07 00 00
        633815a8 7d 51           JGE        LAB_633815fb
        633815aa 8b 85 44        MOV        EAX,dword ptr [RBP + 0x744]
                 07 00 00
        633815b0 48 98           CDQE
        633815b2 48 8b 95        MOV        RDX,qword ptr [RBP + 0x730]
                 30 07 00 00
        633815b9 48 01 d0        ADD        RAX,RDX
        633815bc 0f b6 00        MOVZX      EAX,byte ptr [RAX]
        633815bf 89 c1           MOV        ECX,EAX
        633815c1 8b 85 44        MOV        EAX,dword ptr [RBP + 0x744]
                 07 00 00
        633815c7 99              CDQ
        633815c8 f7 bd 38        IDIV       dword ptr [RBP + 0x738]
                 07 00 00
        633815ce 89 d0           MOV        EAX,EDX
        633815d0 48 98           CDQE
        633815d2 0f b6 84        MOVZX      EAX,byte ptr [RBP + RAX*0x1 + 0x700]
                 05 00 07 
                 00 00
        633815da 31 c1           XOR        ECX,EAX
        633815dc 8b 85 44        MOV        EAX,dword ptr [RBP + 0x744]
                 07 00 00
        633815e2 48 98           CDQE
        633815e4 48 8b 95        MOV        RDX,qword ptr [RBP + 0x730]
                 30 07 00 00
        633815eb 48 01 d0        ADD        RAX,RDX
        633815ee 89 ca           MOV        EDX,ECX
        633815f0 88 10           MOV        byte ptr [RAX],DL
        633815f2 83 85 44        ADD        dword ptr [RBP + 0x744],0x1
                 07 00 00 01
        */
        $ = { 8b 85 44 07 00 00 3b 85 3c 07 00 00 7d ?? 8b 85 44 07 00 00 4? 98 4? 8b 95 30 07 00 00 4? 01 d0 0f b6 00 89 c1 8b 85 44 07 00 00 99 f7 bd 38 07 00 00 89 d0 4? 98 0f b6 84 05 00 07 00 00 31 c1 8b 85 44 07 00 00 4? 98 4? 8b 95 30 07 00 00 4? 01 d0 89 ca 88 10 83 85 44 07 00 00 01 }
        /*
                                     LAB_63381546                                    XREF[1]:     63381590(j)  
        63381546 8b 85 48        MOV        EAX,dword ptr [RBP + 0x748]
                 07 00 00
        6338154c 3b 85 40        CMP        EAX,dword ptr [RBP + 0x740]
                 07 00 00
        63381552 7d 3e           JGE        LAB_63381592
        63381554 8b 85 48        MOV        EAX,dword ptr [RBP + 0x748]
                 07 00 00
        6338155a 83 e0 01        AND        EAX,0x1
        6338155d 85 c0           TEST       EAX,EAX
        6338155f 75 28           JNZ        LAB_63381589
        63381561 8b 85 4c        MOV        EAX,dword ptr [RBP + 0x74c]
                 07 00 00
        63381567 48 98           CDQE
        63381569 48 8b 95        MOV        RDX,qword ptr [RBP + 0x730]
                 30 07 00 00
        63381570 48 01 c2        ADD        RDX,RAX
        63381573 8b 85 48        MOV        EAX,dword ptr [RBP + 0x748]
                 07 00 00
        63381579 48 98           CDQE
        6338157b 0f b6 44        MOVZX      EAX,byte ptr [RBP + RAX*0x1 + -0x50]
                 05 b0
        63381580 88 02           MOV        byte ptr [RDX],AL
        63381582 83 85 4c        ADD        dword ptr [RBP + 0x74c],0x1
                 07 00 00 01
                             LAB_63381589                                    XREF[1]:     6338155f(j)  
        63381589 83 85 48        ADD        dword ptr [RBP + 0x748],0x1
                 07 00 00 01
        */
        $ = { 8b 85 48 07 00 00 3b 85 40 07 00 00 7d ?? 8b 85 48 07 00 00 83 e0 01 85 c0 75 ?? 8b 85 4c 07 00 00 4? 98 4? 8b 95 30 07 00 00 4? 01 c2 8b 85 48 07 00 00 4? 98 0f b6 44 05 b0 88 02 83 85 4c 07 00 00 01 83 85 48 07 00 00 01 }
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and any of them
}