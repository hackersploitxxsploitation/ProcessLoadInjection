# ProcessLoadInjection
Injeçao de DLL via injeçao de shellcode
Injeçao de DLL  furtiva via injeçao de shellcode para pentesters e  hackers eticos



Fluxo de Ataque->> 1- OpenProcess Obtenha um HANDLE para o processo na qual quer injetar
2-VirtualAllocEx-> aloque memoria para seu shellcode
3-WriteProcessMemory-> iscreva o shellcode na memoria do seu processo.
4-CreateRemoteThread()->  Crie uma Thread   remota para execuçao do nosso payloada
5-Nosso shellcode iria  chmar a  DLL  e irar expotara nossa funçao  para execuçao

para evitar detecçoes por AV ,use  NtCreateThreadEx;
se pode cripotgrafar a carga util enfim vai da criaatividade do autor.
**Ob:Ainda falta testar 
Detalhes da tecnica: Em vez  de carregar nossa DLL num processo remoto por meio de injetor,podemos injetar uma carga util na memoria do processo e a carga util   carregara  dinamicamente nossa DLL   e  executara o codigo.
Nome da tecnica:ProcessLoadInjection.  --> Autor:hackersploitxxsploitation
Nao sei se alguem ja fezalgo parecido se sim me digam.
