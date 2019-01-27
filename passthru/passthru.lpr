{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

program netfilter;
{$APPTYPE CONSOLE}

uses  uwindivert in '..\uwindivert.pas',
  ipheader in '..\ipheader.pas',
  windows,sysutils,winsock, uconsole;

const
  MAXBUF   =   400000;
 MAXBATCH =   $FF;

const batch = 1;

function passthru(param:pointer):dword;stdcall;
var
   packet:array[0..MAXBUF-1] of UINT8;
packet_len, addr_len:UINT;
     addr:array[0..MAXBATCH-1] of WINDIVERT_ADDRESS;
     h:thandle;
begin
h:=thandle(param^);
writeln('thread:'+IntToStr(GetCurrentThreadId ));
while 1=1 do
      begin
        addr_len := batch * sizeof(WINDIVERT_ADDRESS);
        if WinDivertRecv(h, @packet[0], sizeof(packet), @addr, @packet_len)=false then
        begin
        writeln('WinDivertRecv failed,'+inttostr(getlasterror));
        break;
        end;
        if WinDivertSend (h,@packet[0],packet_len ,@addr ,nil)=false then
        begin
        writeln('WinDivertSend failed,'+inttostr(getlasterror));
        break;
        end;
      if KeyPressed =true then break;
      end;
end;


procedure capture(param_:string);
var
h:thandle;
filter:pchar;
priority:word;

i:byte;

tid:dword;
label done;
begin
priority:=0;
getmem(filter,210);
//https://reqrypt.org/windivert-doc.html#filter_language
//filter:='outbound and tcp.SrcPort == 80'+#0;
if param_<>'' then filter:=pchar(param_) else filter:='ip';
h := WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0); //no flag
if (h = INVALID_HANDLE_VALUE) then
  begin
  writeln('invalid handle,'+inttostr(getlasterror));
  exit;
  end;

if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_LEN, 8192)=false then
  begin
  writeln('WinDivertSetParam1 failed,'+inttostr(getlasterror));
  goto done;
  end;
if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 2048)=false then
  begin
  writeln('WinDivertSetParam2 failed,'+inttostr(getlasterror));
  exit;
  end;


for i:=1 to 4 do CreateThread (nil,1,@passthru,@h,0,tid);

passthru (@h);

done:
WinDivertClose (h);

end;

begin
  //rather than  KeyPressed, we could have used getmessage/GetAsyncKeyState
  if paramcount=1 then capture(paramstr(1)) else capture ('');
end.

