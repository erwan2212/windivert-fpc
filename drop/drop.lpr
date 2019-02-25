{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

program netdump;
{$APPTYPE CONSOLE}

uses  uwindivert in '..\uwindivert.pas',
  ipheader in '..\ipheader.pas',
  windows,sysutils,winsock, uconsole;

var
  cap:boolean=false;
  fromf:file;



procedure capture(param_:string;const flag:uint64=1);
var
h:thandle;
filter:pchar;
priority:word;
//packet:pointer;
packet:array[0..8191] of byte;
addr:WINDIVERT_ADDRESS;
packet_len:integer;
i:byte;
pipheader:PIP_Header;
src_port,dest_port:word;
str_dir,str_time,str_prot,str_srcip,str_destip,str_len:string;
label done;
begin
priority:=0;
getmem(filter,210);
writeln('filter=' + param_);
writeln('flag=' + inttostr(flag));
//https://reqrypt.org/windivert-doc.html#filter_language
//filter:='outbound and tcp.SrcPort == 80'+#0;
if param_<>'' then filter:=pchar(param_) else filter:='ip';
//0 or WINDIVERT_FLAG_SNIFF or WINDIVERT_FLAG_DROP
h := WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, flag);
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


writeln('press a key to stop');
readln;

done:

WinDivertClose (h);

end;

{$R *.res}

begin
   //rather than  KeyPressed, we could have used getmessage/GetAsyncKeyState
  //writeln(cmdline);
  if paramcount=0 then
     begin
     writeln('drop 1.0 by erwan2212@gmail.com');
     writeln('drop filter');
     writeln('see https://reqrypt.org/windivert-doc.html#filter_language for filter syntax');
     writeln('ex: drop ip');
     writeln('ex: drop tcp.Syn');
     writeln('ex: drop "(tcp.DstPort==80 or tcp.DstPort==443)"');
     writeln('ex: drop "ip.DstAddr>=192.168.1.0 and ip.DstAddr<=192.168.1.255"');
     exit;
     end;
  if paramcount=1 then
     begin
     capture(paramstr(1),WINDIVERT_FLAG_DROP);
     exit;
     end;
end.

