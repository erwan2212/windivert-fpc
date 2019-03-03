{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

program netdump;
{$APPTYPE CONSOLE}

uses  uwindivert in '..\uwindivert.pas',
  windows,dos,sysutils, uconsole,pcaptools;

var
  cap:boolean=false;
  _filter:string;
  fromf:file;
  h:thandle;

procedure open_cap;
const DLT_EN10MB      =1;
begin
AssignFile(FromF, 'dump'+formatdatetime('hh-nn-ss-zzz', now)+'.cap');
Rewrite (FromF,1);
write_cap_header(fromf,DLT_EN10MB);
end;

procedure close_cap;
begin
closefile(fromf);
end;

procedure save_frame(len:integer;data:pointer;ptime:pchar);
var
buf:pchar;
begin

    if len>0 then
    begin
       //mode_raw : dont forget ethernet header !
       len:=len+14;
       buf:=allocmem(len); //allocmem=getmem+Initialize
       //ethernet header 14 bytes
       buf[12]:=#8;buf[13]:=#0;
       //we could fill in the mac addresses by resolving ip to mac...
       {
       if PIP_Header(data)^.ip_srcaddr=inet_Addr(PChar(ip)) then copymemory(@buf[6],@mac[0],6);
       if PIP_Header(data)^.ip_destaddr=inet_Addr(PChar(ip)) then copymemory(@buf[0],@mac[0],6);
       }
       copymemory(@buf[14],data,len-14);
       write_cap_packet(fromf,len,ptime,buf);
       FreeMem(buf,len);
    end; //if len>0 then

end;


{$R *.res}

procedure OnPacket2(str_time,str_prot,str_srcip,src_port,str_destip,dest_port:string;len:integer;data:pointer);
begin

writeln(str_time+' '+str_prot+' '+str_srcip+':'+src_port+' '+str_destip+':'+dest_port+' '+inttostr(len) + ' Bytes');

if (cap=true) and (stop=false) then save_frame(len,data,pchar(str_time) ); //checking stop should not be necessary...
end;

begin
   //rather than  KeyPressed, we could have used getmessage/GetAsyncKeyState
  if paramcount=0 then
     begin
     writeln('netdump 1.0 by erwan2212@gmail.com');
     writeln('netdump filter [CAP]');
     writeln('see https://reqrypt.org/windivert-doc.html#filter_language for filter syntax');
     writeln('ex: netdump ip');
     writeln('ex: netdump tcp.Syn');
     writeln('ex: netdump "(tcp.DstPort==80 or tcp.DstPort==443)"');
     writeln('ex: netdump "ip.DstAddr>=192.168.1.0 and ip.DstAddr<=192.168.1.255"');
     exit;
     end;

  _filter:=paramstr(1);
  if (paramcount=2) and (pos('CAP',uppercase(cmdline))>0) then cap:=true;
  uwindivert.OnPacket :=OnPacket2;
  if uppercase(GetEnv('layer'))='FORWARD' then uwindivert.layer:= WINDIVERT_LAYER_NETWORK_FORWARD;
  if cap=true then open_cap ;
  uwindivert.capture (@_filter);
  if cap=true then close_cap  ;

end.

