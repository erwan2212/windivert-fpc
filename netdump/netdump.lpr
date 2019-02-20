{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

program netdump;
{$APPTYPE CONSOLE}

uses  uwindivert in '..\uwindivert.pas',
  ipheader in '..\ipheader.pas',
  windows,dos,sysutils,winsock, uconsole,pcaptools;

//function EnableRouter(var pHandle: THandle; pOverlapped: POVERLAPPED): DWORD; stdcall;external 'iphlpapi.dll';

var
  cap:boolean=false;
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

procedure capture(param_:string;const layer:WINDIVERT_LAYER=WINDIVERT_LAYER_NETWORK; const flag:uint64=1);
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
if param_<>'' then filter:=pchar(param_) else filter:='ip';
writeln('filter=' + param_);
writeln('flag=' + inttostr(flag));
if layer=WINDIVERT_LAYER_NETWORK then writeln('layer=LAYER_NETWORK') else writeln('layer=LAYER_NETWORK_FORWARD');
//https://reqrypt.org/windivert-doc.html#filter_language
//filter:='outbound and tcp.SrcPort == 80'+#0;
//0 or WINDIVERT_FLAG_SNIFF or WINDIVERT_FLAG_DROP
h := WinDivertOpen(filter, layer, priority, flag);
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

if cap=true then open_cap;

while 1=1 do
  begin
  if WinDivertRecv(h, @packet[0], sizeof(packet), @addr, @packet_len)=false then
  begin
  writeln('WinDivertRecv failed,'+inttostr(getlasterror));
  break;
  end;

  pipheader:=@packet[0];
  str_len:=inttostr(ntohs(pipheader^.ip_totallength)) ;
  str_time:=FormatDateTime('hh:nn:ss:zzz', now);
  str_srcip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_srcaddr)));
  str_destip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_destaddr)));
  src_port:=0;
  dest_port:=0;

  if isByteOn(addr.Direction,0)=true then str_dir:='INBOUND';
  if isByteOn(addr.Direction,0)=false then str_dir:='OUTBOUND';

  For i := 0 To 8 Do
        If pipheader^.ip_protocol = IPPROTO[i].itype Then str_prot := IPPROTO[i].name;

  //tcp
      If pipheader^.ip_protocol=6 then
      begin
           src_port:=   ntohs(PTCP_Header(@pipheader^.data )^.src_portno ) ;
           dest_port:= ntohs(PTCP_Header(@pipheader^.data )^.dst_portno )  ;
      end;
      //udp
      If pipheader^.ip_protocol=17 then
      begin
           src_port:=   ntohs(PUDP_Header(@pipheader^.data )^.src_portno ) ;
           dest_port:= ntohs(PUDP_Header(@pipheader^.data )^.dst_portno )  ;
      end;

  //writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes Dir.:'+str_dir);
  writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes');
  if cap=true then save_frame(strtoint(str_len ),pipheader,pchar(str_time) );
  if KeyPressed =true then break;
 end;

done:
if cap=true then close_cap ;
WinDivertClose (h);

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
  if paramcount=1 then
     begin
     if uppercase(GetEnv('layer'))='FORWARD'
        then capture(paramstr(1),WINDIVERT_LAYER_NETWORK_FORWARD,WINDIVERT_FLAG_SNIFF)
        else capture(paramstr(1),WINDIVERT_LAYER_NETWORK,WINDIVERT_FLAG_SNIFF);
     exit;
     end;
  if (paramcount=2) and (pos('CAP',uppercase(cmdline))>0) then
     begin
     cap:=true;
     if uppercase(GetEnv('layer'))='FORWARD'
        then capture(paramstr(1),WINDIVERT_LAYER_NETWORK_FORWARD,WINDIVERT_FLAG_SNIFF)
        else capture(paramstr(1),WINDIVERT_LAYER_NETWORK,WINDIVERT_FLAG_SNIFF);
     exit;
     end;
end.

