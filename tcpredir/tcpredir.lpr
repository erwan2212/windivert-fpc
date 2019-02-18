{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

program tcpredir;
{$APPTYPE CONSOLE}

uses  uwindivert in '..\uwindivert.pas',
  ipheader in '..\ipheader.pas',
  windows,sysutils,winsock, uconsole;


procedure capture(original_port,new_port:string);
var
h:thandle;
filter:pchar;
priority:word;
//packet:pointer;
packet:array[0..8191] of byte;
addr:WINDIVERT_ADDRESS;
packet_len,written:integer;
i:byte;
pipheader:PIP_Header;
src_port,dest_port:word;
  str_time,str_prot,str_srcip,str_destip,str_len:string;
label done;
begin
priority:=0;
getmem(filter,210);
//https://reqrypt.org/windivert-doc.html#filter_language
//filter:='outbound and tcp.SrcPort == 80'+#0;
filter:=pchar('((inbound and tcp.DstPort == '+original_port+') or (outbound and tcp.SrcPort == '+new_port+'))') ;
writeln('filter=' + strpas(filter));
//flag 0 or WINDIVERT_FLAG_SNIFF (1) or WINDIVERT_FLAG_DROP (2)
h := WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
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


while 1=1 do
  begin
  if WinDivertRecv(h, @packet[0], sizeof(packet), @addr, @packet_len)=false then
  begin
  writeln('WinDivertRecv failed,'+inttostr(getlasterror));
  break;
  end;

  pipheader:=@packet[0];
  str_len:=inttostr(ntohs(pipheader^.ip_totallength ));
  str_time:=FormatDateTime('hh:nn:ss:zzz', now);
  str_srcip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_srcaddr)));
  str_destip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_destaddr)));

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

      //when traffic from client to backdoor server
      if dest_port =strtoint(original_port) then //we could check for the direction as well...
      begin
      //we need to change that dst port to diverted port ...
      PTCP_Header(@pipheader^.data)^.dst_portno:=htons(strtoint(new_port));
      if WinDivertHelperCalcChecksums(@packet[0],packet_len ,nil,0)=0 then writeln('WinDivertHelperCalcChecksums failed, '+inttostr(getlasterror));
      if WinDivertSend (h,@packet[0],packet_len ,@addr,@written)=false
         then writeln('WinDivertSend failed,'+inttostr(getlasterror));
         //else writeln('WinDivertSend sent to '+str_destip+':'+new_port+','+inttostr(written)+ ' bytes');
      end;

      //when traffic from backdoor server to client
      if src_port =strtoint(new_port ) then  //we could check for the direction as well...
      begin
      //we need to change that src port to original port
      PTCP_Header(@pipheader^.data)^.src_portno:=htons(strtoint(original_port));
      if WinDivertHelperCalcChecksums(@packet[0],packet_len ,nil,0)=0 then writeln('WinDivertHelperCalcChecksums failed, '+inttostr(getlasterror));
      if WinDivertSend (h,@packet[0],packet_len ,@addr,@written)=false
         then writeln('WinDivertSend failed,'+inttostr(getlasterror));
         //else writeln('WinDivertSend sent from '+str_srcip+':'+original_port+','+inttostr(written)+ ' bytes');
      end;


  writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes');
  if KeyPressed =true then break;
 end;

done:
WinDivertClose (h);

end;

begin
  //rather than  KeyPressed, we could have used getmessage/GetAsyncKeyState
  //writeln(cmdline);
  //((inbound and tcp.DstPort == 445 ) or (outbound and tcp.SrcPort == 1337))

  if (paramcount=0) or (paramcount<>2) then
     begin
     writeln('tcpredir 1.0 by erwan2212@gmail.com');
     writeln('tcpredir original_port new_port');
     exit;
     end;

     capture(paramstr(1),paramstr(2));
end.

