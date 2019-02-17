{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

program proxy;
{$APPTYPE CONSOLE}

uses  uwindivert in '..\uwindivert.pas',
  ipheader in '..\ipheader.pas',
  windows,sysutils,winsock, uconsole;

var
  ports:array[0..65535] of longword;


procedure capture(original_port,new_port,new_ip:string);
var
h:thandle;
filter:pchar;
priority:word;
//packet:pointer;
packet,divert:array[0..8191] of byte;
addr:WINDIVERT_ADDRESS;
packet_len,written,payload_len:integer;
i:byte;
pipheader:PIP_Header;
src_port,dest_port:word;
  str_time,str_prot,str_srcip,str_destip,str_len:string;
  //
  ip_header,ipv6_header, icmp_header, icmpv6_header, tcp_header,udp_header, payload:pointer;

label done;
begin
priority:=0;
getmem(filter,210);
//https://reqrypt.org/windivert-doc.html#filter_language
filter:=pchar('((outbound and tcp.DstPort == '+original_port+') or (inbound and tcp.SrcPort == '+new_port+'))') ;
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
  writeln('WinDivertSetParam failed,'+inttostr(getlasterror));
  goto done;
  end;
if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 2048)=false then
  begin
  writeln('WinDivertSetParam failed,'+inttostr(getlasterror));
  exit;
  end;

fillchar(ports,sizeof(ports),0);

//look https://parsiya.net/blog/2015-10-19-proxying-hipchat-part-3-ssl-added-and-removed-here/ for https  but different mitm approach?

while 1=1 do
  begin
  if WinDivertRecv(h, @packet[0], sizeof(packet), @addr, @packet_len)=false then
  begin
  writeln('WinDivertRecv failed,'+inttostr(getlasterror));
  break;
  end;


  {
  //we are not going to use this for now but rather use PIP_Header type to parse our packet
  //note that we could be passing nil for some of the pointers
  WinDivertHelperParsePacket(@packet[0], packet_len, @ip_header,
			@ipv6_header, @icmp_header, @icmpv6_header, @tcp_header, @udp_header,
                        @payload, @payload_len);
  }

  writeln('direction:'+inttostr(addr.Direction ));
  //writeln('IfIdx:'+inttostr(addr.IfIdx ));

  pipheader:=@packet[0];

  str_time:=FormatDateTime('hh:nn:ss:zzz', now);
  str_len:=inttostr(ntohs(pipheader^.ip_totallength) );
  str_srcip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_srcaddr)));
  str_destip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_destaddr)));

  For i := 0 To 8 Do
        If pipheader^.ip_protocol = IPPROTO[i].itype Then str_prot := IPPROTO[i].name;

  //tcp
      If pipheader^.ip_protocol=6 then
      begin
           src_port:=  ntohs(PTCP_Header(@pipheader^.data )^.src_portno ) ;
           dest_port:= ntohs(PTCP_Header(@pipheader^.data )^.dst_portno )  ;
      end;
      //udp
      If pipheader^.ip_protocol=17 then
      begin
           src_port:=   ntohs(PUDP_Header(@pipheader^.data )^.src_portno ) ;
           dest_port:= ntohs(PUDP_Header(@pipheader^.data )^.dst_portno )  ;
      end;

      //when traffic from client to transparent proxy server
      //Make sure that Privoxy's own requests aren't redirected as well, if running local
      //accept-intercepted-requests=1 in privoxy
      if (dest_port =strtoint(original_port)) and  (addr.Direction <>WINDIVERT_DIRECTION_INBOUND) then
      begin
      //we need to change that dst port to new_port ...
      writeln('client to remote');
      //the below is to associate a remote ip to a local dynamic port
      //a bit rough but works for now...
      //addr.Direction :=1;
      ports[PTCP_Header(@pipheader^.data)^.src_portno ]:= pipheader^.ip_destaddr;
      pipheader^.ip_destaddr:=(inet_Addr(PansiChar(ansistring(new_ip)))); //htonl(INADDR_LOOPBACK)
      PTCP_Header(@pipheader^.data)^.dst_portno:=htons(strtoint(new_port));
      {
      //we could be using a new structure (divert) but to send we wont...
      }
      //
      if WinDivertHelperCalcChecksums(@packet[0],packet_len ,nil,0)=0 then writeln('WinDivertHelperCalcChecksums1 failed, '+inttostr(getlasterror));
      if WinDivertSend (h,@packet[0],packet_len ,@addr,@written)=false
      //if WinDivertSend (h,@divert[0],packet_len ,@addr,@written)=false
         then writeln('WinDivertSend failed,'+inttostr(getlasterror));
         //else writeln('WinDivertSend sent to '+ansistring(new_ip)+':'+new_port+','+inttostr(written)+ ' bytes');
      end;

      //when traffic from transparent proxy server to client
      if (src_port =strtoint(new_port )) and (addr.Direction =WINDIVERT_DIRECTION_INBOUND)
                   and (ports[PTCP_Header(@pipheader^.data)^.dst_portno]<>0) then
      begin
      //we need to change that src port to original_port
      //addr.Direction :=0 ;
      writeln('proxy to client');
      writeln('original ip='+strpas(Inet_Ntoa(TInAddr(ports[PTCP_Header(@pipheader^.data)^.dst_portno]))));
      pipheader^.ip_srcaddr:=ports[PTCP_Header(@pipheader^.data)^.dst_portno] ;
      PTCP_Header(@pipheader^.data)^.src_portno:=htons(strtoint(original_port));
      {
      //we could be using a new structure (divert) to send but we wont...
      }
      //
      if WinDivertHelperCalcChecksums(@packet[0],packet_len ,nil,0)=0 then writeln('WinDivertHelperCalcChecksums2 failed, '+inttostr(getlasterror));
      //if WinDivertSend (h,@divert[0],packet_len ,@addr,@written)=false
      if WinDivertSend (h,@packet[0],packet_len ,@addr,@written)=false
         then writeln('WinDivertSend failed,'+inttostr(getlasterror));
         //else writeln('WinDivertSend sent from '+ansistring(ports[PTCP_Header(@pipheader^.data)^.dst_portno])+':'+original_port+','+inttostr(written)+ ' bytes');
      end;


  writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes');
  if KeyPressed =true then break;
 end;

done:
WinDivertClose (h);

end;

begin
  //rather than  KeyPressed, we could have used getmessage/GetAsyncKeyState

  if (paramcount=0) or (paramcount<>3) then
     begin
     writeln('proxy-tcp 1.0 by erwan2212@gmail.com');
     writeln('proxy-tcp original_port new_port new_ip');
     writeln('remember that if you divert to a local app, this local app could be diverted as well.');
     exit;
     end;

     capture(paramstr(1),paramstr(2),paramstr(3));
end.
