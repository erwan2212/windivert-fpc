{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

program proxy;
{$APPTYPE CONSOLE}

uses  uwindivert in '..\uwindivert.pas',
  ipheader in '..\ipheader.pas',
  JwaWinDNS,
  windows,dos,sysutils,winsock,inifiles, uconsole;

type DNS_ANSWER=record
  nameptr:word;
  wtype:word;
  wclass:word;
  ttl:dword;
  datalength:word;
  ip:dword;
end;

var
  ports:array[0..65535] of longword;

  function readini(section,ident,default:string;config:string=''):string;
  var
  ini:tinifile;
  fname:string;
  begin
  writeln(section);
  if config<>'' then fname:=config else fname:='config.INI';
  if FileExists(fname) then
    begin
      ini:=tinifile.Create (fname);
      result:=ini.ReadString (section,ident,default  );
      freeandnil(ini);
    end
    else result:=default;

  end;

procedure capture(layer:WINDIVERT_LAYER;port:string);
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
  str_newip,str_dir,str_time,str_prot,str_srcip,str_destip,str_len:string;
  //
  ip_header,ipv6_header, icmp_header, icmpv6_header, tcp_header,udp_header, payload:pointer;
 PDNS_MESSAGE_BUFFER_:  PDNS_MESSAGE_BUFFER;
 PDNS_RECORD_:PDNS_RECORD;
 status:DNS_STATUS;
 PDNS_HEADER_:PDNS_HEADER;
 buf_:array [0..1023] of byte;
 offset:byte=0;
 ip:dword=0;
 AnswerCount: WORD=0;
label done;
begin
priority:=0;
getmem(filter,210);
//https://reqrypt.org/windivert-doc.html#filter_language
//if rogue server is local, return traffic direction could be seen as OUTBOUND
//filter:=pchar('((outbound and udp.DstPort == '+original_port+') or (inbound and udp.SrcPort == '+new_port+'))')
//we only want to catch return traffic ... to eventually divert it
filter:=pchar('udp.SrcPort == '+port );
writeln('filter=' + strpas(filter));
if layer=WINDIVERT_LAYER_NETWORK_FORWARD then writeln('layer=FORWARD');
h := WinDivertOpen(filter, layer, priority, 0);
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

  pipheader:=@packet[0];

  str_time:=FormatDateTime('hh:nn:ss:zzz', now);
  str_len:=inttostr(ntohs(pipheader^.ip_totallength) );
  str_srcip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_srcaddr)));
  str_destip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_destaddr)));

  if isByteOn(addr.Direction,0)=true then str_dir:='INBOUND';
  if isByteOn(addr.Direction,0)=false then str_dir:='OUTBOUND';
  //writeln('direction:'+str_dir);
  //writeln('IfIdx:'+inttostr(addr.IfIdx ));

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
           dest_port:=  ntohs(PUDP_Header(@pipheader^.data )^.dst_portno )  ;
      end;

      //when traffic from client to transparent proxy server
      //we dont want to divert outbound traffic here...
      //we dont even need to filter inbound so the below is useless for now
      if (dest_port=strtoint(port)) and  (isByteOn(addr.Direction,0)=false) then  // WINDIVERT_DIRECTION_OUTBOUND
      begin
      writeln('client to remote');
      //
      if WinDivertHelperCalcChecksums(@packet[0],packet_len ,nil,0)=0 then writeln('WinDivertHelperCalcChecksums1 failed, '+inttostr(getlasterror));
      if WinDivertSend (h,@packet[0],packet_len ,@addr,@written)=false
         then writeln('WinDivertSend failed,'+inttostr(getlasterror));
      end;

      //when traffic from transparent proxy server to client
      //if rogue server is local, direction could be seen as OUTBOUND (not INBOUND as expected)
      if (src_port =strtoint(port )) and ((layer=WINDIVERT_LAYER_NETWORK_FORWARD ) or (isByteOn(addr.Direction,0)=true)) // WINDIVERT_DIRECTION_INBOUND
      then
      begin
      writeln('**************************************');
      writeln('remote to client');
      //facts : ip header=20, udp header=8 - dns header is 12, query is variable, answer type A is 16
      //PDNS_MESSAGE_BUFFER_:= @Pudp_Header(@pipheader^.data)^.data [0]; //bad idea, we dont want to alter our original packet for now
      try
      status:=-1;
      PDNS_MESSAGE_BUFFER_ := GetMem(ntohs(Pudp_Header(@pipheader^.data)^.udp_length)-8);
      CopyMemory (PDNS_MESSAGE_BUFFER_ , @Pudp_Header(@pipheader^.data)^.data [0],ntohs(Pudp_Header(@pipheader^.data)^.udp_length)-8);
      PDNS_HEADER_ :=@PDNS_MESSAGE_BUFFER_^.MessageHead;
      AnswerCount:=ntohs(PDNS_HEADER_^.AnswerCount );
      writeln('AnswerCount:'+inttostr(AnswerCount)) ;
      DNS_BYTE_FLIP_HEADER_COUNTS ( PDNS_HEADER_  );
      //finally...lets parse our message ... might be easier to do it manually parsing bytes ...
      PDNS_RECORD_:=nil;
      status:=DnsExtractRecordsFromMessage_UTF8(PDNS_MESSAGE_BUFFER_ ,Pudp_Header(@pipheader^.data)^.udp_length , @PDNS_RECORD_ );
      Freemem (PDNS_MESSAGE_BUFFER_ );
      finally
      end;
      if status<>0 then writeln('status:'+inttostr(status)); //9003: name does not exist   //9005 refused
      if (PDNS_RECORD_ <>nil) and (AnswerCount=1) then
         begin
         writeln('ttl:'+inttostr(PDNS_RECORD_^.dwTtl) +' pName:'+strpas(PDNS_RECORD_^.pName)+' wtype:'+inttostr(PDNS_RECORD_^.wType));
         if PDNS_RECORD_^.wType=DNS_TYPE_A then
            begin
            writeln('A.IpAddress:'+strpas(Inet_Ntoa(TInAddr(PDNS_RECORD_^.Data.A.IpAddress))));
            //writeln('packet_len:'+inttostr(packet_len) );
            //writeln('udp_length:'+inttostr(ntohs(Pudp_Header(@pipheader^.data)^.udp_length)));
            str_newip:=readini (strpas(PDNS_RECORD_^.pName),'ip','');
            if str_newip<>'' then
            begin
            offset:=ntohs(Pudp_Header(@pipheader^.data)^.udp_length)-8; //minus udp header
            copymemory(@buf_[0],@Pudp_Header(@pipheader^.data)^.data [0],offset);
            //lets modify last 4 bytes - dodgy as we assume there is 1 answer of type A
            //buf_[offset-4]:=1;buf_[offset-3]:=2;buf_[offset-2]:=3;buf_[offset-1]:=4; //ip
            ip:=inet_Addr(PansiChar(ansistring(str_newip)));
            copymemory(@buf_[offset-4],@ip,4);
            //lets put our modified buffer back
            copymemory(@Pudp_Header(@pipheader^.data)^.data [0],@buf_[0],offset);
            //debug purpose
            //for offset:=0 to packet_len-1 do write(inttohex(packet[offset],2)+' ');
            //writeln;
            end;
            end;
         if (PDNS_RECORD_^.wType=DNS_TYPE_PTR) and (PDNS_RECORD_^.Data.PTR.pNameHost<>nil) then writeln(strpas(PDNS_RECORD_^.Data.PTR.pNameHost) ) ;
         //if (PDNS_RECORD_^.wType=DNS_TYPE_CNAME) and (PDNS_RECORD_^.Data.CNAME.pNameHost<>nil) then writeln(strpas(PDNS_RECORD_^.Data.CNAME.pNameHost)) ;
         end;
      //
      if WinDivertHelperCalcChecksums(@packet[0],packet_len ,nil,0)=0 then writeln('WinDivertHelperCalcChecksums2 failed, '+inttostr(getlasterror));
      //if WinDivertSend (h,@divert[0],packet_len ,@addr,@written)=false
      if WinDivertSend (h,@packet[0],packet_len ,@addr,@written)=false
         then writeln('WinDivertSend failed,'+inttostr(getlasterror));
         //else writeln('WinDivertSend sent from '+ansistring(ports[Pudp_Header(@pipheader^.data)^.dst_portno])+':'+original_port+','+inttostr(written)+ ' bytes');
      end;

  writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes'+' Dir:'+str_dir);
  if KeyPressed =true then break;
 end;

done:
WinDivertClose (h);

end;

{$R *.res}

begin
  //rather than  KeyPressed, we could have used getmessage/GetAsyncKeyState

  if (paramcount=0) then
     begin
     writeln('intercept-dns 1.0 by erwan2212@gmail.com');
     writeln('intercept-dns incoming_port [local]');
     writeln('remember that if you divert to a local app, this local app could be diverted as well.');
     exit;
     end;

  if uppercase(GetEnv('layer'))='FORWARD'
        then capture(WINDIVERT_LAYER_NETWORK_FORWARD,paramstr(1))
        else capture(WINDIVERT_LAYER_NETWORK,paramstr(1));
end.

