{
As for just installing a kernel mode driver, you may use the Service Controller (sc.exe).
Use sc create [service name] binPath= [path to your .sys file] type= kernel to create a kernel-mode service
and sc start [service name] to start it.
Don't forget to sc stop and sc delete it before making changes to the driver.
}
unit ufrmmain;

interface

uses
  Windows, sysutils,Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls,ipheader,winsock,uwindivert;

type

  { TForm1 }

  Tfrmmain = class(TForm)
    Button1: TButton;
    Memo1: TMemo;
    Button2: TButton;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
   private
    { Private declarations }
  public
    { Public declarations }
  end;




var
  frmmain: Tfrmmain;
  stop:boolean;



implementation

{$R *.dfm}

procedure Tfrmmain.Button1Click(Sender: TObject);
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
  str_time,str_prot,str_srcip,str_destip,str_len:string;
label done;
begin
stop:=false;
priority:=0;
getmem(filter,210);
//https://reqrypt.org/windivert-doc.html#filter_language
//filter:='outbound and tcp.SrcPort == 80'+#0;
filter:='ip';
h := WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
if (h = INVALID_HANDLE_VALUE) then
  begin
  showmessage('invalid handle,'+inttostr(getlasterror));
  exit;
  end;

if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_LEN, 8192)=false then
  begin
  showmessage('WinDivertSetParam1 failed,'+inttostr(getlasterror));
  goto done;
  end;
if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 2048)=false then
  begin
  showmessage('WinDivertSetParam2 failed,'+inttostr(getlasterror));
  exit;
  end;

while 1=1 do
  begin

  if WinDivertRecv(h, @packet[0], sizeof(packet), @addr, @packet_len)=false then
  begin
  showmessage('WinDivertRecv failed,'+inttostr(getlasterror));
  break;
  end;

  pipheader:=@packet[0];

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

  memo1.lines.add(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes');

  Application.ProcessMessages ;

  if stop=true then break;
  end;

done:
WinDivertClose (h);

end;

procedure Tfrmmain.Button2Click(Sender: TObject);
begin
stop:=true;
end;


end.
