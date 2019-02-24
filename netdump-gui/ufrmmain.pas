unit ufrmmain;

{$mode delphi}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, Grids,
  ComCtrls, StdCtrls, windows, winsock, pcaptools,
  uwindivert in '..\uwindivert.pas',ipheader in '..\ipheader.pas';

type

  { Tfrmmain }

  Tfrmmain = class(TForm)
    btnstart: TButton;
    btnstop: TButton;
    cmbfilter: TComboBox;
    GroupBox1: TGroupBox;
    ListView1: TListView;
    StatusBar1: TStatusBar;
    procedure btnstartClick(Sender: TObject);
    procedure btnstopClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private

  public

  end;

var
  frmmain: Tfrmmain;
  cap:boolean=false;
  fromf:file;
  h:thandle;
  stop:boolean=false;
  _filter:string;
  tid:dword=0;

implementation

{$R *.lfm}

{ Tfrmmain }

procedure open_cap;
const DLT_EN10MB      =1;
begin
frmmain.StatusBar1.SimpleText :='capturing to '+'dump'+formatdatetime('hh-nn-ss-zzz', now)+'.cap';
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

procedure display(str_time,str_prot,str_srcip,src_port,str_destip,dest_port,str_len:string);
var
li:TListItem ;
begin
//showmessage('display');
li:=frmmain.ListView1.Items.Add ;
li.Caption :=str_time ;
li.SubItems.Add (str_prot );
li.SubItems.Add (str_srcip+':'+src_port );
li.SubItems.Add (str_destip+':'+dest_port );
li.SubItems.Add (str_len );
SendMessage(frmmain.ListView1.Handle, WM_VSCROLL, SB_LINEDOWN, 0);
end;


function capture(param_:pointer):dword;stdcall;
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
if param_<>nil then filter:=pchar(param_^) else filter:='ip';
//showmessage(filter );
//https://reqrypt.org/windivert-doc.html#filter_language
//filter:='outbound and tcp.SrcPort == 80'+#0;
//0 or WINDIVERT_FLAG_SNIFF or WINDIVERT_FLAG_DROP
h := WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, WINDIVERT_FLAG_SNIFF);
if (h = INVALID_HANDLE_VALUE) then
  begin
  {$i-}raise exception.Create  ('invalid handle,'+inttostr(getlasterror));{$i+}
  exit;
  end;

if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_LEN, 8192)=false then
  begin
  {$i-}raise exception.Create ('WinDivertSetParam1 failed,'+inttostr(getlasterror));{$i+}
  goto done;
  end;
if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 2048)=false then
  begin
  {$i-}raise exception.Create ('WinDivertSetParam2 failed,'+inttostr(getlasterror));{$i+}
  exit;
  end;

if cap=true then open_cap;

while 1=1 do
  begin
  if WinDivertRecv(h, @packet[0], sizeof(packet), @addr, @packet_len)=false then
  begin
  {$i-}raise exception.Create ('WinDivertRecv failed,'+inttostr(getlasterror));{$i+}
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
  //writeln(str_time+' '+str_prot+' '+str_srcip+':'+inttostr(src_port)+' '+str_destip+':'+inttostr(dest_port)+' '+str_len + ' Bytes');
  display(str_time,str_prot,str_srcip,inttostr(src_port),str_destip,inttostr(dest_port),str_len);
  if cap=true then save_frame(strtoint(str_len ),pipheader,pchar(str_time) );
  if stop =true then break;
 end;

done:
if cap=true then close_cap ;
WinDivertClose (h);

end;

procedure Tfrmmain.FormCreate(Sender: TObject);
begin

end;

procedure Tfrmmain.btnstopClick(Sender: TObject);
begin
  stop:=true;
  btnstart.enabled:=true;
  btnstop.enabled:=not btnstart.enabled;
  StatusBar1.SimpleText :='stopped';
end;

procedure Tfrmmain.btnstartClick(Sender: TObject);
begin
  ListView1.Clear ;;
  StatusBar1.SimpleText :='';
  stop:=false;
  cap:=true;
  _filter :=cmbfilter.Text;
  CreateThread (nil,$ffff,@capture,@_filter,0,tid);
  btnstart.enabled:=false;
  btnstop.enabled:=not btnstart.enabled;
  //capture(@_filter );
end;

procedure Tfrmmain.FormShow(Sender: TObject);
begin
  cmbfilter.ItemIndex :=0;

end;

end.

