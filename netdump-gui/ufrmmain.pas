unit ufrmmain;

{$mode delphi}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, Grids,
  ComCtrls, StdCtrls, Menus, windows, clipbrd, winsock,  pcaptools,
  uwindivert in '..\uwindivert.pas',ipheader in '..\ipheader.pas';

//type OnPacket=procedure (str_time,str_prot,str_srcip,src_port,str_destip,dest_port,str_len:string) of object;

type
   { Tfrmmain }
   Tfrmmain = class(TForm)
    btnstart: TButton;
    btnstop: TButton;
    chkcap: TCheckBox;
    cmbfilter: TComboBox;
    GroupBox1: TGroupBox;
    GroupBox2: TGroupBox;
    ListView1: TListView;
    MainMenu1: TMainMenu;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    MenuItem3: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    MenuItem6: TMenuItem;
    OpenDialog1: TOpenDialog;
    StatusBar1: TStatusBar;
    procedure btnstartClick(Sender: TObject);
    procedure btnstopClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GroupBox2Click(Sender: TObject);
    procedure ListView1DblClick(Sender: TObject);
    procedure MenuItem2Click(Sender: TObject);
    procedure MenuItem3Click(Sender: TObject);
    procedure MenuItem5Click(Sender: TObject);
    procedure MenuItem6Click(Sender: TObject);
  private
  public

  end;



var
  frmmain: Tfrmmain;
  cap:boolean=false;
  fromf:file;
  h:thandle;
  //stop:boolean=false;
  _filter:string;
  tid:dword=0;
  _tick:int64=0;
  _total:int64=0;
  _count:int64=0;
  _current_file:string='';


implementation

{$R *.lfm}

{ Tfrmmain }

function open_cap:string;
var
  fname:string;
begin
fname:='dump'+formatdatetime('hh-nn-ss-zzz', now)+'.cap';
frmmain.StatusBar1.SimpleText :='capturing to '+fname;
AssignFile(FromF, fname);
Rewrite (FromF,1);
write_cap_header(fromf,DLT_EN10MB);
result:=fname;
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

procedure OnPacket2(str_time,str_prot,str_srcip,src_port,str_destip,dest_port:string;len:integer;data:pointer);
var
li:TListItem ;
current:int64;
speed:double;
begin


//every sec, look at how mucb bytes were captured
_total:=_total+len ;
current:=GetTickCount64;
if (current -_tick>SysUtils.MSecsPerSec)  then
   begin
   speed:= _total / (current -_tick) ; //number of bytes captured div by elapsed time since last point in time
   frmmain.StatusBar1.simpletext:=FormatFloat('0.00', speed) + ' KB/S';
   _tick:=GetTickCount64; //new point in time
   _total:=0; //we took our measure, lets reset total bytes count
   end;
//

//display packet details
inc(_count );
li:=frmmain.ListView1.Items.Add ;
li.Caption :=inttostr(_count) ;
li.SubItems.Add (str_time );
li.SubItems.Add (str_prot );
li.SubItems.Add (str_srcip+':'+src_port );
li.SubItems.Add (str_destip+':'+dest_port );
li.SubItems.Add (inttostr(len) );
//https://docs.microsoft.com/en-us/windows/desktop/controls/wm-vscroll
//ressource intensive
//SendMessage(frmmain.ListView1.Handle, WM_VSCROLL, SB_LINEDOWN, 0);

if (cap=true) and (stop=false) then save_frame(len,data,pchar(str_time) ); //checking stop should not be necessary...
end;

procedure open_frames(filename:string);
var fromf:file;
eth_prot,NumRead,i,len: Integer;
ethbuf,ipbuf,buf:tpacketbuffer;
pipheader: PIP_Header;
{
ptcpheader:PTCP_Header;
pudpheader:PUDP_Header;
}
str_time,str_len,str_srcip,str_destip ,str_prot:string;
src_port ,dest_port:word;
tv_sec,tv_usec:longint;
offset:int64=0;
begin

try
AssignFile(FromF, FileName);
Reset(FromF, 1);
except
  on e:exception do
    begin
    raise exception.create('open_frames:'+e.message);
    end;
end;

//cap header 24
fillchar(buf,sizeof(buf),0);
BlockRead(fromf,buf,sizeof(tcpdump_file_header),numread);
inc(offset,sizeof(tcpdump_file_header));

if (Ptcpdump_file_header(@buf).linktype<>DLT_EN10MB) then //and (linktype<>DLT_IEEE802_11) then
  begin
  CloseFile(FromF);
  raise exception.create('only LinkType DLT_EN10MB is supported');
  end;


repeat
//packet header 16bytes
fillchar(buf,sizeof(buf),0);
BlockRead(fromf,buf,sizeof(tcpdump_packet),numread);
inc(offset,sizeof(tcpdump_packet));
len:=Ptcpdump_packet(@buf).len;
tv_sec:= Ptcpdump_packet(@buf).timeval.tv_sec; //1551571200.442000000
tv_usec:=Ptcpdump_packet(@buf).timeval.tv_usec;
str_time:=FormatDateTime('hh:nn:ss',UnixTimeToDateTime(tv_sec)); //unixtime=epoch time =secs.usec
str_time:=str_time +'.'+ format('%.3d',[round(tv_usec/1000)]);
fillchar(ethbuf,sizeof(ethbuf),0);
//ethernet header 14 bytes
BlockRead(fromf,ethbuf,14,numread);
inc(offset,14);
//or the entire frame
//BlockRead(fromf,ethbuf,len,numread);

//ip header len-14
fillchar(ipbuf,sizeof(ipbuf),0);
BlockRead(fromf,ipbuf,len-14,numread);
inc(offset,len-14);
pipheader :=@ipbuf;
str_srcip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_srcaddr)));
str_destip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_destaddr)));
str_len:=inttostr(ntohs(pipheader^.ip_totallength)) ;
For i := 0 To 8 Do If pipheader^.ip_protocol = IPPROTO[i].itype Then str_prot := IPPROTO[i].name;
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
//pb : on perds l heure ...
OnPacket2(str_time,str_prot,str_srcip,inttostr(src_port),str_destip,inttostr(dest_port),len-14,@ipbuf[0]);

until (NumRead = 0) or (eof(fromf)) or (HiWord(GetAsyncKeyState(VK_ESCAPE)) <> 0);
//
CloseFile(FromF);
frmmain.statusbar1.simpletext :='Done Loading CAP file!';
end;



procedure Tfrmmain.btnstopClick(Sender: TObject);
var
i:byte=0;
begin
  stop:=true;
  //check if thread terminates
      while i<30 do
      begin
      if WaitForSingleObject(h, 50) <> WAIT_TIMEOUT then break;
      Application.ProcessMessages ;
      inc(i);
      end;
  //
  if cap=true then close_cap ;
  //
  btnstart.enabled:=true;
  btnstop.enabled:=not btnstart.enabled;
  StatusBar1.SimpleText :='stopped';
end;

procedure Tfrmmain.btnstartClick(Sender: TObject);
begin
  ListView1.Clear ;;
  StatusBar1.SimpleText :='';
  stop:=false;
  cap:=chkcap.Checked ;
  _filter :=cmbfilter.Text;
  //
  if cap=true then _current_file := open_cap;
  //
  _count:=0;
  uwindivert.OnPacket :=OnPacket2 ;
  h:=CreateThread (nil,$ffff,@uwindivert.capture,@_filter,0,tid);
  //
  btnstart.enabled:=false;
  btnstop.enabled:=not btnstart.enabled;

end;





procedure Tfrmmain.FormShow(Sender: TObject);
begin
  cmbfilter.ItemIndex :=0;

end;

procedure Tfrmmain.GroupBox2Click(Sender: TObject);
begin

end;

procedure Tfrmmain.ListView1DblClick(Sender: TObject);
var
num:int64;
begin
  if ListView1.Selected =nil then exit;
  num:=strtoint(ListView1.Selected.Caption );

end;

procedure Tfrmmain.MenuItem2Click(Sender: TObject);
begin
  application.Terminate ;
end;

procedure Tfrmmain.MenuItem3Click(Sender: TObject);
begin
  ListView1.Clear ;
  _count:=0;
  _current_file :='';
  if OpenDialog1.Execute=false then exit ;
  _current_file :=OpenDialog1.FileName;
  open_frames (_current_file );
  {
  ATBinHex1.OpenStream (TFileStream.Create(OpenDialog1.FileName, fmOpenRead or fmShareDenyNone));
  ATBinHex1.PosAt(sizeof(tcpdump_file_header));
  ATBinHex1.SetSelection(sizeof(tcpdump_file_header),32,false);
  ATBinHex1.Redraw ;
  }
end;

procedure Tfrmmain.MenuItem5Click(Sender: TObject);
begin
if ListView1.Selected =nil then exit;
Clipboard.AsText := ListView1.Selected.SubItems [0]+','+
                 ListView1.Selected.SubItems [1]+','+
                 ListView1.Selected.SubItems [2]+'->'+
                 ListView1.Selected.SubItems [3]+','+
                 ListView1.Selected.SubItems [4];
end;

procedure Tfrmmain.MenuItem6Click(Sender: TObject);
begin
  _current_file :='';
  _count:=0;
  ListView1.Clear ;
end;

end.

