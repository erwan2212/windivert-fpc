unit ufrmmain;

{$mode delphi}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, Grids,
  ComCtrls, StdCtrls, windows,  pcaptools,
  uwindivert in '..\uwindivert.pas';

//type OnPacket=procedure (str_time,str_prot,str_srcip,src_port,str_destip,dest_port,str_len:string) of object;

type
   { Tfrmmain }
   Tfrmmain = class(TForm)
    btnstart: TButton;
    btnstop: TButton;
    cmbfilter: TComboBox;
    GroupBox1: TGroupBox;
    GroupBox2: TGroupBox;
    ListView1: TListView;
    StatusBar1: TStatusBar;
    procedure btnstartClick(Sender: TObject);
    procedure btnstopClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure GroupBox2Click(Sender: TObject);
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
li:=frmmain.ListView1.Items.Add ;
li.Caption :=str_time ;
li.SubItems.Add (str_prot );
li.SubItems.Add (str_srcip+':'+src_port );
li.SubItems.Add (str_destip+':'+dest_port );
li.SubItems.Add (inttostr(len) );
//https://docs.microsoft.com/en-us/windows/desktop/controls/wm-vscroll
//ressource intensive
//SendMessage(frmmain.ListView1.Handle, WM_VSCROLL, SB_LINEDOWN, 0);

if (cap=true) and (stop=false) then save_frame(len,data,pchar(str_time) ); //checking stop should not be necessary...
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
  cap:=true;
  _filter :=cmbfilter.Text;
  //
  if cap=true then open_cap;
  //
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

end.

