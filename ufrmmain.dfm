object frmmain: Tfrmmain
  Left = 249
  Height = 285
  Top = 123
  Width = 485
  Caption = 'windivert'
  ClientHeight = 285
  ClientWidth = 485
  Color = clBtnFace
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  LCLVersion = '1.8.2.0'
  object Button1: TButton
    Left = 16
    Height = 25
    Top = 16
    Width = 75
    Caption = 'start'
    OnClick = Button1Click
    TabOrder = 0
  end
  object Memo1: TMemo
    Left = 16
    Height = 209
    Top = 56
    Width = 449
    Lines.Strings = (
      'Memo1'
    )
    TabOrder = 1
  end
  object Button2: TButton
    Left = 104
    Height = 25
    Top = 16
    Width = 75
    Caption = 'stop'
    OnClick = Button2Click
    TabOrder = 2
  end
end
