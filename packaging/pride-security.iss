; Instalador do Pride Security Desktop — Inno Setup 6
;
; INSTALACAO POR USUARIO, E ISSO NAO E DETALHE
; --------------------------------------------
; `PrivilegesRequired=lowest` mais `{userpf}` instalam em %LOCALAPPDATA% sem
; UAC. Duas consequencias que decidem o resto do desenho:
;
;   1. Nao ha prompt de administrador. Num notebook corporativo isso e a
;      diferenca entre o usuario conseguir avaliar o produto e abrir um chamado.
;   2. `Program Files` seria somente leitura para o usuario comum, entao gravar
;      o banco ao lado do executavel falharia depois da instalacao -- na maquina
;      do usuario, nunca na de quem empacotou. `app/paths.py` ja resolve isso
;      apontando para %LOCALAPPDATA%, e o instalador nao contradiz.
;
; O QUE A DESINSTALACAO NAO APAGA
; --------------------------------
; O banco em %LOCALAPPDATA%\PrideSecurity fica. E dado de seguranca da
; organizacao, com historico de decisao; apagar por padrao seria perda
; silenciosa. A desinstalacao pergunta, e o padrao e manter.
;
; ASSINATURA
; ----------
; Sem assinatura de codigo o SmartScreen avisa em toda instalacao, e a reputacao
; zera a cada versao nova. Registrado como pendencia real em
; docs/PROJECT_STATE.md; nao ha contorno tecnico, so certificado.

#define Nome "Pride Security"
#define Versao "0.1.0"
#define Publicador "Pride Security"
#define Exe "PrideSecurity.exe"

[Setup]
AppId={{7F3C2A91-5B4E-4D18-9C6A-2E8B1D0F4A73}
AppName={#Nome}
AppVersion={#Versao}
AppVerName={#Nome} {#Versao}
AppPublisher={#Publicador}
DefaultDirName={userpf}\PrideSecurity
DefaultGroupName={#Nome}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist\installer
OutputBaseFilename=PrideSecurity-{#Versao}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#Exe}
; O aplicativo escuta so em 127.0.0.1; a licenca e o aviso ficam na propria tela.
SetupLogging=yes

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na area de trabalho"; \
  GroupDescription: "Atalhos:"; Flags: unchecked

[Files]
Source: "..\dist\PrideSecurity\*"; DestDir: "{app}"; \
  Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#Nome}"; Filename: "{app}\{#Exe}"
Name: "{group}\Desinstalar {#Nome}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\{#Nome}"; Filename: "{app}\{#Exe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#Exe}"; Description: "Abrir o {#Nome} agora"; \
  Flags: nowait postinstall skipifsilent

[UninstallDelete]
; So o arquivo de trava, que e estado de execucao. O banco NAO entra aqui.
Type: files; Name: "{localappdata}\PrideSecurity\running.port"

[Code]
// Pergunta antes de apagar o banco. O padrao e manter: quem desinstala para
// atualizar nao espera perder o historico de decisoes, e essa perda seria
// silenciosa e irreversivel.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Dados: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    Dados := ExpandConstant('{localappdata}\PrideSecurity');
    if DirExists(Dados) then
    begin
      if MsgBox('Apagar tambem os dados do {#Nome} (banco de achados, decisoes '
                + 'e historico) em:' + #13#10 + Dados + #13#10#13#10
                + 'Escolha Nao para manter os dados.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(Dados, True, True, True);
    end;
  end;
end;
