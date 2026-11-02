; Installer hooks: the helper is a Windows service, so the installer (which runs
; elevated, per machine) registers it after copying the files and removes it
; before they are deleted. The bundled helper does the work through its own
; `service install|uninstall`, which copies it under Program Files.

!include "LogicLib.nsh"

; The folder the helper installs itself into, with wintun.dll beside it (both
; put there by `service install`). The 64-bit Program Files is the native one on
; x64 and arm64.
!define ROUTEWISE_HELPER_HOME "$PROGRAMFILES64\RouteWise"

; Finds the bundled helper folder in $R9: resources land under $INSTDIR\helper,
; with $INSTDIR\resources\helper as the fallback layout.
!macro RouteWiseFindBundledHelper
  StrCpy $R9 "$INSTDIR\helper"
  ${IfNot} ${FileExists} "$R9\routewise.exe"
    StrCpy $R9 "$INSTDIR\resources\helper"
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro RouteWiseFindBundledHelper
  ${If} ${FileExists} "$R9\routewise.exe"
    nsExec::ExecToLog '"$R9\routewise.exe" service install'
    Pop $0
    ${If} $0 != 0
      DetailPrint "RouteWise helper service install failed with exit code $0"
      ${IfNot} ${Silent}
        MessageBox MB_OK|MB_ICONEXCLAMATION "RouteWise was installed, but its helper service could not be set up (exit code $0). Open RouteWise to try again from the tray menu."
      ${EndIf}
    ${EndIf}
  ${Else}
    DetailPrint "The RouteWise helper is not part of this installer; skipping the service install"
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; The template checks for a running app only after this hook, and an abort
  ; there would leave the service already removed. Check here first: declining
  ; the prompt aborts before anything is touched.
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  ; An update leaves the service alone: the new install replaces it in place.
  ${If} $UpdateMode <> 1
    !insertmacro RouteWiseFindBundledHelper
    ${If} ${FileExists} "$R9\routewise.exe"
      ; Stops and deletes the service and removes the installed copy. The
      ; bundled copy runs it, since a running helper cannot delete itself.
      nsExec::ExecToLog '"$R9\routewise.exe" service uninstall'
      Pop $0
      ${If} $0 != 0
        DetailPrint "RouteWise helper service uninstall failed with exit code $0"
      ${EndIf}
    ${EndIf}
    Delete "${ROUTEWISE_HELPER_HOME}\wintun.dll"
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Only empties: the helper's settings and logs live under ProgramData and stay.
  ; The launch-at-login Run value is removed by the template itself.
  RMDir "${ROUTEWISE_HELPER_HOME}"
!macroend
