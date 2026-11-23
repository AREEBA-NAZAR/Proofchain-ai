# Starts the whole local stack in three windows: chain, API, web.
# Usage (from the proofchain folder):  .\dev.ps1
# If your machine does not allow running scripts, use the manual steps in README.md.
$root = $PSScriptRoot

Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$root\contracts'; npx hardhat node"
Write-Host 'Waiting for the local chain...'
$deadline = (Get-Date).AddSeconds(45)
$chainReady = $false
while ((Get-Date) -lt $deadline) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.BeginConnect('127.0.0.1', 8545, $null, $null)
        if ($connect.AsyncWaitHandle.WaitOne(500) -and $client.Connected) {
            $client.EndConnect($connect)
            $chainReady = $true
            break
        }
    } catch {
        # The Hardhat node is still starting.
    } finally {
        $client.Dispose()
    }
    Start-Sleep -Milliseconds 500
}
if (-not $chainReady) {
    throw 'The local chain did not start on 127.0.0.1:8545 within 45 seconds.'
}

Push-Location "$root\contracts"
npx hardhat run scripts/deploy.js --network localhost
Pop-Location
if ($LASTEXITCODE -ne 0) { throw 'Contract deployment failed; API and web app were not started.' }

Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$root\backend'; .\.venv\Scripts\python -m uvicorn app.main:create_app --factory --port 8000"
Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$root\frontend'; npm run dev"

Write-Host ''
Write-Host 'Web:  http://localhost:3000'
Write-Host 'API:  http://127.0.0.1:8000/docs'
Write-Host 'Note: the local chain is in-memory. Restarting it erases all records;'
Write-Host '      delete backend\data\proofchain.db afterwards so the index matches.'
