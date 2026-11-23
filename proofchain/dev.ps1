# Starts the whole local stack in three windows: chain, API, web.
# Usage (from the proofchain folder):  .\dev.ps1
# If your machine does not allow running scripts, use the manual steps in README.md.
$root = $PSScriptRoot

Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$root\contracts'; npx hardhat node"
Write-Host 'Waiting for the local chain...'
Start-Sleep -Seconds 8

Push-Location "$root\contracts"
npx hardhat run scripts/deploy.js --network localhost
Pop-Location

Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$root\backend'; .\.venv\Scripts\python -m uvicorn app.main:create_app --factory --port 8000"
Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$root\frontend'; npm run dev"

Write-Host ''
Write-Host 'Web:  http://localhost:3000'
Write-Host 'API:  http://127.0.0.1:8000/docs'
Write-Host 'Note: the local chain is in-memory. Restarting it erases all records;'
Write-Host '      delete backend\data\proofchain.db afterwards so the index matches.'
