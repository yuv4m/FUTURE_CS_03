$venv = Join-Path $PSScriptRoot "venv\Scripts\Activate.ps1"

if (Test-Path $venv) {
	. $venv
} else {
	Write-Host "Activate script not found. Acrivate venv manually."
	exit 1
}

waitress-serve --listen=*:8080 app:app