<#
.SYNOPSIS
    Initializes a Git repository and pushes the project to GitHub.

.DESCRIPTION
    This script prepares the phishing-triage-bot project for GitHub:
      1. Initializes git (if not already initialized)
      2. Stages all files
      3. Creates the initial commit
      4. Prompts for the GitHub repository URL
      5. Adds the remote and pushes to main

.NOTES
    Run from the project root directory:
        .\publish_github.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== Phishing Triage Bot - GitHub Publisher ===" -ForegroundColor Cyan
Write-Host ""

# -- 1. Check for git -----------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: git is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# -- 2. Initialize git if needed ------------------------------
if (Test-Path ".git") {
    Write-Host "[OK] Git repository already initialized." -ForegroundColor Green
} else {
    Write-Host "Initializing git repository..." -ForegroundColor Yellow
    git init
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: git init failed." -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Git repository initialized." -ForegroundColor Green
}

# -- 3. Stage all files ----------------------------------------
Write-Host "Staging files..." -ForegroundColor Yellow
git add .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: git add failed." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Files staged." -ForegroundColor Green

# -- 4. Create initial commit ----------------------------------
# Check if there are changes to commit
$status = git status --porcelain
if (-not $status) {
    Write-Host "[OK] Nothing to commit - working tree clean." -ForegroundColor Green
} else {
    Write-Host "Creating initial commit..." -ForegroundColor Yellow
    git commit -m "Initial commit - Phishing Triage Bot"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: git commit failed." -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Initial commit created." -ForegroundColor Green
}

# -- 5. Rename branch to main ----------------------------------
git branch -M main
Write-Host "[OK] Branch set to 'main'." -ForegroundColor Green

# -- 6. Add remote origin --------------------------------------
$existingRemote = git remote 2>&1
if ($existingRemote -match "origin") {
    Write-Host "[OK] Remote 'origin' already configured:" -ForegroundColor Green
    $currentUrl = git remote get-url origin
    Write-Host "     $currentUrl" -ForegroundColor Gray
    Write-Host ""
    $change = Read-Host "Do you want to change it? (y/N)"
    if ($change -eq "y" -or $change -eq "Y") {
        $repoUrl = Read-Host "Enter the new GitHub repository URL"
        if (-not $repoUrl) {
            Write-Host "ERROR: No URL provided. Aborting." -ForegroundColor Red
            exit 1
        }
        git remote set-url origin $repoUrl
        Write-Host "[OK] Remote updated to $repoUrl" -ForegroundColor Green
    }
} else {
    Write-Host ""
    $repoUrl = Read-Host "Enter your GitHub repository URL (e.g. https://github.com/user/phishing-triage-bot.git)"
    if (-not $repoUrl) {
        Write-Host "ERROR: No URL provided. Aborting." -ForegroundColor Red
        exit 1
    }
    git remote add origin $repoUrl
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to add remote." -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Remote 'origin' added." -ForegroundColor Green
}

# -- 7. Push to GitHub -----------------------------------------
Write-Host ""
Write-Host "Pushing to GitHub (main)..." -ForegroundColor Yellow
git push -u origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: git push failed. Check your credentials and repository URL." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Successfully published to GitHub! ===" -ForegroundColor Green
Write-Host ""
