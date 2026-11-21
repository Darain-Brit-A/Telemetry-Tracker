@echo off
title AIOps Tier 1 (collector)
cd /d "%~dp0"
python tools\two_laptop.py collector
pause
