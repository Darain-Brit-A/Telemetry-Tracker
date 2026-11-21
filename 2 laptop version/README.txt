TeleTracker - 2 laptop version
==============================

This laptop = SERVER (Tier 2: dashboard, database, AI engine)
Other laptop = COLLECTOR (Tier 1: reads the live OpenAQ air-quality API and the simulated servers,
               sends only metadata to the server over mutual TLS 1.3)

What is in this folder
  server\          the server copy of the project (stays on THIS laptop)
  collector\       ready-made collector folder (for the OTHER laptop)
  collector.zip    the same collector folder as one file, to copy across

The normal single-laptop version is the project folder around this one (D:\Projects\some).

server\, collector\ and collector.zip exist only on the server laptop and are never committed to
git: they contain private keys, collector secrets and the OpenAQ API key. On a fresh clone, create
them like this (in the project folder):
    git worktree add "2 laptop version/server" two-laptop
    copy config\pollution.json "2 laptop version\server\config\"     (your OpenAQ key; make the config folder first)
    cd "2 laptop version\server"
    python tools\two_laptop.py package


------------------------------------------------------------------
ON THIS LAPTOP (server)
------------------------------------------------------------------
1. Connect to the Wi-Fi / hotspot.
2. Double-click  server\start_server.bat   (in D:\Projects\some\2 laptop version)
   Wait for "TIER 2 READY". Leave the window open.
3. Dashboard: http://localhost:8080
      acme-admin / acme-admin-demo        (simulated servers)
      cityair-admin / cityair-admin-demo  (live air quality)


------------------------------------------------------------------
ON THE OTHER LAPTOP (collector)
------------------------------------------------------------------
1. Install Python 3.12 or newer from python.org (tick "Add Python to PATH"). Nothing else.
2. Connect to the SAME Wi-Fi / hotspot as the server.
3. Copy collector.zip over (USB stick, or right-click > Share > Nearby sharing) and unzip it.
4. Double-click  collector\start_collector.bat
   It finds the server by itself and starts sending. Leave the window open.

Within a few seconds the server dashboard shows the collectors Online / Excellent, and the header
says "Tier 1: ... on another machine". The live air data takes about 90 seconds to load its history.


------------------------------------------------------------------
IF IT DOES NOT CONNECT
------------------------------------------------------------------
* The collector window says it cannot reach the server:
  On THIS laptop, open PowerShell as Administrator and run once:
      New-NetFirewallRule -DisplayName "TeleTracker 2-laptop" -Direction Inbound -Program (Get-Command python).Source -Action Allow -Profile Any
  (allows Python to accept the collector's connection; remove it later with
   Remove-NetFirewallRule -DisplayName "TeleTracker 2-laptop")
* Both laptops must be on the same network. Some phone hotspots stop devices from talking to
  each other; if so, use a normal Wi-Fi router.
* "timestamp outside allowed skew": set both laptops' clocks to the correct time.
* The collector asks for an address: type the address shown in the server window
  (the line "collectors send to : https://...").

Rebuild the collector package (only needed after "setup_env.py --force" on the server):
      cd "D:\Projects\some\2 laptop version\server"
      python tools\two_laptop.py package
Then copy the new collector.zip to the other laptop again.

The collector folder and collector.zip contain the collectors' secrets, private keys and the OpenAQ
API key. Do not upload or share them.
