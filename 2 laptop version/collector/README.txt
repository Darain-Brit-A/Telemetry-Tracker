TeleTracker Tier 1 - collector laptop
=====================================

1. Install Python 3.12 or newer from python.org (tick "Add Python to PATH").
2. Connect this laptop to the SAME Wi-Fi / hotspot as the server laptop.
3. Make sure the server laptop shows "TIER 2 READY" (start_server.bat on the server).
4. Double-click start_collector.bat in this folder.

It finds the server by itself, then starts 7 collectors: live air quality from the OpenAQ API
(Bengaluru, Delhi, Mumbai, Chennai) and the simulated servers. Close the window to stop.

This folder contains the collectors' secrets, private keys and the OpenAQ API key: do not share it.
