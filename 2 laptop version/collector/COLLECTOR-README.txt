Start everything in this bundle with:
    python run_all.py --collector col-acme-cloud --collector col-acme-dc1 --collector col-air-blr --collector col-air-bom --collector col-air-del --collector col-air-maa --collector col-globex-nyc

TeleTracker Collector col-acme-cloud (fra-cloud) - run on this machine
======================================================================

1. Get the project code on this machine (same version as the SaaS machine), e.g.
       git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
   and install Python 3.12+ (no packages needed).

2. Unpack this zip INTO the project folder, so that config/collectors/col-acme-cloud.json exists.

3. Check the SaaS machine is reachable (it must allow inbound TCP 8443):
       Test-NetConnection 10.192.149.213 -Port 8443

4. Start the collector and its local data source:
       python run_all.py --collector col-acme-cloud
   (that starts collector/collector.py --config col-acme-cloud plus the simulator for its hosts)

5. On the SaaS machine's dashboard the collector turns Online within seconds; its console is
   http://127.0.0.1:9102 on THIS machine.

Clocks on both machines must be within 5 minutes of each other (request signatures expire).
This zip contains the collector's secret and private key: delete it once unpacked.


TeleTracker Collector col-acme-dc1 (blr-dc1) - run on this machine
==================================================================

1. Get the project code on this machine (same version as the SaaS machine), e.g.
       git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
   and install Python 3.12+ (no packages needed).

2. Unpack this zip INTO the project folder, so that config/collectors/col-acme-dc1.json exists.

3. Check the SaaS machine is reachable (it must allow inbound TCP 8443):
       Test-NetConnection 10.192.149.213 -Port 8443

4. Start the collector and its local data source:
       python run_all.py --collector col-acme-dc1
   (that starts collector/collector.py --config col-acme-dc1 plus the simulator for its hosts)

5. On the SaaS machine's dashboard the collector turns Online within seconds; its console is
   http://127.0.0.1:9101 on THIS machine.

Clocks on both machines must be within 5 minutes of each other (request signatures expire).
This zip contains the collector's secret and private key: delete it once unpacked.


TeleTracker Collector col-air-blr (Bengaluru) - run on this machine
===================================================================

1. Get the project code on this machine (same version as the SaaS machine), e.g.
       git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
   and install Python 3.12+ (no packages needed).

2. Unpack this zip INTO the project folder, so that config/collectors/col-air-blr.json exists.

3. Check the SaaS machine is reachable (it must allow inbound TCP 8443):
       Test-NetConnection 10.192.149.213 -Port 8443

4. Start the collector and its local data source:
       python run_all.py --collector col-air-blr
   (that starts collector/collector.py --config col-air-blr plus the OpenAQ poller (needs config/pollution.json with your OpenAQ key))

5. On the SaaS machine's dashboard the collector turns Online within seconds; its console is
   http://127.0.0.1:9104 on THIS machine.

Clocks on both machines must be within 5 minutes of each other (request signatures expire).
This zip contains the collector's secret and private key: delete it once unpacked.


TeleTracker Collector col-air-bom (Mumbai) - run on this machine
================================================================

1. Get the project code on this machine (same version as the SaaS machine), e.g.
       git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
   and install Python 3.12+ (no packages needed).

2. Unpack this zip INTO the project folder, so that config/collectors/col-air-bom.json exists.

3. Check the SaaS machine is reachable (it must allow inbound TCP 8443):
       Test-NetConnection 10.192.149.213 -Port 8443

4. Start the collector and its local data source:
       python run_all.py --collector col-air-bom
   (that starts collector/collector.py --config col-air-bom plus the OpenAQ poller (needs config/pollution.json with your OpenAQ key))

5. On the SaaS machine's dashboard the collector turns Online within seconds; its console is
   http://127.0.0.1:9106 on THIS machine.

Clocks on both machines must be within 5 minutes of each other (request signatures expire).
This zip contains the collector's secret and private key: delete it once unpacked.


TeleTracker Collector col-air-del (Delhi) - run on this machine
===============================================================

1. Get the project code on this machine (same version as the SaaS machine), e.g.
       git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
   and install Python 3.12+ (no packages needed).

2. Unpack this zip INTO the project folder, so that config/collectors/col-air-del.json exists.

3. Check the SaaS machine is reachable (it must allow inbound TCP 8443):
       Test-NetConnection 10.192.149.213 -Port 8443

4. Start the collector and its local data source:
       python run_all.py --collector col-air-del
   (that starts collector/collector.py --config col-air-del plus the OpenAQ poller (needs config/pollution.json with your OpenAQ key))

5. On the SaaS machine's dashboard the collector turns Online within seconds; its console is
   http://127.0.0.1:9105 on THIS machine.

Clocks on both machines must be within 5 minutes of each other (request signatures expire).
This zip contains the collector's secret and private key: delete it once unpacked.


TeleTracker Collector col-air-maa (Chennai) - run on this machine
=================================================================

1. Get the project code on this machine (same version as the SaaS machine), e.g.
       git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
   and install Python 3.12+ (no packages needed).

2. Unpack this zip INTO the project folder, so that config/collectors/col-air-maa.json exists.

3. Check the SaaS machine is reachable (it must allow inbound TCP 8443):
       Test-NetConnection 10.192.149.213 -Port 8443

4. Start the collector and its local data source:
       python run_all.py --collector col-air-maa
   (that starts collector/collector.py --config col-air-maa plus the OpenAQ poller (needs config/pollution.json with your OpenAQ key))

5. On the SaaS machine's dashboard the collector turns Online within seconds; its console is
   http://127.0.0.1:9107 on THIS machine.

Clocks on both machines must be within 5 minutes of each other (request signatures expire).
This zip contains the collector's secret and private key: delete it once unpacked.


TeleTracker Collector col-globex-nyc (nyc-dc) - run on this machine
===================================================================

1. Get the project code on this machine (same version as the SaaS machine), e.g.
       git clone https://github.com/Darain-Brit-A/Telemetry-Tracker.git
   and install Python 3.12+ (no packages needed).

2. Unpack this zip INTO the project folder, so that config/collectors/col-globex-nyc.json exists.

3. Check the SaaS machine is reachable (it must allow inbound TCP 8443):
       Test-NetConnection 10.192.149.213 -Port 8443

4. Start the collector and its local data source:
       python run_all.py --collector col-globex-nyc
   (that starts collector/collector.py --config col-globex-nyc plus the simulator for its hosts)

5. On the SaaS machine's dashboard the collector turns Online within seconds; its console is
   http://127.0.0.1:9103 on THIS machine.

Clocks on both machines must be within 5 minutes of each other (request signatures expire).
This zip contains the collector's secret and private key: delete it once unpacked.
