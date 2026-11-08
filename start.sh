#!/bin/bash

# 1. Start Virtual Monitor (1280x720 resolution is optimized for iframes)
Xvfb :99 -screen 0 1280x720x24 -listen tcp &
sleep 2

# 2. Start Fluxbox (The Window Manager to make it look like a real OS)
fluxbox &
sleep 1

# 3. Start VNC Server (Captures the screen)
x11vnc -display :99 -nopw -forever -shared -bg -localhost

# 4. Start noVNC (Converts VNC to WebSockets for your frontend)
echo "Starting noVNC Stream on port 6080..."
websockify --web /usr/share/novnc/ 6080 localhost:5900