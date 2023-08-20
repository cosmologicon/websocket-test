# websocket-test

My attempt to write an example websocket Python backend and JavaScript frontend.

# Version 0

Absolute minimum proof of concept. The server runs locally and just responds with Hello World.

Deploy local server:

	python3 server-v0.py

Then open client-v0.html in a browser.

# Version 1

Adds the ability to exchange multiple messages with the client, and to close the connection from
either end. Server still runs locally and only accepts one client at a time.

Deploy local server:

	python3 server-v1.py

Then open client-v1.html in a browser. You can open multiple clients in different browser windows,
but the server will only be able to communicate with one of them at a time.

# Version 2

Adds the ability to connect with multiple clients simultaneously. The client is unchanged.

Deploy local server:

	python3 server-v2.py

Then open client-v1.html in a browser. You can open multiple clients in different browser windows,
which the server can operate with simultaneously.
