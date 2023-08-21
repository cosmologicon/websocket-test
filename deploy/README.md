# Deploy instructions

Instructions for how to run websocket servers on my domain.

I like to have a separate server process running for each game or app, although I think this is not
the normal way to do it. For each different process, do the following steps:

## Choose an unused port

This supposedly shows you all used port, but beware that some are under non-numeric names (e.g.
`http` means port `80`):

	netstat -lat

For myself, I reserve 5-digit ports starting with 23 (since W is the 23rd letter), such as `23456`,
for websocket servers. In the server code this is the `port` argument of `asyncio.start_server`,
for example. The URL at which the server will be accessible then is:

	https://ufx.space:23456

## Create subdirectory for server code


