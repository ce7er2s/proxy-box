# How to start:

```
go build cmd/main.go
./main

```

## Little about it

Ta-da! Hardcoded to work at 127.0.0.1:50057
Can't do shit about BIND and UDP ASSOCIATE (but who need them anyway?)

Can't do shit about hostname resolve on server side (socks5h) and IPv6 addresses.
Can do shit in real-life testing tho: `curl` works fine and my web browser extension "Smart Proxy" works okay with it (tested with: wtf.ip, Spotify and Twitch)

