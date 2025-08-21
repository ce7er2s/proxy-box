## How to start

```
go build cmd/main.go
./main

```

Hardcoded to serve at 127.0.0.1:50057 because why having a choice?

## Can-do's and can-not-do's


Can't do shit about BIND and UDP ASSOCIATE. (but who need them anyway?)

Can't do shit about hostname resolve on server side (socks5h) and IPv6 addresses.

Can do shit in real-life testing:

- curl works fine
- web extension Smart Proxy
- ssh with ProxyCommand and netcat


## To-do

- BIND
- UDP ASSOCIATE
- Hostname resolve
- IPv6
- Code refactoring (WIP)


You know the drill, author is me, `@ce7er2s`. For the rest of the drill go read that sweet LICENSE!
