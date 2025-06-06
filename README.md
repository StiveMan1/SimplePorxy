# 🛠️ Simple Proxy — Set It, Forget It

Hey there!\
This is a simple, no-nonsense TCP proxy server that you can fire up in seconds. Built in C, driven by a config.cfg, and managed via systemd. No fancy dependencies, just the stuff that works.
📁 What’s Inside


```
./
├── .gitignore                # Ignore garbage
├── config.cfg                # Proxy settings — you’ll probably tweak this
├── config.h                  # Where the struct magic lives
├── install.sh                # Just run it and relax
├── main.c                    # The brains of the proxy
└── simple-porxy.service      # systemd service (yeah, typo included 🙃)
```

## 🚀 Getting Started
### 1. 🧼 Run the Installer

```bash
sudo ./install.sh
```

This script:
* Installs GCC and libconfig if you don’t have them
* Compiles the code
* Copies the config to /etc/simple-proxy/config.cfg
* Installs the binary to /usr/bin/simple-proxy
* Enables and starts the service with systemd

That’s it. You’re live.

### 2. 🔧 Configure Your Proxy

Edit /etc/simple-proxy/config.cfg. Here’s what it looks like:

```cfg
proxy_servers = (
    {
        domain: 2; // IPv4
        service: 1; // TCP
        protocol: 6; // IPPROTO_TCP
        interface: 0; // 0.0.0.0

        port: 1234; // Listen here

        destination = {
            address: "127.0.0.1"; // Send data to this host
            port: 1234; // ...and this port
        }
    }
);
```

Want more proxies? Just add more { ... } blocks in the array.

## 🔄 What It Actually Does

This proxy:

* Listens for connections on specified port(s)
* When a connection comes in, it opens a socket to your destination server
* It pipes data back and forth using epoll and threads
* When either side dies, it cleans up like a champ

## 📦 What’s With the Name?

You’ll notice the simple-porxy.service file has a typo.
Yes, we kept it — just in case someone accidentally used it. You're welcome.

## 🧹 Uninstall?

Just:

```bash
sudo systemctl stop simple-proxy
sudo systemctl disable simple-proxy
sudo rm /usr/bin/simple-proxy
sudo rm /etc/systemd/system/simple-proxy.service
sudo rm -rf /etc/simple-proxy
```

Done.

## 🛠️ Dev Notes

* Written in C (with some pthreads and libconfig)
* Uses epoll to handle I/O efficiently
* Not meant to be bulletproof — but it’s fast and minimal

### 📅 Plans

Here’s what might land in future updates (or not, depending on how lazy I am 😄):

1. [ ] 🔐 TLS support (optional passthrough or termination)
2. [ ] 🧠 Config reload without restart — maybe catch SIGHUP
3. [ ] 📊 Basic logging (connections, errors, maybe traffic stats)
4. [ ] 🧪 Tests (yes, actual tests. Some day.)
5. [ ] 🐞 IPv6 support
6. [ ] ⚙️ Hot-restart existing connections (stretch goal)
7. [ ] 📦 Deb/rpm packaging for easier install
8. [ ] 🖥️ Simple web/status UI (think: dashboard-lite)
9. [ ] 🔁 UDP support (because why not)

Got better ideas? Open an issue or send a PR — even a typo fix makes my day.

## 📫 Questions?

Open an issue, or better yet — just read the source. It’s small and clean.

Happy proxying! 🧃