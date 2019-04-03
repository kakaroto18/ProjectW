# Deploy wireguard and v2ray on ubuntu 18.04+

## Requirements

1. Local computer with *nix installation
2. VPS running ubuntu 18.04+ that has been configured with SSH no-password login

## How to use

1. Install Ruby and gems (Ruby 2.3+ recommended)

```
# If you use Ubuntu, you can run:
sudo apt-get install ruby
sudo gem install sshkit os

# If you use macOS, you can run:
(sudo) gem install sshkit os
```

2. Checkout this project and prepare `config.yml`

```
cd PATH_TO_PROJECTW # Replace with real path
cp config.yml.skel config.yml
```

3. Edit `config.yml`. Change config as necessary.

```yaml
---
domain: 'example.com'       # Your public ip address or domain
wireguard:                  # If you want to install wireguard, keep this block remove otherwise
  port: 54321               # Wireguard port
  wg_ip: '10.10.10.1'.      # Wireguard server
  clients:                  # clients ip list
    - '10.10.10.2'          # client ip should use the same subnet as wg_ip
    - '10.10.10.3'
v2ray:                      # If you want to install v2ray, keep this block; remove otherwise
  port: 50443               # V2Ray port
  clients: 1                # Number of clients to add
  show_qr: false            # Show client config qr. Default to no, because client conf is too big
```

4. Start deploy:

```
ruby deploy.rb
```

## Client app

- Wireguard official client
- TunSafe
- i2ray (for v2ray)
