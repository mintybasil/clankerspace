# Image Builder Examples

Example `build-image.sh` commands for different use cases. Run from the `ae-poc` directory (requires `proxy-ca.pem` from the egress proxy).

## 1. Minimal image

Just curl + CA cert. No Pi, no Node.js. Smallest possible image (~14MB).

```bash
./build-image.sh --ca-cert proxy-ca.pem --image-name minimal --size 200M \
    images/minimal.ext4
```

## 2. Pi agent image

Node.js + Pi harness + CA cert + proxy config. The standard agent environment image for running Pi inside a VM.

```bash
./build-image.sh --ca-cert proxy-ca.pem --image-name pi-agent \
    --with-pi --size 500M \
    images/pi-agent.ext4
```

## 3. Pi agent with dev tools

Adds git, jq, and python3 alongside Pi.

```bash
./build-image.sh --ca-cert proxy-ca.pem --image-name pi-dev \
    --with-pi --packages "git,jq,python3" --size 800M \
    images/pi-dev.ext4
```

## 4. Pi agent with custom Pi packages

Installs a Pi skills package alongside the harness.

```bash
./build-image.sh --ca-cert proxy-ca.pem --image-name pi-skills \
    --with-pi --pi-packages "npm:@earendil-works/pi-coding-skills" \
    --packages "git" --size 800M \
    images/pi-skills.ext4
```

## 5. Custom proxy config

Different proxy host/port — useful when the proxy runs on a different interface.

```bash
./build-image.sh --ca-cert proxy-ca.pem --image-name custom-proxy \
    --with-pi --proxy-host 10.0.2.1 --proxy-port 8443 \
    images/custom-proxy.ext4
```

## 6. No proxy (base image)

Builds a base image without proxy env vars. Proxy config will be injected at launch time.

```bash
./build-image.sh --ca-cert proxy-ca.pem --image-name base-no-proxy \
    --no-proxy --with-pi --size 500M \
    images/base-no-proxy.ext4
```