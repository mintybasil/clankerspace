# Image configuration examples for build-image.sh
#
# Each example shows a different use case. Run the corresponding command
# from the ae-poc directory (requires proxy-ca.pem from the egress proxy).
#
# ─────────────────────────────────────────────────────────────────────

# 1. Minimal image — just curl + CA cert (for testing proxy connectivity)
#    No Pi, no Node.js. Smallest possible image (~100MB).
#
# ./build-image.sh --ca-cert proxy-ca.pem --image-name minimal --size 200M \
#     images/minimal.ext4


# 2. Pi agent image — Node.js + Pi harness + CA cert + proxy config
#    The standard agent environment image for running Pi inside a VM.
#
# ./build-image.sh --ca-cert proxy-ca.pem --image-name pi-agent \
#     --with-pi --size 500M \
#     images/pi-agent.ext4


# 3. Pi agent image with extra tools — git, jq, python3
#
# ./build-image.sh --ca-cert proxy-ca.pem --image-name pi-dev \
#     --with-pi --packages "git,jq,python3" --size 800M \
#     images/pi-dev.ext4


# 4. Pi agent with custom Pi packages — e.g., a coding skills package
#
# ./build-image.sh --ca-cert proxy-ca.pem --image-name pi-skills \
#     --with-pi --pi-packages "npm:@earendil-works/pi-coding-skills" \
#     --packages "git" --size 800M \
#     images/pi-skills.ext4


# 5. Custom proxy config — different proxy host/port
#
# ./build-image.sh --ca-cert proxy-ca.pem --image-name custom-proxy \
#     --with-pi --proxy-host 10.0.2.1 --proxy-port 8443 \
#     images/custom-proxy.ext4


# 6. No proxy — for building base images that will have proxy config
#    injected at launch time
#
# ./build-image.sh --ca-cert proxy-ca.pem --image-name base-no-proxy \
#     --no-proxy --with-pi --size 500M \
#     images/base-no-proxy.ext4