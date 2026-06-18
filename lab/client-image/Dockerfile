# A small, general-purpose "client" box the user gets a shell on. It carries
# ordinary networking/HTTP tooling (curl, python, dns/ping) so you can interact
# with the target over the isolated lab network. No preloaded exploit content —
# what you run is up to you, using the target app's documented exercises.
FROM alpine:3.20
RUN apk add --no-cache bash curl wget python3 py3-pip iputils bind-tools jq nmap-ncat
# Keep the container alive so we can exec an interactive shell into it.
CMD ["sleep", "infinity"]
