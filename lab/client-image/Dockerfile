# A small, general-purpose "client" box the user gets a shell on. It carries
# ordinary networking/HTTP tooling (curl, python, dns/ping) so you can interact
# with the target over the isolated lab network, plus sqlmap for the blind-SQLi
# challenge. What you run is up to you, using the target app's documented exercises.
FROM alpine:3.20
RUN apk add --no-cache bash curl wget python3 py3-pip iputils bind-tools jq nmap-ncat
# sqlmap is NOT packaged for Alpine 3.20 (neither main nor community), so install
# it from PyPI — it's pure Python and ships a `sqlmap` console script. Alpine's pip
# is a PEP 668 "externally managed" environment, hence --break-system-packages.
RUN pip install --no-cache-dir --break-system-packages sqlmap
# Keep the container alive so we can exec an interactive shell into it.
CMD ["sleep", "infinity"]
