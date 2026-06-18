# Tiny, dependency-free static server. Listens on 8080 (an unprivileged port),
# writes nothing to disk, and runs fine with all Linux capabilities dropped.
FROM python:3.12-alpine
WORKDIR /site
COPY index.html /site/index.html
EXPOSE 8080
CMD ["python", "-m", "http.server", "8080"]
