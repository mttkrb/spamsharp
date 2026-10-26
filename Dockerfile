FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/SpamSharp.csproj .
RUN dotnet restore -r linux-x64
COPY src/ .
RUN dotnet publish -c Release -r linux-x64 --self-contained -o /out

# rspamd-Image als Basis; redis und die App kommen dazu, alles in einem Container
FROM rspamd/rspamd:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends redis-server \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /var/lib/rspamd && ln -s /data/rspamd /var/lib/rspamd
COPY rspamd/local.d/ /etc/rspamd/local.d/
COPY --from=build /out /app
WORKDIR /app
ENV DATA_DIR=/data ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
# /data gehört beim ersten Start root (von Docker angelegt): übernehmen, dann ohne root weiter
ENTRYPOINT ["/bin/sh", "-c", "mkdir -p /data && chown -R _rspamd:_rspamd /data && exec setpriv --reuid=_rspamd --regid=_rspamd --init-groups /app/SpamSharp"]
