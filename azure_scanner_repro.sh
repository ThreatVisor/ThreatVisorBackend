# ~/produce-scanner-status.sh
#!/usr/bin/env bash
set -euo pipefail

OUTDIR=~/scanner-reports
mkdir -p "$OUTDIR"
MD="$OUTDIR/azure_scanner_status.md"

# Images we care about
IMAGES=( "zaproxy/zap-stable" "custom-rengine" "wapiti-custom" "ghcr.io/sullo/nikto:latest" "w3af-custom" )

echo "# Azure Scanner Status" > "$MD"
echo "" >> "$MD"
echo "- Generated: $(date -u +"%Y-%m-%d %H:%M:%SZ")" >> "$MD"
echo "- Host: $(hostname)" >> "$MD"
echo "" >> "$MD"

echo "## Installed Images" >> "$MD"
echo "" >> "$MD"
{
  echo '```'
  docker images | awk 'NR==1 || /zaproxy\/zap-stable|custom-rengine|wapiti-custom|w3af-custom|ghcr\.io\/sullo\/nikto/'
  echo '```'
} >> "$MD"
echo "" >> "$MD"

echo "## Entrypoint / Cmd" >> "$MD"
echo "" >> "$MD"
echo '```' >> "$MD"
for img in "${IMAGES[@]}"; do
  docker image inspect "$img" --format '{{index .RepoTags 0}} -> Entrypoint={{.Config.Entrypoint}} Cmd={{.Config.Cmd}}' 2>/dev/null || echo "$img -> (not present)"
done >> "$MD"
echo '```' >> "$MD"
echo "" >> "$MD"

echo "## Sanity Checks (stdout excerpts)" >> "$MD"
echo "" >> "$MD"

# Helpers
run() { bash -lc "$1" 2>&1 || true; }

ZAP_HELP="$(run 'docker run --rm zaproxy/zap-stable zap-baseline.py --help | head -5')"
RENGINE_PY="$(run 'docker run --rm --entrypoint sh custom-rengine -c "python3 -V"')"
WAPITI_VER="$(run 'docker run --rm wapiti-custom --version')"
NIKTO_VER="$(run 'docker run --rm ghcr.io/sullo/nikto:latest -Version')"
W3AF_HELP="$(run 'docker run --rm w3af-custom --help | head -10')"

printf "### ZAP\n\n```\n%s\n```\n\n" "$ZAP_HELP"   >> "$MD"
printf "### reNgine (python present)\n\n```\n%s\n```\n\n" "$RENGINE_PY" >> "$MD"
printf "### Wapiti\n\n```\n%s\n```\n\n" "$WAPITI_VER" >> "$MD"
printf "### Nikto\n\n```\n%s\n```\n\n" "$NIKTO_VER"   >> "$MD"
printf "### w3af\n\n```\n%s\n```\n\n" "$W3AF_HELP"   >> "$MD"

cat >> "$MD" <<'TXT'
## How These Were Installed (exact working steps)

### ZAP
```bash
docker pull zaproxy/zap-stable
reNgine (built from the repo’s /web Dockerfile)
bash
Copy code
git clone https://github.com/yogeshojha/rengine.git
cd rengine
docker build -t custom-rengine -f web/Dockerfile web
# sanity check
docker run --rm --entrypoint sh custom-rengine -c 'python3 -V'
Wapiti (official repo, headless Dockerfile)
bash
Copy code
git clone https://github.com/wapiti-scanner/wapiti.git
cd wapiti
docker build -t wapiti-custom -f Dockerfile.headless .
# sanity
docker run --rm wapiti-custom --version
Nikto (official GHCR image)
bash
Copy code
docker pull ghcr.io/sullo/nikto:latest
# sanity
docker run --rm ghcr.io/sullo/nikto:latest -Version
w3af (custom image using project’s installer script)
Dockerfile used:

dockerfile
Copy code
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-lc"]
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev git build-essential \
    libxml2-dev libxslt1-dev zlib1g-dev libssl-dev libffi-dev libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel
RUN [ -f scripts/install.sh ] && chmod +x scripts/install.sh && yes | ./scripts/install.sh || true
RUN echo '#!/bin/bash' > /usr/local/bin/w3af && \
    echo 'exec python3 /app/w3af_console "$@"' >> /usr/local/bin/w3af && \
    chmod +x /usr/local/bin/w3af
ENTRYPOINT ["w3af"]
Build & sanity:

bash
Copy code
docker build -t w3af-custom .
docker run --rm w3af-custom --help | head -20
Microservice Mapping Used
javascript
Copy code
const SCANNERS = {
  zap:    { containerName: 'zaproxy/zap-stable',            reportFile: 'zap_report.json',    reportFormat: 'json' },
  rengine:{ containerName: 'custom-rengine',                 reportFile: 'rengine_report.json',reportFormat: 'json' }, // service-style
  wapiti: { containerName: 'wapiti-custom',                  reportFile: 'wapiti_report.json', reportFormat: 'json' },
  nikto:  { containerName: 'ghcr.io/sullo/nikto:latest',     reportFile: 'nikto_report.txt',   reportFormat: 'txt'  },
  w3af:   { containerName: 'w3af-custom',                    reportFile: 'w3af_report.txt',    reportFormat: 'txt'  }
};
TXT

echo "Wrote $MD"

bash
Copy code

**Run it:**
```bash
chmod +x ~/produce-scanner-status.sh
~/produce-scanner-status.sh
You’ll get: ~/scanner-reports/azure_scanner_status.md — perfect to send to the other AI/person.

B) Repro script (exact install steps that worked)
If you also want to hand them a single script to recreate the working setup, give them this:

bash
Copy code
# ~/azure_scanner_repro.sh
#!/usr/bin/env bash
set -euo pipefail

echo ">> Creating workspace"
mkdir -p ~/scanner-images ~/scanner-reports
cd ~/scanner-images

echo ">> ZAP"
docker pull zaproxy/zap-stable

echo ">> reNgine (build from /web)"
if [ ! -d rengine ]; then git clone https://github.com/yogeshojha/rengine.git; fi
cd rengine
docker build -t custom-rengine -f web/Dockerfile web
docker run --rm --entrypoint sh custom-rengine -c 'python3 -V'
cd ..

echo ">> Wapiti (headless)"
if [ ! -d wapiti ]; then git clone https://github.com/wapiti-scanner/wapiti.git; fi
cd wapiti
docker build -t wapiti-custom -f Dockerfile.headless .
docker run --rm wapiti-custom --version
cd ..

echo ">> Nikto (GHCR)"
docker pull ghcr.io/sullo/nikto:latest
docker run --rm ghcr.io/sullo/nikto:latest -Version

echo ">> w3af (custom Dockerfile with installer)"
if [ ! -d w3af ]; then git clone https://github.com/andresriancho/w3af.git; fi
cd w3af
cat > Dockerfile <<'EOF'
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-lc"]
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev git build-essential \
    libxml2-dev libxslt1-dev zlib1g-dev libssl-dev libffi-dev libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel
RUN [ -f scripts/install.sh ] && chmod +x scripts/install.sh && yes | ./scripts/install.sh || true
RUN echo '#!/bin/bash' > /usr/local/bin/w3af && \
    echo 'exec python3 /app/w3af_console "$@"' >> /usr/local/bin/w3af && \
    chmod +x /usr/local/bin/w3af
ENTRYPOINT ["w3af"]
EOF
docker build -t w3af-custom .
docker run --rm w3af-custom --help | head -10
cd ..

echo ">> Installed images:"
docker images | awk 'NR==1 || /zaproxy\/zap-stable|custom-rengine|wapiti-custom|w3af-custom|ghcr\.io\/sullo\/nikto/'

echo ">> Done."
