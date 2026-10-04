# Single image for every lab target. One build, many services.
#
# Built ONCE while the guest still has internet, then the guest is moved to the
# isolated network and snapshotted. Everything after that point runs offline,
# which is what makes an active-scan experiment safe: no packet can leave the
# lab even if a CIDR is mistyped.
FROM python:3.12-slim

# openssl: the TLS target generates its own self-signed certificate at startup,
# which is what exercises fingerprinting layer L2. Real ICS devices almost
# universally present self-signed certs, so the lab must too.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl openssh-server \
 && rm -rf /var/lib/apt/lists/*

# Compatible-release pins: reproducible within a patch series without pinning to
# a version that may not exist on a given index. REPRODUCE.md records the exact
# resolved versions with `pip freeze` after the build, which is what the paper's
# artifact appendix should cite.
RUN pip install --no-cache-dir \
      "pymodbus~=3.6.0" \
      "asyncua~=1.1"

WORKDIR /srv
COPY targets/ /srv/targets/

# Targets run unprivileged. None of them needs root, and a lab that runs
# everything as root teaches the wrong habit.
RUN useradd --create-home --shell /bin/bash labtarget
USER labtarget

CMD ["python", "-c", "print('specify a command in docker-compose.yml')"]
