# Test image for the vspam.org SpamAssassin rules. Built by run-tests.sh.
#
# gnupg and the sa-update dependencies are here so the same image can also
# exercise the update channel end to end, not just lint the rules.
FROM debian:bookworm-slim

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       spamassassin \
       libnet-dns-perl \
       libio-socket-ssl-perl \
       libmail-dkim-perl \
       gnupg \
       curl \
       ca-certificates \
  && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "3600"]
