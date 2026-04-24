#!/usr/bin/env bash
set -euo pipefail

SERIES="${1:?usage: render-feed-page.sh <24.10|25.12> <feed-dir> <package-file>}"
FEED_DIR="${2:?usage: render-feed-page.sh <24.10|25.12> <feed-dir> <package-file>}"
PACKAGE_FILE="${3:?usage: render-feed-page.sh <24.10|25.12> <feed-dir> <package-file>}"

BASE_URL="https://rico-x.github.io/tproxy-manager"
OUT_FILE="$FEED_DIR/index.html"

[ -d "$FEED_DIR" ] || {
  echo "feed directory not found: $FEED_DIR" >&2
  exit 1
}

case "$SERIES" in
  24.10)
    if [[ -f "$FEED_DIR/keys/usign.pub" && -f "$FEED_DIR/Packages.sig" ]]; then
      cat > "$OUT_FILE" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>TPROXY-Manager feed for OpenWrt 24.10</title>
<h2>TPROXY-Manager feed for OpenWrt 24.10.x (opkg)</h2>
<p>Install from feed:</p>
<pre>
wget -O /tmp/usign.pub ${BASE_URL}/24.10/keys/usign.pub
opkg-key add /tmp/usign.pub
echo 'src/gz tproxy ${BASE_URL}/24.10' >> /etc/opkg/customfeeds.conf
opkg update
opkg install tproxy-manager
</pre>
<p>Local install:</p>
<pre>
opkg install /tmp/${PACKAGE_FILE}
</pre>
<ul>
  <li><a href="Packages">Packages</a></li>
  <li><a href="Packages.gz">Packages.gz</a></li>
  <li><a href="Packages.sig">Packages.sig</a></li>
  <li><a href="keys/usign.pub">keys/usign.pub</a></li>
  <li><a href="${PACKAGE_FILE}">${PACKAGE_FILE}</a></li>
</ul>
EOF
    else
      cat > "$OUT_FILE" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>TPROXY-Manager packages for OpenWrt 24.10</title>
<h2>TPROXY-Manager for OpenWrt 24.10.x (opkg)</h2>
<p>Feed signing is not configured for this build. Use local install.</p>
<pre>
opkg install /tmp/${PACKAGE_FILE}
</pre>
<ul>
  <li><a href="Packages">Packages</a></li>
  <li><a href="Packages.gz">Packages.gz</a></li>
  <li><a href="${PACKAGE_FILE}">${PACKAGE_FILE}</a></li>
</ul>
EOF
    fi
    ;;
  25.12)
    if [[ -f "$FEED_DIR/keys/tproxy-manager.pem" ]]; then
      cat > "$OUT_FILE" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>TPROXY-Manager feed for OpenWrt 25.12</title>
<h2>TPROXY-Manager feed for OpenWrt 25.12.x (apk)</h2>
<p>Install from feed:</p>
<pre>
wget -O /etc/apk/keys/tproxy-manager.pem ${BASE_URL}/25.12/keys/tproxy-manager.pem
echo '${BASE_URL}/25.12/packages.adb' >> /etc/apk/repositories.d/customfeeds.list
apk update
apk add tproxy-manager
</pre>
<p>Local install:</p>
<pre>
apk add --allow-untrusted /tmp/${PACKAGE_FILE}
</pre>
<ul>
  <li><a href="packages.adb">packages.adb</a></li>
  <li><a href="keys/tproxy-manager.pem">keys/tproxy-manager.pem</a></li>
  <li><a href="${PACKAGE_FILE}">${PACKAGE_FILE}</a></li>
</ul>
EOF
    else
      cat > "$OUT_FILE" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>TPROXY-Manager packages for OpenWrt 25.12</title>
<h2>TPROXY-Manager for OpenWrt 25.12.x (apk)</h2>
<p>Feed signing is not configured for this build. Use local install.</p>
<pre>
apk add --allow-untrusted /tmp/${PACKAGE_FILE}
</pre>
<ul>
  <li><a href="packages.adb">packages.adb</a></li>
  <li><a href="${PACKAGE_FILE}">${PACKAGE_FILE}</a></li>
</ul>
EOF
    fi
    ;;
  *)
    echo "unsupported series: $SERIES" >&2
    exit 1
    ;;
esac
