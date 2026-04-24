#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PRIVATE_DIR="$ROOT_DIR/keys/private"
PRIVATE_KEY="$PRIVATE_DIR/tproxy-manager-apk.key"
PUBLIC_KEY="$ROOT_DIR/keys/tproxy-manager-apk.pem"

mkdir -p "$PRIVATE_DIR"

openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY"
chmod 600 "$PRIVATE_KEY"
openssl ec -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" >/dev/null 2>&1
chmod 644 "$PUBLIC_KEY"

cat <<EOF
Generated APK signing key pair:
  private: $PRIVATE_KEY
  public:  $PUBLIC_KEY

Next steps:
  1. Commit only $PUBLIC_KEY
  2. Add the contents of $PRIVATE_KEY to the GitHub secret APK_PRIVATE_KEY
  3. Do not commit the private key
EOF
