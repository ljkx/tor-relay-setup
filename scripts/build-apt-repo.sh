#!/usr/bin/env bash
# Build a signed apt repository from release .deb files.
#
#   scripts/build-apt-repo.sh DEB_DIR OUT_DIR SIGNING_KEY_FINGERPRINT
#
# The key must already be in the gpg keyring (the release workflow imports
# it from the APT_SIGNING_KEY secret). OUT_DIR receives:
#
#   pool/main/t/tor-relay-setup/*.deb
#   dists/stable/{Release,InRelease,Release.gpg}
#   dists/stable/main/binary-{amd64,arm64}/Packages{,.gz}
#   tor-relay-setup.asc          the public signing key
#   index.html                   how to add the repository
#
# Needs apt-ftparchive (apt-utils) and gpg. GPG_PASSPHRASE is used when set.
set -Eeuo pipefail

[[ $# -eq 3 ]] || {
  printf 'usage: %s DEB_DIR OUT_DIR SIGNING_KEY_FINGERPRINT\n' "$0" >&2
  exit 2
}
deb_dir=$1
out=$2
key=$3
suite=stable
archs=(amd64 arm64)
pages_url="${PAGES_URL:-https://ljkx.github.io/tor-relay-setup}"

shopt -s nullglob
debs=("$deb_dir"/*.deb)
[[ ${#debs[@]} -gt 0 ]] || {
  printf 'no .deb files in %s\n' "$deb_dir" >&2
  exit 1
}

pool="pool/main/t/tor-relay-setup"
mkdir -p "${out}/${pool}"
cp -- "${debs[@]}" "${out}/${pool}/"

cd "$out"
for arch in "${archs[@]}"; do
  dir="dists/${suite}/main/binary-${arch}"
  mkdir -p "$dir"
  apt-ftparchive --arch "$arch" packages pool > "${dir}/Packages"
  gzip -9nkf "${dir}/Packages"
done

apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=tor-relay-setup \
  -o APT::FTPArchive::Release::Label=tor-relay-setup \
  -o APT::FTPArchive::Release::Suite="$suite" \
  -o APT::FTPArchive::Release::Codename="$suite" \
  -o APT::FTPArchive::Release::Architectures="${archs[*]}" \
  -o APT::FTPArchive::Release::Components=main \
  -o APT::FTPArchive::Release::Description="tor-relay-setup releases" \
  release "dists/${suite}" > "${TMPDIR:-/tmp}/Release"
mv "${TMPDIR:-/tmp}/Release" "dists/${suite}/Release"

gpg_sign=(gpg --batch --yes --local-user "$key" --digest-algo SHA512)
if [[ -n "${GPG_PASSPHRASE:-}" ]]; then
  gpg_sign+=(--pinentry-mode loopback --passphrase-fd 3)
  exec 3<<< "$GPG_PASSPHRASE"
fi
"${gpg_sign[@]}" --clearsign -o "dists/${suite}/InRelease" "dists/${suite}/Release"
if [[ -n "${GPG_PASSPHRASE:-}" ]]; then exec 3<<< "$GPG_PASSPHRASE"; fi
"${gpg_sign[@]}" --armor --detach-sign -o "dists/${suite}/Release.gpg" "dists/${suite}/Release"
gpg --batch --armor --export "$key" > tor-relay-setup.asc
gpg --batch --verify "dists/${suite}/InRelease" 2> /dev/null

cat > index.html << EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>tor-relay-setup apt repository</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem;color:#1f1b24}
pre{background:#f4eff8;padding:1rem;overflow-x:auto;border-radius:8px}a{color:#7d4698}</style></head>
<body><h1>tor-relay-setup apt repository</h1>
<p>Signed packages of <a href="https://github.com/ljkx/tor-relay-setup">tor-relay-setup</a> for Debian and Ubuntu (amd64, arm64).
Signing key fingerprint: <code>${key}</code>.</p>
<pre>sudo curl -fsSLo /usr/share/keyrings/tor-relay-setup.asc ${pages_url}/tor-relay-setup.asc
gpg --show-keys /usr/share/keyrings/tor-relay-setup.asc   # compare the fingerprint
sudo tee /etc/apt/sources.list.d/tor-relay-setup.sources &lt;&lt;'SRC'
Types: deb
URIs: ${pages_url}/
Suites: ${suite}
Components: main
Signed-By: /usr/share/keyrings/tor-relay-setup.asc
SRC
sudo apt update &amp;&amp; sudo apt install tor-relay-setup</pre>
</body></html>
EOF
touch .nojekyll
printf 'apt repository for %s built in %s\n' "$(basename -a "${debs[@]}" | tr '\n' ' ')" "$out"
