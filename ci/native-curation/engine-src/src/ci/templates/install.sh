#!/usr/bin/env bash
# The expected digest and build identity come from the reviewed workflow profile.
set +x
set -euo pipefail
export LC_ALL=C
umask 077
MAX=536870912
die() { printf '%s\n' "relship bootstrap: $1" >&2; exit 1; }
for tool in curl od dd wc tr head chmod mkdir rm mv cat; do
  command -v "$tool" >/dev/null 2>&1 || die 'required native utility unavailable'
done
[[ ${RELSHIP_SHA256:-} =~ ^[0-9a-fA-F]{64}$ ]] || die 'invalid expected digest'
[[ ${RELSHIP_SOURCE_ID:-} =~ ^[0-9a-fA-F]{64}$ ]] || die 'invalid expected source identity'
[[ ${RELSHIP_VERSION:-} =~ ^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$ ]] || die 'invalid expected version'
[[ ${RELSHIP_FORMAT:-} == binary || ${RELSHIP_FORMAT:-} == tar.gz || ${RELSHIP_FORMAT:-} == zip ]] || die 'unsupported archive format'
[[ ${RELSHIP_URL:-} == https://* && ${RELSHIP_URL:-} != *[![:graph:]]* && ${RELSHIP_URL:-} != *'"'* && ${RELSHIP_URL:-} != *'\'* ]] || die 'HTTPS URL required'
authority=${RELSHIP_URL#https://}; authority=${authority%%[/?#]*}
[[ -n $authority && $authority != *@* ]] || die 'URL credentials forbidden'
[[ ${RELSHIP_DOWNLOAD_TOKEN:-} =~ ^[A-Za-z0-9._~+/-]*=*$ ]] || die 'invalid bearer token'
[[ ${RELSHIP_INSTALL_DIR:-} == /* && $RELSHIP_INSTALL_DIR != *$'\n'* && $RELSHIP_INSTALL_DIR != *$'\r'* ]] || die 'absolute private install directory required'
[[ ! -e $RELSHIP_INSTALL_DIR && ! -L $RELSHIP_INSTALL_DIR ]] || die 'install directory already exists'
mkdir -m 700 -- "$RELSHIP_INSTALL_DIR" || die 'cannot create private install directory'
complete=false
cleanup() {
  if [[ $complete == true ]]; then
    rm -f -- "$RELSHIP_INSTALL_DIR/download" "$RELSHIP_INSTALL_DIR/archive" "$RELSHIP_INSTALL_DIR/entry"
  else
    rm -rf -- "$RELSHIP_INSTALL_DIR"
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
download=$RELSHIP_INSTALL_DIR/download
installed=$RELSHIP_INSTALL_DIR/relship
# URL and authorization stay on stdin, never in curl's argument list. -q must be first.
curl_config() {
  printf 'url = "%s"\n' "$RELSHIP_URL"
  if [[ -n ${RELSHIP_DOWNLOAD_TOKEN:-} ]]; then
    printf 'header = "Authorization: Bearer %s"\n' "$RELSHIP_DOWNLOAD_TOKEN"
  fi
}
redirect=(--max-redirs 0)
[[ -n ${RELSHIP_DOWNLOAD_TOKEN:-} ]] || redirect=(--location --max-redirs 3)
# head also bounds chunked downloads with older curl versions.
if ! curl_config | curl -q --config - --silent --fail --globoff \
  --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 180 \
  --speed-limit 1024 --speed-time 30 --max-filesize "$MAX" "${redirect[@]}" \
  --write-out '%{http_code}' --output /dev/fd/3 3>&1 1>"$RELSHIP_INSTALL_DIR/status" 2>/dev/null \
  | head -c "$((MAX + 1))" > "$download"; then
  die 'HTTPS download failed'
fi
status=$(cat "$RELSHIP_INSTALL_DIR/status")
rm -f -- "$RELSHIP_INSTALL_DIR/status"
[[ $status == 200 ]] || die 'HTTPS download did not return status 200'
unset RELSHIP_DOWNLOAD_TOKEN
unset RELSHIP_URL
size=$(wc -c < "$download"); [[ $size -gt 0 && $size -le $MAX ]] || die 'download size limit exceeded'
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$download"); actual=${actual%% *}
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$download"); actual=${actual%% *}
else
  die 'native SHA-256 utility unavailable'
fi
expected=$(printf '%s' "$RELSHIP_SHA256" | tr A-F a-f)
[[ $actual == "$expected" ]] || die 'download SHA-256 mismatch'

# Restricted ASCII names make byte parsing and exact unzip member selection portable.
safe_name() {
  local path=$1 part
  [[ -n $path && ${#path} -le 240 && $path != /* && $path != */ && $path != *//* ]] || die 'unsafe archive member path'
  [[ $path != *[!A-Za-z0-9_./-]* ]] || die 'unsafe archive member path'
  while [[ $path == */* ]]; do
    part=${path%%/*}; path=${path#*/}
    [[ $part != . && $part != .. ]] || die 'unsafe archive member path'
  done
  [[ $path != . && $path != .. ]] || die 'unsafe archive member path'
}
seen='|'
seen_files='|'
remember() {
  local name prefix
  name=$(printf '%s' "$1" | tr A-Z a-z)
  [[ $seen != *"|$name|"* ]] || die 'duplicate or case-colliding archive member'
  prefix=$name
  while [[ $prefix == */* ]]; do prefix=${prefix%/*}; [[ $seen_files != *"|$prefix|"* ]] || die 'archive file and directory paths conflict'; done
  if [[ ${2:-false} == false ]]; then
    [[ $seen != *"|$name/"* ]] || die 'archive file and directory paths conflict'
    seen_files=$seen_files$name'|'
  fi
  seen=$seen$name'|'
}
read_bytes() {
  bytes=( $(dd if="$archive" bs=1 skip="$1" count="$2" 2>/dev/null | od -An -v -tu1) )
  [[ ${#bytes[@]} -eq $2 ]] || die 'truncated archive record'
}
le() {
  local start=$1 count=$2 i value=0 shift=0
  for ((i=start; i<start+count; i++)); do
    value=$((value + (bytes[i] << shift))); shift=$((shift + 8))
  done
  VAL=$value
}
ascii() {
  local start=$1 count=$2 padded=$3 i byte char ended=false
  VAL=''
  for ((i=start; i<start+count; i++)); do
    byte=${bytes[i]}
    if [[ $byte -eq 0 && $padded == true ]]; then ended=true; continue; fi
    [[ $ended == false && $byte -ge 32 && $byte -le 126 ]] || die 'invalid archive text field'
    printf -v char '\\%03o' "$byte"; printf -v char '%b' "$char"; VAL=$VAL$char
  done
}
octal() {
  local start=$1 count=$2 i byte value=0 ended=false
  for ((i=start; i<start+count; i++)); do
    byte=${bytes[i]}
    if [[ $byte -eq 0 || $byte -eq 32 ]]; then ended=true; continue; fi
    [[ $ended == false && $byte -ge 48 && $byte -le 55 ]] || die 'unsupported tar numeric field'
    value=$((value * 8 + byte - 48)); [[ $value -le $MAX ]] || die 'archive entry size limit exceeded'
  done
  VAL=$value
}
# Timestamp and uid/gid metadata have no extraction semantics. Other extras fail closed.
zip_extras() {
  local offset=$1 length=$2 end=$(( $1 + $2 )) identifier amount seen_extra='|'
  while [[ $offset -lt $end ]]; do
    [[ $((offset + 4)) -le $end ]] || die 'truncated ZIP extra field'
    read_bytes "$offset" 4; le 0 2; identifier=$VAL; le 2 2; amount=$VAL
    [[ $identifier -eq 21589 || $identifier -eq 30837 || $identifier -eq 22613 || $identifier -eq 10 ]] || die 'unsupported ZIP extra field'
    [[ $seen_extra != *"|$identifier|"* ]] || die 'duplicate ZIP extra field'
    seen_extra=$seen_extra$identifier'|'
    offset=$((offset + 4 + amount)); [[ $offset -le $end ]] || die 'truncated ZIP extra payload'
  done
}
pax_metadata() {
  local position=0 finish length digits byte record key value character
  [[ $2 -le 65536 ]] || die 'oversized PAX metadata'
  read_bytes "$1" "$2"
  while [[ $position -lt ${#bytes[@]} ]]; do
    digits=''; length=0; finish=$position
    while [[ $finish -lt ${#bytes[@]} && ${bytes[finish]} -ne 32 ]]; do
      byte=${bytes[finish]}; [[ $byte -ge 48 && $byte -le 57 && ${#digits} -lt 6 ]] || die 'invalid PAX length'
      digits=$digits$((byte - 48)); length=$((length * 10 + byte - 48)); finish=$((finish + 1))
    done
    [[ -n $digits && $length -gt $((${#digits} + 3)) && $((position + length)) -le ${#bytes[@]} && ${bytes[position + length - 1]} -eq 10 ]] || die 'invalid PAX record'
    finish=$((finish + 1)); key=''
    while [[ $finish -lt $((position + length - 1)) && ${bytes[finish]} -ne 61 ]]; do
      byte=${bytes[finish]}; [[ $byte -ge 33 && $byte -le 126 ]] || die 'invalid PAX key'
      printf -v character '\\%03o' "$byte"; printf -v character '%b' "$character"; key=$key$character; finish=$((finish + 1))
    done
    [[ -n $key && $finish -lt $((position + length - 1)) ]] || die 'invalid PAX key'
    [[ $pax_keys != *"|$key|"* ]] || die 'duplicate PAX key'
    pax_keys=$pax_keys$key'|'
    # Extended attributes are passive bytes: the installer never applies them.
    if [[ $key == SCHILY.xattr.* || $key == LIBARCHIVE.xattr.* ]]; then position=$((position + length)); continue; fi
    finish=$((finish + 1)); value=''
    while [[ $finish -lt $((position + length - 1)) ]]; do
      byte=${bytes[finish]}; [[ $byte -ge 32 && $byte -le 126 ]] || die 'non-ASCII PAX record'
      printf -v character '\\%03o' "$byte"; printf -v character '%b' "$character"; value=$value$character; finish=$((finish + 1))
    done
    case $key in
      path) [[ $3 == local ]] || die 'global PAX path forbidden'; safe_name "${value%/}"; pax_path=$value ;;
      size) [[ $3 == local && $value =~ ^[0-9]{1,9}$ ]] || die 'invalid PAX size'; pax_size=$((10#$value)); [[ $pax_size -le $MAX ]] || die 'PAX size limit exceeded' ;;
      mtime|atime|ctime|uid|gid|uname|gname|SCHILY.fflags) : ;;
      *) die 'unsupported PAX attribute' ;;
    esac
    position=$((position + length))
  done
}
if [[ $RELSHIP_FORMAT == binary ]]; then
  [[ -z ${RELSHIP_MEMBER:-} ]] || die 'binary downloads cannot declare a member'
  mv -- "$download" "$installed"
else
  safe_name "${RELSHIP_MEMBER:-}"
  member=$RELSHIP_MEMBER
  found=false
  if [[ $RELSHIP_FORMAT == tar.gz ]]; then
    command -v gzip >/dev/null 2>&1 || die 'native gzip utility unavailable'
    archive=$RELSHIP_INSTALL_DIR/archive
    if ! (ulimit -t 120; gzip -dc "$download" 2>/dev/null) | head -c "$((MAX + 1))" > "$archive"; then die 'invalid or oversized gzip stream'; fi
    expanded=$(wc -c < "$archive")
    [[ $expanded -le $MAX && $((expanded % 512)) -eq 0 ]] || die 'invalid or oversized tar archive'
    offset=0; count=0; selected_offset=0; selected_size=0; pax_path=''; pax_size=''; pending_pax=false
    while [[ $((offset + 512)) -le $expanded ]]; do
      read_bytes "$offset" 512
      sum=0; for byte in "${bytes[@]}"; do sum=$((sum + byte)); done
      if [[ $sum -eq 0 ]]; then
        [[ $pending_pax == false ]] || die 'orphan PAX header'
        [[ $((expanded - offset)) -ge 1024 ]] || die 'missing tar end marker'
        tail_size=$(dd if="$archive" bs=512 skip="$((offset / 512))" 2>/dev/null | tr -d '\000' | wc -c)
        [[ $tail_size -eq 0 ]] || die 'unexpected tar trailing data'
        break
      fi
      count=$((count + 1)); [[ $count -le 1024 ]] || die 'too many archive members'
      octal 148 8; checksum=$VAL
      for ((i=148; i<156; i++)); do sum=$((sum - bytes[i] + 32)); done
      [[ $checksum -eq $sum ]] || die 'tar header checksum mismatch'
      # POSIX ustar and GNU ustar differ in magic/version and prefix layout.
      ascii 257 5 false; [[ $VAL == ustar ]] || die 'unsupported tar header'
      ascii 0 100 true; name=$VAL
      if [[ ${bytes[262]} -eq 0 && ${bytes[263]} -eq 48 && ${bytes[264]} -eq 48 ]]; then
        ascii 345 155 true; [[ -z $VAL ]] || name=$VAL/$name
      elif [[ ${bytes[262]} -ne 32 || ${bytes[263]} -ne 32 || ${bytes[264]} -ne 0 ]]; then die 'unsupported tar header'; fi
      kind=${bytes[156]}; octal 124 12; entry_size=$VAL
      if [[ $kind -eq 76 ]]; then
        [[ $name == '././@LongLink' && $pending_pax == false && $entry_size -gt 1 && $entry_size -le 242 ]] || die 'invalid GNU long-name header'
        read_bytes "$((offset + 512))" "$entry_size"
        [[ ${bytes[entry_size - 1]} -eq 0 ]] || die 'unterminated GNU long name'
        ascii 0 "$entry_size" true; safe_name "${VAL%/}"; pax_path=$VAL; pending_pax=true
        offset=$((offset + 512 + ((entry_size + 511) / 512) * 512))
        continue
      fi
      if [[ $kind -eq 120 || $kind -eq 103 ]]; then
        [[ $name == '././@PaxHeader' ]] || safe_name "$name"
        [[ $pending_pax == false ]] || die 'ambiguous consecutive PAX headers'
        pax_keys='|'
        if [[ $kind -eq 120 ]]; then pending_pax=true; scope=local; else scope=global; fi
        pax_metadata "$((offset + 512))" "$entry_size" "$scope"
        offset=$((offset + 512 + ((entry_size + 511) / 512) * 512))
        continue
      fi
      [[ $kind -eq 0 || $kind -eq 48 || $kind -eq 53 ]] || die 'non-regular tar member'
      safe_name "${name%/}"
      [[ -z $pax_path ]] || name=$pax_path
      [[ -z $pax_size || $pax_size -eq $entry_size ]] || die 'ambiguous PAX size override'
      pax_path=''; pax_size=''; pending_pax=false
      if [[ $kind -eq 53 ]]; then [[ $entry_size -eq 0 ]] || die 'nonempty tar directory'; name=${name%/}; fi
      safe_name "$name"
      if [[ $kind -eq 53 ]]; then remember "$name" true; else remember "$name" false; fi
      next=$((offset + 512 + ((entry_size + 511) / 512) * 512))
      [[ $next -le $expanded ]] || die 'truncated tar member'
      if [[ $name == "$member" ]]; then
        [[ $kind -ne 53 && $entry_size -gt 0 ]] || die 'declared member is not a regular executable'
        found=true; selected_offset=$((offset / 512 + 1)); selected_size=$entry_size
      fi
      offset=$next
    done
    [[ $offset -lt $expanded && $found == true ]] || die 'declared tar member or end marker missing'
    # Read only the declared regular member; archive paths never reach the filesystem.
    dd if="$archive" bs=512 skip="$selected_offset" count="$(((selected_size + 511) / 512))" 2>/dev/null | head -c "$selected_size" > "$installed"
  else
    command -v unzip >/dev/null 2>&1 || die 'native unzip utility unavailable'
    archive=$download
    [[ $size -ge 22 ]] || die 'truncated ZIP archive'
    read_bytes "$((size - 22))" 22
    le 0 4
    if [[ $VAL -ne 101010256 ]]; then
      tail_length=65557; [[ $size -ge $tail_length ]] || tail_length=$size
      read_bytes "$((size - tail_length))" "$tail_length"
      candidate=-1
      for ((i=0; i<=tail_length-22; i++)); do
        if [[ ${bytes[i]} -eq 80 && ${bytes[i+1]} -eq 75 && ${bytes[i+2]} -eq 5 && ${bytes[i+3]} -eq 6 ]]; then
          le "$((i + 20))" 2
          if [[ $((i + 22 + VAL)) -eq $tail_length ]]; then [[ $candidate -eq -1 ]] || die 'ambiguous ZIP end records'; candidate=$i; fi
        fi
      done
      [[ $candidate -ge 0 ]] || die 'missing ZIP end record'
      bytes=( "${bytes[@]:candidate:22}" )
    fi
    le 4 4; [[ $VAL -eq 0 ]] || die 'multi-disk ZIP forbidden'
    le 8 2; entries=$VAL; le 10 2; [[ $VAL -eq $entries && $entries -gt 0 && $entries -le 1024 ]] || die 'invalid ZIP entry count'
    le 12 4; directory_size=$VAL; le 16 4; directory=$VAL; le 20 2; archive_comment=$VAL
    [[ $((directory + directory_size + 22 + archive_comment)) -eq $size ]] || die 'unsupported ZIP layout'
    cursor=$directory; physical=0; total=0; selected_size=0
    for ((index=0; index<entries; index++)); do
      read_bytes "$cursor" 46
      le 0 4; [[ $VAL -eq 33639248 ]] || die 'invalid ZIP directory record'
      le 4 2; made_by=$VAL; le 6 2; [[ $VAL -le 20 ]] || die 'unsupported ZIP version'
      le 8 2; flags=$VAL; le 10 2; method=$VAL
      [[ $((flags & ~2062)) -eq 0 && ($method -eq 0 || $method -eq 8) && ($method -eq 8 || $((flags & 6)) -eq 0) ]] || die 'unsupported ZIP flags or compression'
      le 16 4; crc=$VAL; le 20 4; compressed=$VAL; le 24 4; entry_size=$VAL
      le 28 2; length=$VAL; le 30 2; extra=$VAL; le 32 2; comment=$VAL; le 34 2; disk=$VAL
      le 38 4; attrs=$VAL; le 42 4; local_offset=$VAL
      [[ $length -gt 0 && $length -le 241 && $extra -le 4096 && $disk -eq 0 && $local_offset -eq $physical ]] || die 'unsupported or ambiguous ZIP metadata'
      total=$((total + entry_size)); [[ $total -le $MAX && $compressed -le $MAX ]] || die 'ZIP expanded size limit exceeded'
      read_bytes "$((cursor + 46))" "$length"; ascii 0 "$length" false; name=$VAL
      directory_entry=false; [[ $name != */ ]] || directory_entry=true
      # Unix type must be explicit. DOS files may only carry ordinary attributes.
      mode=$(((attrs >> 16) & 61440)); host=$((made_by >> 8))
      if [[ $host -eq 3 ]]; then
        if [[ $directory_entry == true ]]; then [[ $mode -eq 16384 ]] || die 'non-directory ZIP member'; else [[ $mode -eq 32768 ]] || die 'non-regular ZIP member'; fi
      elif [[ $host -eq 0 ]]; then
        [[ $((attrs & ~63)) -eq 0 && $((attrs & 8)) -eq 0 ]] || die 'unsupported DOS ZIP attributes'
        if [[ $directory_entry == true ]]; then [[ $((attrs & 16)) -eq 16 ]] || die 'ambiguous ZIP directory'; else [[ $((attrs & 16)) -eq 0 ]] || die 'ambiguous ZIP file'; fi
      else die 'unsupported ZIP creator platform'; fi
      if [[ $directory_entry == true ]]; then [[ $entry_size -eq 0 ]] || die 'nonempty ZIP directory'; fi
      safe_name "${name%/}"; remember "${name%/}" "$directory_entry"
      zip_extras "$((cursor + 46 + length))" "$extra"
      read_bytes "$physical" 30
      le 0 4; [[ $VAL -eq 67324752 ]] || die 'invalid ZIP local record'
      le 4 2; [[ $VAL -le 20 ]] || die 'unsupported ZIP local version'
      le 6 2; [[ $VAL -eq $flags ]] || die 'ZIP local flags mismatch'
      le 8 2; [[ $VAL -eq $method ]] || die 'ZIP local method mismatch'
      le 14 4; [[ $VAL -eq $crc || ($((flags & 8)) -ne 0 && $VAL -eq 0) ]] || die 'ZIP local checksum mismatch'
      le 18 4; [[ $VAL -eq $compressed || ($((flags & 8)) -ne 0 && $VAL -eq 0) ]] || die 'ZIP local compressed size mismatch'
      le 22 4; [[ $VAL -eq $entry_size || ($((flags & 8)) -ne 0 && $VAL -eq 0) ]] || die 'ZIP local expanded size mismatch'
      le 26 2; [[ $VAL -eq $length ]] || die 'ZIP local name length mismatch'
      le 28 2; local_extra=$VAL; [[ $local_extra -le 4096 ]] || die 'oversized ZIP local extra metadata'
      read_bytes "$((physical + 30))" "$length"; ascii 0 "$length" false
      [[ $VAL == "$name" ]] || die 'ZIP local and directory names differ'
      zip_extras "$((physical + 30 + length))" "$local_extra"
      physical=$((physical + 30 + length + local_extra + compressed))
      if [[ $((flags & 8)) -ne 0 ]]; then
        read_bytes "$physical" 4; le 0 4
        if [[ $VAL -eq 134695760 ]]; then physical=$((physical + 4)); fi
        read_bytes "$physical" 12; le 0 4; [[ $VAL -eq $crc ]] || die 'ZIP descriptor checksum mismatch'
        le 4 4; [[ $VAL -eq $compressed ]] || die 'ZIP descriptor compressed size mismatch'
        le 8 4; [[ $VAL -eq $entry_size ]] || die 'ZIP descriptor expanded size mismatch'
        physical=$((physical + 12))
      fi
      [[ $physical -le $directory ]] || die 'ZIP members overlap directory'
      cursor=$((cursor + 46 + length + extra + comment))
      if [[ $name == "$member" ]]; then [[ $directory_entry == false && $entry_size -gt 0 ]] || die 'declared member is not a regular executable'; found=true; selected_size=$entry_size; fi
    done
    [[ $cursor -eq $((directory + directory_size)) && $physical -eq $directory && $found == true ]] || die 'ZIP layout or declared member mismatch'
    if ! (ulimit -t 120; unzip -p "$archive" "$member" 2>/dev/null) | head -c "$((selected_size + 1))" > "$installed"; then die 'ZIP member extraction failed'; fi
    [[ $(wc -c < "$installed") -eq $selected_size ]] || die 'ZIP member expanded size mismatch'
  fi
fi
chmod 755 "$installed"
if ! "$installed" build-info --json --expect-version "$RELSHIP_VERSION" \
  --expect-source-id "$RELSHIP_SOURCE_ID" --expect-contract 1 >/dev/null 2>&1; then
  die 'installed engine build identity mismatch'
fi
if [[ -n ${GITHUB_ENV:-} ]]; then printf 'RELSHIP_BIN=%s\n' "$installed" >> "$GITHUB_ENV"; else printf '%s\n' "$installed"; fi
complete=true
