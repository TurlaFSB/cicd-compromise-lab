# leak.awk — step-aware fact extractor for scenario 13 (credential leakage via
# artifacts). Reads one workflow YAML file and prints tab-separated facts.
#
# It tracks step boundaries (a `- ` list item under steps:) so that `path:` and
# `include-hidden-files:` are only read inside an actions/upload-artifact step,
# and `persist-credentials:` only inside an actions/checkout step. This avoids
# confusing an upload path with, say, an input named `path:` on another action.
#
# Facts:
#   CHECKOUT_PERSIST <line> <0|1>   a checkout step; 1 if persist-credentials:false is set
#   UPLOAD           <line>         an actions/upload-artifact step begins
#   UPLOAD_PATH      <line> <value> a path value inside an upload step (inline or block item)
#   UPLOAD_HIDDEN    <line>         include-hidden-files: true inside an upload step
#   SECRET_TO_FILE   <line>         a run line writes ${{ secrets.* }} to a real file

function flush_checkout() {
  if (cur_kind == "checkout" && co_line > 0)
    print "CHECKOUT_PERSIST\t" co_line "\t" persist
  co_line = 0
}

function indent_of(s,   n) { match(s, /^[ ]*/); return RLENGTH }

{ raw = $0 }
raw ~ /^[[:space:]]*#/ { next }
raw ~ /^[[:space:]]*$/ { next }

# New step boundary: a "- " list item. Flush any pending checkout, reset state.
raw ~ /^[[:space:]]*-[[:space:]]/ {
  flush_checkout()
  cur_kind = ""; in_path = 0; persist = 0
}

# Identify the step's action.
raw ~ /uses:[[:space:]]*actions\/checkout([@/]|$)/ {
  cur_kind = "checkout"; co_line = NR; persist = 0; in_path = 0
}
raw ~ /uses:[[:space:]]*actions\/upload-artifact([@/]|$)/ {
  cur_kind = "upload"; in_path = 0
  print "UPLOAD\t" NR
}

# Inside a checkout step: note persist-credentials: false.
cur_kind == "checkout" && raw ~ /persist-credentials:[[:space:]]*false/ { persist = 1 }

# Inside an upload step: hidden files + path (inline or block).
cur_kind == "upload" {
  if (raw ~ /include-hidden-files:[[:space:]]*true/) print "UPLOAD_HIDDEN\t" NR

  if (raw ~ /^[[:space:]]*path:[[:space:]]*[|>][[:space:]]*$/) {
    in_path = 1; path_indent = indent_of(raw)
  } else if (raw ~ /^[[:space:]]*path:[[:space:]]*[^|>[:space:]]/) {
    v = raw; sub(/^[[:space:]]*path:[[:space:]]*/, "", v)
    gsub(/^["']|["']$/, "", v)
    print "UPLOAD_PATH\t" NR "\t" v
    in_path = 0
  } else if (in_path) {
    if (indent_of(raw) > path_indent && raw !~ /^[[:space:]]*[A-Za-z0-9_-]+:/) {
      v = raw; sub(/^[[:space:]]*/, "", v); sub(/[[:space:]]*$/, "", v)
      gsub(/^["']|["']$/, "", v)
      if (v != "") print "UPLOAD_PATH\t" NR "\t" v
    } else {
      in_path = 0
    }
  }
}

# A secret redirected into a real file (not a $GITHUB_* runner file).
raw ~ /\$\{\{[[:space:]]*secrets\./ {
  if ((raw ~ />/ || raw ~ /(^|[[:space:]])tee([[:space:]]|$)/) && raw !~ /GITHUB_(ENV|OUTPUT|STATE|PATH)/)
    print "SECRET_TO_FILE\t" NR
}

END { flush_checkout() }
