# scan.awk — fact extractor for scenario 11 (workflow_run artifact poisoning).
#
# Reads one workflow YAML file and prints tab-separated facts that detect.sh
# turns into findings. Comments are ignored. The parser is intentionally small
# and line-oriented; it tracks just enough structure to tell apart:
#   - a `workflow_run:` TRIGGER key (under on:) from a `github.event.workflow_run`
#     CONTEXT reference,
#   - lines inside a `run:` shell block from lines in `with:`/`env:` mappings,
#   - a `uses:` step from its following `with:` inputs.
#
# Facts (first field is the tag):
#   ONRUN        <line>                 the on: block declares a workflow_run trigger
#   RUNCTX       <line> <field>         github.event.workflow_run.<field> used in a run: block
#   CHECKOUT_REF <line> <field>         a checkout step pins ref: to workflow_run.<field>
#   DL_RUNID     <line>                 an artifact is downloaded from the triggering run
#   DL_GHSCRIPT  <line>                 github-script lists/downloads the run's artifacts
#   EXEC         <line> <token>         a run: line executes code from the workspace

BEGIN { in_on = 0; on_indent = -1; in_run = 0; run_indent = -1; cur_uses = ""; uses_indent = -1 }

# Strip a trailing comment that is clearly not inside quotes (best-effort), and
# skip whole-line comments and blanks.
{
  line = $0
  raw = $0
}
raw ~ /^[[:space:]]*#/ { next }
raw ~ /^[[:space:]]*$/ { next }

# Current indentation of this line.
{
  match(raw, /^[[:space:]]*/)
  indent = RLENGTH
}

# ── on: block tracking ───────────────────────────────────────────────
# Enter when we see a top-level `on:` key.
raw ~ /^on:[[:space:]]*/ { in_on = 1; on_indent = indent; }
# A new top-level key (indent 0) that is not `on:` closes the on: block.
indent == 0 && raw !~ /^on:/ { in_on = 0 }

# A `workflow_run:` mapping key inside on: is the trigger. Guard against the
# context form `github.event.workflow_run` (which contains a dot before it).
in_on == 1 && raw ~ /^[[:space:]]*workflow_run:[[:space:]]*$/ {
  print "ONRUN\t" NR
}
# Also accept `on: [push, workflow_run]` inline and `on: workflow_run`.
raw ~ /^on:.*workflow_run/ && raw !~ /github\.event/ { print "ONRUN\t" NR }

# ── run: block tracking ──────────────────────────────────────────────
# A `run:` key opens a shell block; body lines are more-indented than the key.
raw ~ /^[[:space:]]*run:[[:space:]]*[|>]?[[:space:]]*$/ {
  in_run = 1; run_indent = indent; next
}
raw ~ /^[[:space:]]*run:[[:space:]]+[^|>]/ {
  # single-line run: — scan this line, do not open a block
  scan_run_line(raw, NR)
  in_run = 0
  next
}
# Inside a run block until indentation drops back to or past the run: key.
in_run == 1 && indent <= run_indent { in_run = 0 }
in_run == 1 { scan_run_line(raw, NR) }

# ── uses: / with: ref: tracking (for checkout) ───────────────────────
raw ~ /^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*/ {
  cur_uses = raw
  uses_indent = indent
}
# A ref: input belonging to the current uses: step (more indented), pinned to
# a workflow_run context field.
raw ~ /^[[:space:]]*ref:[[:space:]]*/ && indent > uses_indent && cur_uses ~ /actions\/checkout/ {
  if (match(raw, /github\.event\.workflow_run\.[A-Za-z_]+/)) {
    f = substr(raw, RSTART, RLENGTH)
    sub(/github\.event\.workflow_run\./, "", f)
    print "CHECKOUT_REF\t" NR "\t" f
  }
}

# ── artifact download from the triggering run ────────────────────────
# Official downloader pointed at the triggering run id.
raw ~ /run-id:[[:space:]]*\$\{\{[^}]*github\.event\.workflow_run\.id/ { print "DL_RUNID\t" NR }
# github-script that enumerates/downloads the run's artifacts.
raw ~ /listWorkflowRunArtifacts|downloadArtifact|getArtifact/ { print "DL_GHSCRIPT\t" NR }
# Known third-party downloader (its default is to fetch another run's artifact).
raw ~ /uses:[[:space:]]*dawidd6\/action-download-artifact/ { print "DL_RUNID\t" NR }

# ── helper: scan one run-block line for context refs and execution ────
function scan_run_line(l, ln,    f, tok) {
  if (match(l, /github\.event\.workflow_run\.[A-Za-z_]+/)) {
    f = substr(l, RSTART, RLENGTH)
    sub(/github\.event\.workflow_run\./, "", f)
    print "RUNCTX\t" ln "\t" f
  }
  # Execution of code that may have come from the downloaded artifact / checkout.
  # node/python/bash/sh invoked on a path, a sourced file, or a pipe-to-shell.
  if (l ~ /(^|[^[:alnum:]_])(node|python3?|ruby|php)[[:space:]]+[.\/]/ ||
      l ~ /(^|[^[:alnum:]_])(bash|sh)[[:space:]]+[.\/]/ ||
      l ~ /(^|[[:space:]])(source|\.)[[:space:]]+[.\/]/ ||
      l ~ /\|[[:space:]]*(bash|sh)([[:space:]]|$)/ ||
      l ~ /npm[[:space:]]+(ci|install|run)([[:space:]]|$)/) {
    tok = l
    sub(/^[[:space:]]+/, "", tok)
    gsub(/\t/, " ", tok)
    print "EXEC\t" ln "\t" tok
  }
}
