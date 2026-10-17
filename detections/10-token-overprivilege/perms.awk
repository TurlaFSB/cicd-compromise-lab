# perms.awk — extract GITHUB_TOKEN permission facts from a workflow file.
#
# Emits tab-separated records on stdout:
#   TRIG<TAB><name>                          a trigger listed under `on:`
#   WFPERM_PRESENT<TAB><line>                workflow-level `permissions:` exists
#   WFSCALAR<TAB><line><TAB><value>          workflow-level scalar (write-all/read-all)
#   WFPERM<TAB><line><TAB><scope><TAB><lvl>  workflow-level scope grant
#   JOB<TAB><name><TAB><line>                a job key
#   JOBPERM_PRESENT<TAB><job><TAB><line>     job-level `permissions:` exists
#   JOBSCALAR<TAB><job><TAB><line><TAB><v>   job-level scalar
#   JOBPERM<TAB><job><TAB><line><TAB><scope><TAB><lvl>   job-level scope grant
#
# POSIX awk only (works under mawk and gawk). Comments and blank lines are
# ignored. Flow mappings (`permissions: { contents: read }`) are supported.

function strip(s) {
  sub(/[[:space:]]+#.*$/, "", s)
  sub(/^[[:space:]]+/, "", s)
  sub(/[[:space:]]+$/, "", s)
  gsub(/["']/, "", s)
  return s
}

function emit_scope(kind, jobname, ln, scope, lvl) {
  if (kind == "wf") print "WFPERM\t" ln "\t" scope "\t" lvl
  else print "JOBPERM\t" jobname "\t" ln "\t" scope "\t" lvl
}

function handle_value(kind, jobname, ln, v,    inner, n, parts, i, p, sc, lv) {
  if (v == "") return
  if (substr(v, 1, 1) == "{") {
    inner = v
    gsub(/[{}]/, "", inner)
    n = split(inner, parts, ",")
    for (i = 1; i <= n; i++) {
      p = strip(parts[i])
      if (p == "" || index(p, ":") == 0) continue
      sc = p; sub(/:.*/, "", sc)
      lv = p; sub(/^[^:]*:[[:space:]]*/, "", lv)
      emit_scope(kind, jobname, ln, strip(sc), strip(lv))
    }
    return
  }
  if (kind == "wf") print "WFSCALAR\t" ln "\t" v
  else print "JOBSCALAR\t" jobname "\t" ln "\t" v
}

function scope_line(kind, jobname, ln, t,    sc, lv) {
  if (t !~ /^[a-z-]+:/) return
  sc = t; sub(/:.*/, "", sc)
  lv = t; sub(/^[^:]*:[[:space:]]*/, "", lv)
  emit_scope(kind, jobname, ln, sc, strip(lv))
}

BEGIN { sect = "other"; on_ind = -1; job_ind = -1; injobperm = 0; job = "" }

/^[[:space:]]*(#|$)/ { next }

{
  ind = match($0, /[^ ]/) - 1
  t = strip($0)

  if (ind == 0) {
    sect = "other"; injobperm = 0; job = ""
    if (t ~ /^on:/) {
      sect = "on"
      v = strip(substr(t, 4))
      if (v != "") {
        gsub(/[\[\]{}]/, "", v)
        n = split(v, tl, ",")
        for (i = 1; i <= n; i++) {
          nm = strip(tl[i]); sub(/:.*/, "", nm)
          if (nm != "") print "TRIG\t" nm
        }
      }
    } else if (t ~ /^permissions:/) {
      sect = "wfperm"
      print "WFPERM_PRESENT\t" NR
      handle_value("wf", "", NR, strip(substr(t, 13)))
    } else if (t ~ /^jobs:/) {
      sect = "jobs"
    }
    next
  }

  if (sect == "on") {
    if (on_ind < 0) on_ind = ind
    if (ind == on_ind) {
      nm = t; sub(/^-[[:space:]]*/, "", nm); sub(/:.*/, "", nm)
      if (nm != "") print "TRIG\t" nm
    }
  } else if (sect == "wfperm") {
    scope_line("wf", "", NR, t)
  } else if (sect == "jobs") {
    if (job_ind < 0) job_ind = ind
    if (ind == job_ind && t ~ /:$/) {
      job = t; sub(/:$/, "", job); injobperm = 0
      print "JOB\t" job "\t" NR
      next
    }
    if (ind == job_ind + 2 && t ~ /^permissions:/) {
      injobperm = 1; jp_ind = ind
      print "JOBPERM_PRESENT\t" job "\t" NR
      handle_value("job", job, NR, strip(substr(t, 13)))
      next
    }
    if (injobperm && ind > jp_ind) { scope_line("job", job, NR, t); next }
    if (ind <= jp_ind) injobperm = 0
  }
}
