#!/bin/sh
# Runs ProVerif on every model in proofs/, and on the variants that break one half of the hybrid or both, and checks each query gives
# the answer it must. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
# Modified 2026-11-10 by Melanikus: one group at a time, so the Proofs check can run them side by side (proofs.yml); each ProVerif run
# held to a time limit; pqik's query 1 with names that take no arguments (below). Later the same day: secrecy assumptions in every pqik and
# pqxx run, each checked by ProVerif itself (secrets, below). Round 6, the same night: one variant to a group, so each runs on a machine
# of its own; a memory cap; an authentication query alone without phase 1; pqnk's secrecy assumptions; and ProVerif's own line for each
# assumption, shown and required.
#
#   sh proofs/run.sh [group]   needs proverif and timeout on the PATH (GitHub's "Proofs" check installs ProVerif); exits 0 only if every
#                              answer is the one written below. A group is one variant of one query: pqnk-as-written, pqik-q2-dh-broken,
#                              pqxx-q4-both-broken and so on (--groups lists them). pqnk, pqik-q1 to pqik-q3 or pqxx-q1 to pqxx-q4 do all
#                              four variants of that query; with none, every group, one after another.
#
# EVERY QUERY STAYS. A query that isn't proved yet keeps its answer here and fails, so the check stays red until every one is proved
# (Tao 1: a blind spot fails the gate). Splitting the queries changes nothing in the analysis: ProVerif builds its clauses afresh for
# each query declaration (its manual, section 6.7.2, "Grouping queries"), so a model with one query does what that query's own part of
# the whole model does.
#
# PHASE 1, which gives the static keys away after the sessions, stays in every run that asks a secrecy query (forward secrecy), and is
# taken out of a run that asks one authentication query alone. That loses nothing: ProVerif's manual (2.05, section 4.1.6, "Phases")
# says that at the change to phase 1 "all processes which have not yet reached phase i >= 1 are discarded", and in our models only that
# one line is in phase 1, so every event an authentication query asks about happens in phase 0, before the keys are given away. A trace
# that breaks such a query breaks it before phase 1, and is a trace of the model without that line too. The same section: "if a
# protocol discloses a session key after the conclusion of a session, then the secrecy of the data exchanged during that session may be
# compromised but not its authenticity." With it out, the static keys can be assumed secret throughout (secrets, below). Measured: pqxx's
# query 3 ended in a minute this way (proofs-measure 06bd42b, round 4), and was still running at 13 minutes with phase 1 (round 5).
#
# THE TIME LIMIT. Each ProVerif run gets PROOFS_RUN_MINUTES minutes (60 unless set, from 1 to 340). A run that hasn't ended by then fails,
# as one that stops does. A limit can only cost a proof, never make one.
#
# THE MEMORY LIMIT. Each ProVerif run gets PROOFS_MEMORY_GIB gibibytes of address space (14 unless set, from 1 to 2048), so a run that
# needs more stops with "out of memory" and fails, saying so, instead of starving the machine until GitHub loses it (round 5: four
# runners shut down or lost, with no word from ProVerif). GitHub's standard runner for a public repository has 16 GB. A limit can only
# cost a proof, never make one.
#
# THE VARIANTS of each model, made here from it, never kept:
#   as written     every query true
#   dh-broken      the attacker is given the ECDH static keys from the start, and       every query true: ML-KEM alone holds them
#                  every ECDH secret an honest side computes
#   kem-broken     the same for ML-KEM                                                  every query true: ECDH alone holds them
#   both-broken    the attacker is given both                                           every query false: so the model isn't
#                                                                                       trivially true, and the hybrid is what protects
# A broken half is broken entirely, in every model (pqnk and pqxx since 2026-11-10, as pqik was): with its static keys the attacker can
# play that side, so with both broken every authentication query fails too, and is held to it.
# A variant is made by switching on the lines marked LEAKDH or LEAKKEM. ProVerif writes one "RESULT ... is true." or "... is false." line
# a query, in the order the queries are written; "cannot be proved" fails wherever an answer is required.
set -euf

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
group=${1:-all}
minutes=${PROOFS_RUN_MINUTES:-60}
gib=${PROOFS_MEMORY_GIB:-14}

# EVERY QUERY IS IN A GROUP (Primary's review, 2026-11-10). The queries are written once, here, and each has the four variants: proofs.yml's
# matrix must be exactly the groups this makes (its first job checks that, with --groups), and the models must be exactly these three
# with exactly these many queries. So a model or a query added later, or a group dropped from the matrix, can't sit unproved while the
# check stays green: each fails it until it's given its place here, its block below, and its place in the matrix. And a group that runs
# nothing fails (at the end), so a group named here with no block can't pass either.
queries='pqnk pqik-q1 pqik-q2 pqik-q3 pqxx-q1 pqxx-q2 pqxx-q3 pqxx-q4'
kinds='as-written dh-broken kem-broken both-broken'
groups=''
for q in $queries; do
  for k in $kinds; do groups="$groups $q-$k"; done
done
groups=${groups# }
if [ "$group" = --groups ]; then echo "$groups"; exit 0; fi
models=$(find "$here" -maxdepth 1 -name '*.pv' -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ')
if [ "$models" != 'pqik.pv pqnk.pv pqxx.pv ' ]; then echo "proofs: the models are $models, not pqik.pv pqnk.pv pqxx.pv: each needs its groups"; exit 1; fi
for counted in pqnk:2 pqik:3 pqxx:4; do
  n=$(grep -c '^query ' "$here/${counted%%:*}.pv" || true)
  if [ "$n" != "${counted#*:}" ]; then echo "proofs: ${counted%%:*}.pv has $n queries, not ${counted#*:}: each needs its group"; exit 1; fi
done

case "$minutes" in ''|*[!0-9]*) echo 'proofs: PROOFS_RUN_MINUTES is a whole number of minutes'; exit 2 ;; esac
if [ "$minutes" -lt 1 ] || [ "$minutes" -gt 340 ]; then echo 'proofs: PROOFS_RUN_MINUTES is from 1 to 340'; exit 2; fi
case "$gib" in ''|*[!0-9]*) echo 'proofs: PROOFS_MEMORY_GIB is a whole number of gibibytes'; exit 2 ;; esac
if [ "$gib" -lt 1 ] || [ "$gib" -gt 2048 ]; then echo 'proofs: PROOFS_MEMORY_GIB is from 1 to 2048'; exit 2; fi
case "$group" in ''|*[!a-z0-9-]*) group=not-a-group ;; esac
case " all $queries $groups " in
  *" $group "*) ;;
  *) echo 'proofs: the group is one of --groups (a query and a variant, as pqxx-q3-dh-broken), a query (pqnk, pqik-q1 to pqik-q3, pqxx-q1 to pqxx-q4), or none for all of them'; exit 2 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failed=0
ran=0

command -v proverif > /dev/null || { echo 'proofs: proverif is not on the PATH'; exit 1; }
command -v timeout > /dev/null || { echo 'proofs: timeout is not on the PATH, so no run could be held to its time limit'; exit 1; }

# SECRECY ASSUMPTIONS (added 2026-11-10, from the Proofs' round 4 measures; pqnk's in round 6): "not attacker(...)" for every secret the
# variant doesn't give away. A broken half gives away its static keys and every result an honest side computes with that half (dhes, ss1
# and the rest), never the ephemeral exponents, ML-KEM keys and coins themselves. So:
#   as written:  every static key, and every ephemeral secret;
#   dh-broken:   the ML-KEM static keys, and every ephemeral secret;
#   kem-broken:  the ECDH static keys, and every ephemeral secret;
#   both-broken: every ephemeral secret.
# A static key is assumed secret only in phase 0 when the run keeps phase 1, which gives it away after the sessions, and throughout when
# it doesn't (PHASE 1, above). ProVerif then drops every clause that needs the attacker to know one of them, and it checks each assumption
# itself: one that can be derived stops the run with an error, which fails here. ProVerif's manual (2.05, section 6.7.2, page 116): "The
# use of secrecy assumptions preserves soundness because ProVerif also checks that F cannot be derived; if it can be derived, ProVerif
# fails with an error message." Each check also writes a line, "ok, secrecy assumption verified: fact unreachable attacker(...)", and a
# run passes only with that line for every assumption it was given (variant, below), so the log shows each one was checked.
# With them, pqik's query 2 ended in a minute (proofs-measure 06bd42b, round 4), where without them it ran out of memory or time.
secrets() {
  of=$1; kind=$2; later=$3
  case "$of" in
    pqnk) dhstatic='new sdh'; kemstatic='new skem'; ephemeral='new e|new ek|new r1|new re|new r2' ;;
    pqik) dhstatic='new sdh|cdhHonest'; kemstatic='new skem|ckemHonest'; ephemeral='new e|new ek|new r1|new re|new r2|new r3' ;;
    pqxx) dhstatic='new hdh|new jdh'; kemstatic='new hkem|new jkem'; ephemeral='new e|new ek|new r3|new he|new r2|new r4' ;;
    *) return 0 ;;
  esac
  case "$kind" in
    as-written) statics="$dhstatic|$kemstatic" ;;
    dh-broken) statics=$kemstatic ;;
    kem-broken) statics=$dhstatic ;;
    *) statics='' ;;
  esac
  old_ifs=$IFS
  IFS='|'
  for s in $statics; do printf 'not attacker(%s)%s.\n' "$s" "$later"; done
  for s in $ephemeral; do printf 'not attacker(%s).\n' "$s"; done
  IFS=$old_ifs
}

# One run: the model, the variant's name, the sed edits that make it (or nothing), which query (0 for every one), whether every name is
# made with no arguments ("names": see pqik below), and the answers its queries must give, one word each ("true" or "false")
variant() {
  model=$1; name=$2; edits=$3; only=$4; names=$5; want=$6
  # Its query's group (pqnk, or the model and query, as pqxx-q3), and whether this run is to do it
  query=$model
  if [ "$only" -ne 0 ]; then query="$model-q$only"; fi
  if [ "$group" != all ] && [ "$group" != "$query" ] && [ "$group" != "$query-$name" ]; then return 0; fi
  label="$model $name"
  if [ "$only" -ne 0 ]; then label="$model q$only $name"; fi
  if [ "$names" = yes ]; then label="$label, names"; fi
  file="$work/$model-q$only-$name.pv"
  if [ -n "$edits" ]; then sed "$edits" "$here/$model.pv" > "$file.whole"; else cp "$here/$model.pv" "$file.whole"; fi

  # names: every "new x: t" becomes "new x[]: t". At least 4 lines must change, or the model has moved on and this would prove nothing
  if [ "$names" = yes ]; then
    sed 's/^\( *\)new \([A-Za-z0-9_]*\): /\1new \2[]: /' "$file.whole" > "$file.named"
    n=$(diff "$file.whole" "$file.named" | grep -c '^>' || true)
    if [ "$n" -lt 4 ]; then echo "FAIL  $label: names changed $n lines, not 4 or more"; failed=1; return 0; fi
    mv "$file.named" "$file.whole"
  fi

  # One query: a query starts at a line beginning "query " and ends at the line ending with its "."; every other one becomes a comment.
  # Then exactly one must be left.
  if [ "$only" -eq 0 ]; then
    mv "$file.whole" "$file"
  else
    if ! awk -v only="$only" '
      /^query / { n++; inside = 1 }
      { line = $0 }
      inside && n != only { line = "(* " $0 " *)" }
      inside && /\.[ \t]*$/ { inside = 0 }
      { print line }
      END { if (n < only) exit 3 }
    ' "$file.whole" > "$file"; then
      echo "FAIL  $label: $model has no query $only"; failed=1; return 0
    fi
    left=$(grep -c '^query ' "$file" || true)
    if [ "$left" -ne 1 ]; then echo "FAIL  $label: $left queries left, not 1"; failed=1; return 0; fi
  fi

  # Phase 1 (PHASE 1, above): kept with a secrecy query ("query attacker(...)") or with every query; taken out when one authentication
  # query is asked alone. The model must have that line exactly once, and start no phase anywhere else ("phase N;", the instruction,
  # which the comments' words never are), or this would change something it can't see.
  later=' phase 0'
  if [ "$only" -ne 0 ] && ! grep -q '^query attacker(' "$file"; then
    if [ "$(grep -c '^  | (phase 1; out(c, (' "$file")" -ne 1 ]; then echo "FAIL  $label: no single phase-1 line to take out"; failed=1; return 0; fi
    if [ "$(grep -c 'phase [0-9][0-9]*;' "$file")" -ne 1 ]; then echo "FAIL  $label: a phase is started in more places than the one line"; failed=1; return 0; fi
    sed '/^  | (phase 1; out(c, (/d' "$file" > "$file.nophase"
    mv "$file.nophase" "$file"
    later=''
    label="$label, no phase 1"
  fi

  # The secrecy assumptions this model and variant allow (secrets, above), just before the one "process" line
  secrets "$model" "$name" "$later" > "$file.secrets"
  if [ -s "$file.secrets" ]; then
    if [ "$(grep -c '^process$' "$file")" -ne 1 ]; then echo "FAIL  $label: no single \"process\" line to put the secrecy assumptions before"; failed=1; return 0; fi
    awk -v extra="$file.secrets" '/^process$/ { while ((getline line < extra) > 0) print line } { print }' "$file" > "$file.assumed"
    mv "$file.assumed" "$file"
    label="$label, $(wc -l < "$file.secrets" | tr -d ' ') secrets"
  fi

  ran=$((ran + 1))
  # The memory limit (THE MEMORY LIMIT, above) is set in a subshell of its own, so it holds ProVerif and nothing else of this script
  if ( ulimit -v $((gib * 1048576)); exec timeout "${minutes}m" proverif "$file" ) > "$file.out" 2>&1; then code=0; else code=$?; fi
  if [ "$code" -eq 124 ]; then
    echo "FAIL  $label: ProVerif didn't end in $minutes minutes"; tail -n 3 "$file.out"; failed=1; return 0
  fi
  if [ "$code" -ne 0 ] && grep -q 'out of memory' "$file.out"; then
    echo "FAIL  $label: ProVerif ran out of memory (its limit is $gib GiB)"; tail -n 3 "$file.out"; failed=1; return 0
  fi
  if [ "$code" -ne 0 ]; then
    echo "FAIL  $label: ProVerif stopped"; tail -n 20 "$file.out"; failed=1; return 0
  fi

  # Every secrecy assumption it was given has ProVerif's own line saying it was checked (SECRECY ASSUMPTIONS, above): the name, as
  # attacker(name[...]) or, for a later phase, attacker_p1(name[...])
  if [ -s "$file.secrets" ]; then
    while IFS= read -r assumed; do
      secret=$(printf '%s\n' "$assumed" | sed 's/^not attacker(\(new \)\{0,1\}\([A-Za-z0-9_]*\)).*/\2/')
      if ! grep -Eq "ok, secrecy assumption verified: fact unreachable attacker(_p[0-9]+)?\\($secret\\[" "$file.out"; then
        echo "FAIL  $label: no line from ProVerif saying the secrecy assumption on $secret was checked"; failed=1; return 0
      fi
    done < "$file.secrets"
    echo "  $label: $(wc -l < "$file.secrets" | tr -d ' ') secrecy assumptions, each one verified by ProVerif"
  fi
  grep '^RESULT' "$file.out" | sed "s/^/  $label: /"
  got=$(grep '^RESULT' "$file.out" | sed -n 's/.* is \(true\)\.$/\1/p; s/.* is \(false\)\.$/\1/p; s/.*cannot be proved.*/unproved/p' | tr '\n' ' ' | sed 's/ $//')
  # The answers, word by word against what they must be
  set -- $got
  ok=yes
  for must in $want; do
    answer=${1:-none}
    [ "$#" -gt 0 ] && shift
    if [ "$must" != "$answer" ]; then ok=no; fi
  done
  [ "$#" -eq 0 ] || ok=no
  if [ "$ok" = yes ]; then echo "ok    $label: $got"; else echo "FAIL  $label: got \"$got\", must be \"$want\""; failed=1; fi
}

dh='s/(\*LEAKDH //; s/ LEAKDH\*)//'
kem='s/(\*LEAKKEM //; s/ LEAKKEM\*)//'

# Each variant runs only if this run's group asks for it (variant, above): all, its query, or its query and variant.
#
# pqnk: 1 secrecy, 2 the relay's authentication. Handshake A as the code has it until pqIK lands (CRYPTO.md section 14)
variant pqnk as-written '' 0 no 'true true'
variant pqnk dh-broken "$dh" 0 no 'true true'
variant pqnk kem-broken "$kem" 0 no 'true true'
variant pqnk both-broken "$dh; $kem" 0 no 'false false'

# pqik: 1 secrecy, 2 the relay's authentication to the game, 3 the honest player's to the relay. Broken here means broken entirely:
# the attacker gets that half's static secrets as well as every result an honest side computes, so each half alone must hold all three,
# and with both broken every one fails.
#
# Query 1 runs with names that take no arguments ("names" above). As written, a fresh name is, to ProVerif, a function of every message
# its session took before it, and in pqik those nest session in session until the clauses don't fit in memory (the measures, round 2).
# Taking the arguments away only makes ProVerif's picture coarser, never wrong. ProVerif's own manual (2.05, October 17, 2023, section
# 6.7.2, "Performance and termination", page 120) says a name's arguments "tune the performance and precision of the analysis", and:
# "In any case, the internal representation of names always includes session identifiers (necessary for soundness) and variables needed
# to answer queries." So a "true" with names is a proof; at worst names turns a true into "cannot be proved", which fails here.
# With names, query 1 was proved in 2.5 minutes (round 3); queries 2 and 3 don't end with it either, so they run as written.
variant pqik as-written '' 1 yes 'true'
variant pqik dh-broken "$dh" 1 yes 'true'
variant pqik kem-broken "$kem" 1 yes 'true'
variant pqik both-broken "$dh; $kem" 1 yes 'false'
for q in 2 3; do
  variant pqik as-written '' "$q" no 'true'
  variant pqik dh-broken "$dh" "$q" no 'true'
  variant pqik kem-broken "$kem" "$q" no 'true'
  variant pqik both-broken "$dh; $kem" "$q" no 'false'
done

# pqxx: 1 and 2 secrecy (joiner's, host's), 3 the host's authentication, 4 the joiner's
for q in 1 2 3 4; do
  variant pqxx as-written '' "$q" no 'true'
  variant pqxx dh-broken "$dh" "$q" no 'true'
  variant pqxx kem-broken "$kem" "$q" no 'true'
  variant pqxx both-broken "$dh; $kem" "$q" no 'false'
done

if [ "$ran" -eq 0 ]; then echo 'proofs: nothing was run'; exit 1; fi
if [ "$failed" -ne 0 ]; then echo 'proofs: some answers are not the ones they must be'; exit 1; fi
echo 'proofs: every answer is the one it must be'
