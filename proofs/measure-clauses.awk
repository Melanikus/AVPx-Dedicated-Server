# MEASURING ONLY (branch proofs-measure-7, Third, 2026-11-11; never merged, never the real Proofs). ProVerif's output with
# "set verboseRules = true" (every clause it makes), summarised so a run that makes millions of them leaves a log a person can read:
# - its RESULT lines, secrecy assumptions and errors go on to the output, as run.sh reads them;
# - every 2,000 lines, one line into the file "stats": how many lines so far, their bytes, and the average and longest of the last 2,000,
#   so a term that keeps growing shows as a size that keeps growing;
# - every 1,000th line, and the last 200, into the file "keep", each cut to a length a log can hold: which clauses those are.
# Plain POSIX awk (Ubuntu's mawk is enough). Called by run.sh's measured_run as: awk -v keep=FILE -v stats=FILE -f measure-clauses.awk
BEGIN { every = 1000; ring = 200; width = 1500 }
/^RESULT|secrecy assumption|[Ee]rror|out of memory|^Fatal/ { print; fflush() }
{
	n++
	len = length($0)
	bytes += len
	windowBytes += len
	if (len > windowMax) windowMax = len
	if (n % every == 0) print "every " n ": " substr($0, 1, width) > keep
	last[n % ring] = substr($0, 1, width)
	if (n % 2000 == 0) {
		printf "stats: lines=%d bytes=%d average_last_2000=%d longest_last_2000=%d\n", n, bytes, windowBytes / 2000, windowMax > stats
		fflush(stats)
		windowBytes = 0
		windowMax = 0
	}
}
END {
	first = n - ring + 1
	if (first < 1) first = 1
	for (i = first; i <= n; i++) print "last " i ": " last[i % ring] > keep
	printf "stats: lines=%d bytes=%d (the end)\n", n, bytes > stats
}
