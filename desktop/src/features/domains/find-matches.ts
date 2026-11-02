/** Start offsets of every case-insensitive, non-overlapping occurrence of `query` in `text`. */
export function findMatches(text: string, query: string): number[] {
  if (query === "") return [];
  const haystack = text.toLowerCase();
  const needle = query.toLowerCase();
  const matches: number[] = [];
  for (let at = haystack.indexOf(needle); at >= 0; at = haystack.indexOf(needle, at + needle.length)) {
    matches.push(at);
  }
  return matches;
}

/** The first match at or after `caret`, wrapping to the first; undefined when there are none. */
export function nextMatch(matches: readonly number[], caret: number): number | undefined {
  return matches.find((m) => m >= caret) ?? matches[0];
}

/** The last match strictly before `caret`, wrapping to the last; undefined when there are none. */
export function previousMatch(matches: readonly number[], caret: number): number | undefined {
  return [...matches].reverse().find((m) => m < caret) ?? matches[matches.length - 1];
}
