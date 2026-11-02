export interface ClickModifiers {
  /** Cmd on macOS, Ctrl elsewhere: toggle one entry. */
  toggle: boolean;
  /** Shift: select the range from the anchor. */
  range: boolean;
}

export interface SelectionState {
  selected: ReadonlySet<string>;
  /** The entry a shift-click extends from. */
  anchor: string | undefined;
}

export const EMPTY_SELECTION: SelectionState = { selected: new Set(), anchor: undefined };

/**
 * The selection after clicking `pattern` in the visible `rows`: a plain click
 * selects just it, a toggle click adds or removes it, a range click selects
 * everything between the anchor and it.
 */
export function selectionAfterClick(
  state: SelectionState,
  rows: readonly string[],
  pattern: string,
  modifiers: ClickModifiers,
): SelectionState {
  if (modifiers.range && state.anchor !== undefined) {
    const from = rows.indexOf(state.anchor);
    const to = rows.indexOf(pattern);
    if (from >= 0 && to >= 0) {
      const [start, end] = from < to ? [from, to] : [to, from];
      return { selected: new Set(rows.slice(start, end + 1)), anchor: state.anchor };
    }
  }
  if (modifiers.toggle) {
    const selected = new Set(state.selected);
    if (!selected.delete(pattern)) selected.add(pattern);
    return { selected, anchor: pattern };
  }
  return { selected: new Set([pattern]), anchor: pattern };
}
