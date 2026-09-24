// The visible Incomplete choice includes conflicts that require analyst repair.
// API lifecycle values and card badges remain distinct for diagnostics.
export const VISIBLE_LIFECYCLE_FILTERS = ['OPEN', 'INCOMPLETE', 'READY_FOR_APPROVAL', 'ASSESSED']
export const ANALYST_WORK_FILTERS = ['OPEN', 'INCOMPLETE']

export const expandLifecycleSelection = (selection: readonly string[]): string[] =>
    [...new Set(selection.flatMap(value => value === 'INCOMPLETE'
        ? ['INCOMPLETE', 'INCONSISTENT'] : [value]))]
