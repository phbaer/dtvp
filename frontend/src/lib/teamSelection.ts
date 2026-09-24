export function resolveTeamTerm(term: string, options: readonly string[], aliases: Readonly<Record<string, readonly string[]>> = {}) {
    const canonical = (name: string) => Object.entries(aliases).find(([team, names]) =>
        [team, ...names].some(alias => alias.toLowerCase() === name.toLowerCase()))?.[0] || name
    const teams = [...new Set(options.map(canonical))].sort((a, b) => a.localeCompare(b))
    const names = (team: string) => [team, ...(aliases[team] || [])]
    const query = term.trim().toLowerCase()
    const exact = teams.filter(team => names(team).some(name => name.toLowerCase() === query))
    const matches = exact.length ? exact : teams.filter(team => names(team).some(name => name.toLowerCase().includes(query)))
    return { resolved: matches.length === 1 ? matches[0]! : null, matches }
}
