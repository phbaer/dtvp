/**
 * Compares two version strings for sorting.
 * Handles semver-like patterns (e.g., 1.2.3, v1.2.3) and numeric sorting.
 */
export function compareVersions(a: string, b: string): number {
    const cleanA = a.startsWith('v') ? a.substring(1) : a;
    const cleanB = b.startsWith('v') ? b.substring(1) : b;

    const partsA = cleanA.split('.').map(Number);
    const partsB = cleanB.split('.').map(Number);

    const maxLength = Math.max(partsA.length, partsB.length);

    for (let i = 0; i < maxLength; i++) {
        const numA = partsA[i];
        const numB = partsB[i];

        // If one is NaN and the other is a number, the number wins
        if (isNaN(numA as number) && !isNaN(numB as number)) return -1;
        if (!isNaN(numA as number) && isNaN(numB as number)) return 1;

        const valA = isNaN(numA as number) ? 0 : numA;
        const valB = isNaN(numB as number) ? 0 : numB;

        if (valA > valB) return 1;
        if (valA < valB) return -1;
    }

    // If numerical parts are identical, we consider them equal for our sorting purposes
    // but we can use localeCompare as a final stable fallback if they are truly different strings
    return 0;
}

/**
 * Sorts an array of version strings.
 * Default is descending (newest first).
 */
export function sortVersions(versions: string[], ascending = false): string[] {
    return [...versions].sort((a, b) => {
        const cmp = compareVersions(a, b);
        return ascending ? cmp : -cmp;
    });
}
