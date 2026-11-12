#!/usr/bin/env node
// Appends a Markdown job summary (test results, coverage, runner resources)
// to $FORGEJO_STEP_SUMMARY / $GITHUB_STEP_SUMMARY. Without either variable the
// Markdown goes to stdout, so it still shows up in the job log.
//
// Usage: node scripts/ci-summary.mjs --title <text> [--junit <xml>]
//          [--coverage-py <coverage.json>] [--coverage-istanbul <coverage-summary.json>]
//          [--playwright <results.json>] [--resources <label>]
//
// Reports are untrusted input and may be missing when a test step crashed;
// this script reports that instead of failing the job.
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import os from 'node:os';

const MAX_LISTED = 20;
const MAX_MESSAGE = 300;

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i += 2) {
        const key = argv[i];
        const value = argv[i + 1];
        if (!key?.startsWith('--') || value === undefined) {
            throw new Error(`Invalid arguments near "${key ?? ''}"`);
        }
        args[key.slice(2)] = value;
    }
    return args;
}

const decodeXml = (text) => text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => String.fromCodePoint(parseInt(code, 16)))
    .replace(/&amp;/g, '&');

const attributes = (tag) => Object.fromEntries(
    [...tag.matchAll(/([\w:.-]+)="([^"]*)"/g)].map(([, name, value]) => [name, decodeXml(value)]),
);

// Keeps untrusted report text from breaking the surrounding Markdown table.
const cell = (text) => {
    const flat = String(text ?? '').replace(/\s+/g, ' ').trim().replace(/\|/g, '\\|').replace(/`/g, "'");
    return flat.length > MAX_MESSAGE ? `${flat.slice(0, MAX_MESSAGE)}…` : flat;
};

const percent = (value) => (Number.isFinite(value) ? `${value.toFixed(1)}%` : 'n/a');
const seconds = (value) => (Number.isFinite(value) ? `${value.toFixed(1)} s` : 'n/a');
const mib = (bytes) => `${Math.round(bytes / 1024 / 1024)} MiB`;

function missing(label, path) {
    return [`> **${label}:** report \`${path}\` was not found. The step may have crashed before writing it.`, ''];
}

function failureTable(failures, headers = ['Test', 'Message']) {
    if (failures.length === 0) return [];
    const lines = [
        `<details open><summary>${failures.length} failing or flaky</summary>`,
        '',
        `| ${headers.join(' | ')} |`,
        `| ${headers.map(() => '---').join(' | ')} |`,
        ...failures.slice(0, MAX_LISTED).map((row) => `| ${row.map(cell).join(' | ')} |`),
    ];
    if (failures.length > MAX_LISTED) lines.push('', `…and ${failures.length - MAX_LISTED} more; see the log or artifacts.`);
    lines.push('', '</details>', '');
    return lines;
}

function junitSection(path) {
    if (!existsSync(path)) return missing('Test results', path);
    const xml = readFileSync(path, 'utf8');
    const totals = { tests: 0, failures: 0, errors: 0, skipped: 0, time: 0 };
    for (const [tag] of xml.matchAll(/<testsuite\s[^>]*>/g)) {
        const suite = attributes(tag);
        for (const key of Object.keys(totals)) totals[key] += Number(suite[key] ?? 0) || 0;
    }
    const failures = [];
    for (const [, tag, , body] of xml.matchAll(/<testcase\s([^>]*?)(\/>|>([\s\S]*?)<\/testcase>)/g)) {
        const problem = body?.match(/<(failure|error)\b([^>]*)>/);
        if (!problem) continue;
        const testcase = attributes(tag);
        const name = [testcase.classname, testcase.name].filter(Boolean).join(' › ');
        failures.push([name, attributes(problem[2]).message ?? problem[1]]);
    }
    const failed = totals.failures + totals.errors;
    const passed = totals.tests - failed - totals.skipped;
    return [
        `${failed === 0 ? '✅' : '❌'} **${passed} passed**, ${failed} failed, ${totals.skipped} skipped in ${seconds(totals.time)}`,
        '',
        ...failureTable(failures),
    ];
}

function coverageTable(rows) {
    return [
        '| Coverage | Covered | Total | % |',
        '| --- | ---: | ---: | ---: |',
        ...rows.map(([name, covered, total, pct]) => `| ${name} | ${covered} | ${total} | ${percent(pct)} |`),
        '',
    ];
}

function pythonCoverageSection(path) {
    if (!existsSync(path)) return missing('Coverage', path);
    const { totals = {} } = JSON.parse(readFileSync(path, 'utf8'));
    const rows = [['Lines', totals.covered_lines, totals.num_statements, totals.percent_covered]];
    if (totals.num_branches) {
        rows.push(['Branches', totals.covered_branches, totals.num_branches,
            (100 * totals.covered_branches) / totals.num_branches]);
    }
    return coverageTable(rows);
}

function istanbulCoverageSection(path) {
    if (!existsSync(path)) return missing('Coverage', path);
    const { total = {} } = JSON.parse(readFileSync(path, 'utf8'));
    return coverageTable(
        ['lines', 'statements', 'functions', 'branches']
            .filter((key) => total[key])
            .map((key) => [key[0].toUpperCase() + key.slice(1), total[key].covered, total[key].total, total[key].pct]),
    );
}

function playwrightSection(path) {
    if (!existsSync(path)) return missing('Browser test results', path);
    const report = JSON.parse(readFileSync(path, 'utf8'));
    const projects = new Map();
    const problems = [];
    const visit = (suite, trail) => {
        for (const spec of suite.specs ?? []) {
            for (const test of spec.tests ?? []) {
                const name = test.projectName || 'default';
                const row = projects.get(name) ?? { expected: 0, unexpected: 0, flaky: 0, skipped: 0, duration: 0 };
                row[test.status] = (row[test.status] ?? 0) + 1;
                for (const result of test.results ?? []) row.duration += result.duration ?? 0;
                projects.set(name, row);
                if (test.status !== 'unexpected' && test.status !== 'flaky') continue;
                const failed = (test.results ?? []).find((result) => result.error?.message);
                const message = (failed?.error?.message ?? '').replace(/\u001b\[[0-9;]*m/g, '').split('\n')[0];
                problems.push([name, test.status === 'flaky' ? 'flaky' : 'failed',
                    [...trail, spec.title].join(' › '), message]);
            }
        }
        for (const child of suite.suites ?? []) visit(child, [...trail, child.title].filter(Boolean));
    };
    for (const suite of report.suites ?? []) visit(suite, [suite.title].filter(Boolean));

    const stats = report.stats ?? {};
    const lines = [
        `${stats.unexpected ? '❌' : '✅'} **${stats.expected ?? 0} passed**, ${stats.unexpected ?? 0} failed, `
            + `${stats.flaky ?? 0} flaky, ${stats.skipped ?? 0} skipped in ${seconds((stats.duration ?? 0) / 1000)}`,
        '',
        '| Browser | Passed | Failed | Flaky | Skipped | Test time |',
        '| --- | ---: | ---: | ---: | ---: | ---: |',
        ...[...projects].map(([name, row]) => `| ${cell(name)} | ${row.expected} | ${row.unexpected} | ${row.flaky} | ${row.skipped} | ${seconds(row.duration / 1000)} |`),
        '',
    ];
    for (const error of report.errors ?? []) lines.push(`> **Run error:** ${cell(error.message)}`, '');
    return [...lines, ...failureTable(problems, ['Browser', 'Result', 'Test', 'First error'])];
}

const readFirst = (paths) => {
    for (const path of paths) {
        try { return readFileSync(path, 'utf8').trim(); } catch { /* try the next candidate */ }
    }
    return null;
};

// Memory figures explain a killed process: the container (cgroup) limit and
// its OOM-kill counter are distinct from the memory of the host VM.
function resourcesSection(label) {
    const meminfo = Object.fromEntries(
        [...(readFirst(['/proc/meminfo']) ?? '').matchAll(/^(\w+):\s+(\d+) kB/gm)]
            .map(([, key, value]) => [key, Number(value) * 1024]),
    );
    const rows = [
        ['CPUs', String(os.availableParallelism())],
        ['Memory total', mib(os.totalmem())],
        ['Memory available', meminfo.MemAvailable === undefined ? 'n/a' : mib(meminfo.MemAvailable)],
        ['Swap total', meminfo.SwapTotal === undefined ? 'n/a' : mib(meminfo.SwapTotal)],
        ['Swap free', meminfo.SwapFree === undefined ? 'n/a' : mib(meminfo.SwapFree)],
    ];
    const limit = readFirst(['/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes']);
    if (limit !== null) rows.push(['Container memory limit', /^\d+$/.test(limit) && Number(limit) < 2 ** 60 ? mib(Number(limit)) : 'none']);
    const current = readFirst(['/sys/fs/cgroup/memory.current', '/sys/fs/cgroup/memory/memory.usage_in_bytes']);
    if (current !== null) rows.push(['Container memory in use', mib(Number(current))]);
    const peak = readFirst(['/sys/fs/cgroup/memory.peak', '/sys/fs/cgroup/memory/memory.max_usage_in_bytes']);
    if (peak !== null) rows.push(['Container memory peak', mib(Number(peak))]);
    const oomKills = readFirst(['/sys/fs/cgroup/memory.events'])?.match(/^oom_kill (\d+)/m)?.[1];
    if (oomKills !== undefined) rows.push(['Container OOM kills', Number(oomKills) > 0 ? `⚠️ ${oomKills}` : '0']);
    return [
        `<details${Number(oomKills) > 0 ? ' open' : ''}><summary>Runner resources (${cell(label)})</summary>`,
        '',
        '| Resource | Value |',
        '| --- | ---: |',
        ...rows.map(([name, value]) => `| ${name} | ${value} |`),
        '',
        '</details>',
        '',
    ];
}

function build(args) {
    const sections = [
        ['junit', junitSection],
        ['coverage-py', pythonCoverageSection],
        ['coverage-istanbul', istanbulCoverageSection],
        ['playwright', playwrightSection],
        ['resources', resourcesSection],
    ];
    const lines = args.title ? [`## ${args.title}`, ''] : [];
    for (const [key, render] of sections) {
        if (args[key] === undefined) continue;
        try {
            lines.push(...render(args[key]));
        } catch (error) {
            lines.push(`> Could not read \`${args[key]}\`: ${cell(error.message)}`, '');
        }
    }
    return `${lines.join('\n')}\n`;
}

try {
    const markdown = build(parseArgs(process.argv.slice(2)));
    const target = process.env.FORGEJO_STEP_SUMMARY || process.env.GITHUB_STEP_SUMMARY;
    if (target) appendFileSync(target, markdown);
    else process.stdout.write(markdown);
} catch (error) {
    // A broken summary must never turn a passing job red.
    console.error(`ci-summary: ${error.message}`);
}
