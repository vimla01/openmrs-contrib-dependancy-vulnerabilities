import { SEVERITY_RANK, VERSION_COLLATOR } from "./constants.js";

export function buildRepositoryModel(file, report) {
  const rawVulnerabilities = Array.isArray(report?.vulnerabilities)
    ? report.vulnerabilities
    : [];

  const dependencyMap = new Map();
  const repositoryCves = [];

  for (const rawVulnerability of rawVulnerabilities) {
    const normalized = normalizeVulnerability(rawVulnerability);
    const dependencyKey = `${normalized.dependencyName}@@${normalized.dependencyVersion}`;

    if (!dependencyMap.has(dependencyKey)) {
      dependencyMap.set(dependencyKey, {
        key: dependencyKey,
        name: normalized.dependencyName,
        version: normalized.dependencyVersion,
        cveMap: new Map()
      });
    }

    mergeCve(dependencyMap.get(dependencyKey).cveMap, normalized);
  }

  const dependencies = [];
  for (const dependency of dependencyMap.values()) {
    const cves = Array.from(dependency.cveMap.values());
    const highestScore = getHighestScore(cves.map((cve) => cve.score));
    const severity = getSeverityByScore(cves);

    repositoryCves.push(...cves);

    dependencies.push({
      key: dependency.key,
      name: dependency.name,
      version: dependency.version,
      cves,
      cveCount: cves.length,
      highestScore,
      severity,
      fixVersion: deriveDependencyFixVersion(cves),
      exploit: cves.some((cve) => cve.exploitKnown) ? "Yes" : "-"
    });
  }

  return {
    key: file.key,
    name: file.name,
    severity: getSeverityByScore(repositoryCves),
    highestScore: getHighestScore(repositoryCves.map((cve) => cve.score)),
    dependencies
  };
}

function normalizeVulnerability(raw) {
  const score = extractScore(raw);

  return {
    id: raw?.id || raw?.name || "Unknown CVE",
    description: raw?.description || "-",
    severity: Number.isFinite(score) ? severityFromScore(score) : normalizeSeverity(raw?.severity),
    score,
    fixedIn: extractFixedIn(raw),
    affectedVersions: extractAffectedVersions(raw),
    cwe: extractCwe(raw),
    exploitKnown: detectExploit(raw),
    links: collectLinks(raw),
    dependencyName: raw?.location?.dependency?.package?.name || "Unknown dependency",
    dependencyVersion: raw?.location?.dependency?.version || "-"
  };
}

function mergeCve(cveMap, incoming) {
  const existing = cveMap.get(incoming.id);

  if (!existing) {
    cveMap.set(incoming.id, { ...incoming });
    return;
  }

  existing.score = getHighestScore([existing.score, incoming.score]);
  existing.severity = Number.isFinite(existing.score)
    ? severityFromScore(existing.score)
    : worseSeverity(existing.severity, incoming.severity);
  existing.fixedIn = pickHighestVersion([existing.fixedIn, incoming.fixedIn]);
  existing.exploitKnown = existing.exploitKnown || incoming.exploitKnown;
  existing.links = uniqueLinks([...existing.links, ...incoming.links]);

  if (existing.description === "-" && incoming.description !== "-") {
    existing.description = incoming.description;
  }

  if (existing.affectedVersions === "-" && incoming.affectedVersions !== "-") {
    existing.affectedVersions = incoming.affectedVersions;
  }

  if (existing.cwe === "-" && incoming.cwe !== "-") {
    existing.cwe = incoming.cwe;
  }
}

function collectLinks(raw) {
  const links = [];

  if (Array.isArray(raw?.links)) {
    for (const entry of raw.links) {
      if (entry?.url) {
        links.push({
          label: entry.name || "Reference",
          url: entry.url
        });
      }
    }
  }

  if (Array.isArray(raw?.identifiers)) {
    for (const identifier of raw.identifiers) {
      if (identifier?.url) {
        links.push({
          label: identifier.name || identifier.type || "Identifier",
          url: identifier.url
        });
      }
    }
  }

  return uniqueLinks(links);
}

function uniqueLinks(links) {
  const seen = new Set();
  const unique = [];

  for (const link of links) {
    if (!link?.url || seen.has(link.url)) {
      continue;
    }

    seen.add(link.url);
    unique.push(link);
  }

  return unique;
}

function extractScore(raw) {
  const candidates = [
    raw?.score,
    raw?.cvss?.score,
    raw?.cvssScore,
    raw?.details?.cvss?.score,
    raw?.details?.score,
    raw?.severity_score
  ];

  for (const candidate of candidates) {
    const parsed = toScore(candidate);
    if (parsed !== null) {
      return parsed;
    }
  }

  return null;
}

function toScore(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value >= 0 && value <= 10 ? value : null;
  }

  if (typeof value !== "string") {
    return null;
  }

  const parsed = Number.parseFloat(value.trim());
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 10) {
    return null;
  }

  return parsed;
}

function extractFixedIn(raw) {
  const candidates = [
    raw?.fixedIn,
    raw?.fixed_in,
    raw?.fixVersion,
    raw?.fixedVersion,
    raw?.solution
  ];

  const versions = [];

  for (const candidate of candidates) {
    versions.push(...extractVersions(candidate));
  }

  return pickHighestVersion(versions);
}

function extractAffectedVersions(raw) {
  const candidates = [
    raw?.affectedVersions,
    raw?.affected_versions,
    raw?.versions,
    raw?.details?.affectedVersions,
    raw?.details?.affected_versions,
    raw?.details?.versions
  ];

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    if (Array.isArray(candidate)) {
      const values = candidate
        .map((item) => (typeof item === "string" ? item.trim() : ""))
        .filter(Boolean);

      if (values.length > 0) {
        return values.join(", ");
      }
    }

    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.trim();
    }
  }

  return "-";
}

function extractCwe(raw) {
  if (Array.isArray(raw?.identifiers)) {
    for (const identifier of raw.identifiers) {
      const name = `${identifier?.name || ""} ${identifier?.value || ""}`;
      const match = name.match(/CWE-\d+/i);
      if (match) {
        return match[0].toUpperCase();
      }
    }
  }

  if (typeof raw?.description === "string") {
    const match = raw.description.match(/CWE-\d+/i);
    if (match) {
      return match[0].toUpperCase();
    }
  }

  return "-";
}

function detectExploit(raw) {
  if (raw?.exploit === true || raw?.exploitAvailable === true) {
    return true;
  }

  const references = [
    ...(Array.isArray(raw?.links) ? raw.links : []),
    ...(Array.isArray(raw?.identifiers) ? raw.identifiers : [])
  ];

  for (const reference of references) {
    const label = String(reference?.name || "").toLowerCase();
    const url = String(reference?.url || "").toLowerCase();

    if (label.includes("exploit")) {
      return true;
    }

    if (url.includes("exploit-db") || url.includes("packetstorm") || url.includes("poc")) {
      return true;
    }
  }

  return false;
}

function extractVersions(input) {
  if (!input) {
    return [];
  }

  if (Array.isArray(input)) {
    return input.flatMap((item) => extractVersions(item));
  }

  if (typeof input === "object") {
    return extractVersions(input.version || input.fixedIn || input.value || "");
  }

  if (typeof input !== "string") {
    return [];
  }

  const matches = input.match(/\b\d+(?:\.\d+){1,}(?:[-+._][0-9A-Za-z]+)*/g);
  return matches || [];
}

export function normalizeSeverity(rawSeverity) {
  if (typeof rawSeverity !== "string") {
    return "Unknown";
  }

  const lower = rawSeverity.trim().toLowerCase();
  if (lower.startsWith("critical")) {
    return "Critical";
  }
  if (lower.startsWith("high")) {
    return "High";
  }
  if (lower.startsWith("medium")) {
    return "Medium";
  }
  if (lower.startsWith("low")) {
    return "Low";
  }

  return "Unknown";
}

function severityFromScore(score) {
  if (!Number.isFinite(score)) {
    return "Unknown";
  }

  if (score >= 9) {
    return "Critical";
  }
  if (score >= 7) {
    return "High";
  }
  if (score >= 4) {
    return "Medium";
  }
  if (score > 0) {
    return "Low";
  }

  return "Unknown";
}

function getSeverityByScore(cves) {
  if (!Array.isArray(cves) || cves.length === 0) {
    return "Unknown";
  }

  let bestScoredCve = null;

  for (const cve of cves) {
    if (!Number.isFinite(cve?.score)) {
      continue;
    }

    if (!bestScoredCve) {
      bestScoredCve = cve;
      continue;
    }

    const byScore = compareScoreDesc(cve.score, bestScoredCve.score);
    if (byScore < 0) {
      bestScoredCve = cve;
      continue;
    }

    if (byScore === 0) {
      const bySeverity = compareSeverityDesc(cve.severity, bestScoredCve.severity);
      if (bySeverity < 0 || (bySeverity === 0 && compareTextAsc(cve.id, bestScoredCve.id) < 0)) {
        bestScoredCve = cve;
      }
    }
  }

  if (bestScoredCve) {
    return normalizeSeverity(bestScoredCve.severity);
  }

  return getHighestSeverity(cves.map((cve) => cve.severity));
}

function getHighestSeverity(severities) {
  let winner = "Unknown";

  for (const severity of severities) {
    winner = worseSeverity(winner, severity);
  }

  return winner;
}

function worseSeverity(a, b) {
  return severityRank(a) >= severityRank(b) ? normalizeSeverity(a) : normalizeSeverity(b);
}

function severityRank(severity) {
  return SEVERITY_RANK[normalizeSeverity(severity)] || 0;
}

function getHighestScore(scores) {
  let max = null;

  for (const score of scores) {
    if (!Number.isFinite(score)) {
      continue;
    }

    if (max === null || score > max) {
      max = score;
    }
  }

  return max;
}

function deriveDependencyFixVersion(cves) {
  const versions = [];

  for (const cve of cves) {
    if (!cve.fixedIn) {
      return null;
    }

    versions.push(cve.fixedIn);
  }

  return pickHighestVersion(versions);
}

function pickHighestVersion(versions) {
  const clean = versions.filter((version) => typeof version === "string" && version.trim().length);
  if (clean.length === 0) {
    return null;
  }

  let best = clean[0];
  for (const version of clean.slice(1)) {
    if (VERSION_COLLATOR.compare(version, best) > 0) {
      best = version;
    }
  }

  return best;
}

export function sortRepositories(repositories) {
  const sorted = [...repositories];

  sorted.sort((a, b) => {
    const bySeverity = compareSeverityDesc(a.severity, b.severity);
    if (bySeverity !== 0) {
      return bySeverity;
    }

    const byScore = compareScoreDesc(a.highestScore, b.highestScore);
    if (byScore !== 0) {
      return byScore;
    }

    return compareTextAsc(a.name, b.name);
  });

  return sorted;
}

export function sortDependencies(dependencies) {
  const sorted = [...dependencies];

  sorted.sort((a, b) => {
    const bySeverity = compareSeverityDesc(a.severity, b.severity);
    if (bySeverity !== 0) {
      return bySeverity;
    }

    const byScore = compareScoreDesc(a.highestScore, b.highestScore);
    if (byScore !== 0) {
      return byScore;
    }

    return compareTextAsc(a.name, b.name);
  });

  return sorted;
}

export function sortCves(cves) {
  const sorted = [...cves];

  sorted.sort((a, b) => {
    const byScore = compareScoreDesc(a.score, b.score);
    if (byScore !== 0) {
      return byScore;
    }

    const bySeverity = compareSeverityDesc(a.severity, b.severity);
    if (bySeverity !== 0) {
      return bySeverity;
    }

    return compareTextAsc(a.id, b.id);
  });

  return sorted;
}

function compareSeverityDesc(a, b) {
  return severityRank(b) - severityRank(a);
}

function compareScoreDesc(a, b) {
  const aValid = Number.isFinite(a);
  const bValid = Number.isFinite(b);

  if (!aValid && !bValid) {
    return 0;
  }
  if (!aValid) {
    return 1;
  }
  if (!bValid) {
    return -1;
  }

  return b - a;
}

export function compareTextAsc(a, b) {
  return String(a).localeCompare(String(b), undefined, {
    sensitivity: "base",
    numeric: true
  });
}

export function compareTextDesc(a, b) {
  return compareTextAsc(b, a);
}

export function formatScore(score) {
  if (!Number.isFinite(score)) {
    return "-";
  }

  return `${score.toFixed(1).replace(/\.0$/, "")}/10`;
}

export function severityClass(severity) {
  return `severity-${normalizeSeverity(severity).toLowerCase()}`;
}
