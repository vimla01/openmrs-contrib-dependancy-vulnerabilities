import { LIVE_SOURCE, REPORT_FILES } from "./constants.js";
import { buildRepositoryModel, compareTextAsc, compareTextDesc } from "./transform.js";

export async function loadReports() {
  const results = await Promise.allSettled(REPORT_FILES.map(loadPreferredReport));

  const repositories = [];
  const warnings = [];
  let liveCount = 0;
  let staticCount = 0;

  for (const result of results) {
    if (result.status === "fulfilled") {
      repositories.push(result.value.repository);

      if (result.value.source === "live") {
        liveCount += 1;
      } else {
        staticCount += 1;
      }

      continue;
    }

    warnings.push(result.reason instanceof Error ? result.reason.message : "Unexpected load failure");
  }

  return {
    repositories,
    warnings,
    sourceMessage: buildSourceMessage(liveCount, staticCount, repositories.length)
  };
}

function buildSourceMessage(liveCount, staticCount, totalLoaded) {
  if (totalLoaded === 0) {
    return "Could not load dependency reports.";
  }

  if (liveCount === totalLoaded) {
    return "Loaded latest reports from GitHub Actions artifacts.";
  }

  if (liveCount > 0 && staticCount > 0) {
    return `Loaded ${liveCount}/${totalLoaded} reports from GitHub Actions and ${staticCount} from local static files.`;
  }

  return "Loaded reports from local static files.";
}

async function loadPreferredReport(file) {
  const liveErrorMessages = [];

  if (!window.JSZip) {
    const repository = await loadStaticReport(file);
    return {
      source: "static",
      repository
    };
  }

  try {
    const report = await fetchLatestArtifactReport(file.name);
    return {
      source: "live",
      repository: buildRepositoryModel(file, report)
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "live fetch failed";
    liveErrorMessages.push(message);
    console.warn(`[live-fetch] ${file.name}: ${message}`);
  }

  try {
    const repository = await loadStaticReport(file);
    return {
      source: "static",
      repository
    };
  } catch (staticError) {
    const staticMessage = staticError instanceof Error ? staticError.message : "static file load failed";
    throw new Error(
      `Failed to load ${file.name}. Live errors: ${liveErrorMessages.join(" | ") || "none"}. Static error: ${staticMessage}`
    );
  }
}

async function loadStaticReport(file) {
  const response = await fetch(file.path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Could not load ${file.name} (${response.status})`);
  }

  const report = await response.json();
  return buildRepositoryModel(file, report);
}

async function fetchLatestArtifactReport(repoName) {
  const headers = buildGitHubHeaders();
  const branchErrors = [];

  for (const branch of LIVE_SOURCE.branchCandidates) {
    try {
      const runs = await fetchWorkflowRuns(repoName, branch, headers);
      const report = await findDependencyReportInRuns(repoName, runs, headers);

      if (report) {
        return report;
      }
    } catch (error) {
      branchErrors.push(error instanceof Error ? error.message : `Unknown error on ${branch}`);
    }
  }

  throw new Error(
    `No dependency report artifact found for ${repoName} on ${LIVE_SOURCE.branchCandidates.join("/")}. ${branchErrors.join(" | ")}`
  );
}

async function fetchWorkflowRuns(repoName, branch, headers) {
  const url = new URL(
    `https://api.github.com/repos/${LIVE_SOURCE.owner}/${repoName}/actions/runs`
  );
  url.searchParams.set("branch", branch);
  url.searchParams.set("status", "success");
  url.searchParams.set("per_page", "30");

  const response = await fetch(url, { headers });
  await assertGitHubResponse(response, `workflow runs (${repoName}, ${branch})`);

  const payload = await response.json();
  return Array.isArray(payload?.workflow_runs) ? payload.workflow_runs : [];
}

async function findDependencyReportInRuns(repoName, runs, headers) {
  for (const run of runs) {
    const artifacts = await fetchRunArtifacts(repoName, run.id, headers);

    const candidates = artifacts
      .filter((artifact) => !artifact?.expired && LIVE_SOURCE.artifactPattern.test(artifact?.name || ""))
      .sort((a, b) => compareTextDesc(a?.created_at, b?.created_at));

    for (const artifact of candidates) {
      const parsed = await downloadArtifactReport(repoName, artifact.id, headers);
      if (parsed) {
        return parsed;
      }
    }
  }

  return null;
}

async function fetchRunArtifacts(repoName, runId, headers) {
  const url = new URL(
    `https://api.github.com/repos/${LIVE_SOURCE.owner}/${repoName}/actions/runs/${runId}/artifacts`
  );
  url.searchParams.set("per_page", "100");

  const response = await fetch(url, { headers });
  await assertGitHubResponse(response, `artifacts for run ${runId} (${repoName})`);

  const payload = await response.json();
  return Array.isArray(payload?.artifacts) ? payload.artifacts : [];
}

async function downloadArtifactReport(repoName, artifactId, headers) {
  const url = `https://api.github.com/repos/${LIVE_SOURCE.owner}/${repoName}/actions/artifacts/${artifactId}/zip`;

  const response = await fetch(url, { headers });
  await assertGitHubResponse(response, `artifact ${artifactId} download (${repoName})`);

  const zipBlob = await response.blob();
  const zip = await window.JSZip.loadAsync(zipBlob);

  const entries = Object.values(zip.files)
    .filter((entry) => !entry.dir && entry.name.toLowerCase().endsWith(".json"))
    .sort((a, b) => compareTextAsc(a.name, b.name));

  for (const entry of entries) {
    try {
      const text = await entry.async("string");
      const parsed = JSON.parse(text);

      if (Array.isArray(parsed?.vulnerabilities)) {
        return parsed;
      }
    } catch {
      continue;
    }
  }

  return null;
}

async function assertGitHubResponse(response, context) {
  if (response.ok) {
    return;
  }

  if (response.status === 403) {
    throw new Error(`GitHub API rate limited while fetching ${context} (403)`);
  }

  if (response.status === 404) {
    throw new Error(`GitHub endpoint unavailable for ${context} (404)`);
  }

  throw new Error(`GitHub request failed for ${context} (${response.status})`);
}

function buildGitHubHeaders() {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  };

  const token = getGitHubToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

function getGitHubToken() {
  if (typeof window === "undefined") {
    return "";
  }

  if (typeof window.OPENMRS_GITHUB_TOKEN === "string") {
    return window.OPENMRS_GITHUB_TOKEN.trim();
  }

  return "";
}
