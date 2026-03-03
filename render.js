import {
  formatScore,
  severityClass,
  sortCves,
  sortDependencies,
  sortRepositories
} from "./transform.js";

export function renderLoadingState(repoContainer, templateId = "loadingTemplate") {
  const loading = document.getElementById(templateId).content.cloneNode(true);
  repoContainer.replaceChildren(loading);
}

export function renderStatusBanner(statusBanner, sourceMessage, warningMessages) {
  statusBanner.classList.remove("error");

  if (!warningMessages || warningMessages.length === 0) {
    statusBanner.textContent = sourceMessage;
    return;
  }

  statusBanner.classList.add("error");
  statusBanner.textContent = `${sourceMessage} ${warningMessages.join(" | ")}`;
}

export function renderRepositories({
  repoContainer,
  repositories,
  expandedRepos,
  expandedDependencies,
  emptyTemplateId = "emptyTemplate"
}) {
  if (!repositories || repositories.length === 0) {
    const empty = document.getElementById(emptyTemplateId).content.cloneNode(true);
    repoContainer.replaceChildren(empty);
    return;
  }

  repoContainer.innerHTML = sortRepositories(repositories)
    .map((repo) => renderRepository(repo, expandedRepos, expandedDependencies))
    .join("");
}

function renderRepository(repo, expandedRepos, expandedDependencies) {
  const expanded = expandedRepos.has(repo.key);
  const dependencies = sortDependencies(repo.dependencies);

  return `
    <article class="repo-section">
      <button
        class="repo-head"
        data-action="toggle-repo"
        data-repo-key="${escapeHtml(repo.key)}"
        aria-expanded="${expanded ? "true" : "false"}"
      >
        <div class="repo-title-wrap">
          <h2 class="repo-title">${escapeHtml(repo.name)}</h2>
          <span class="pill ${severityClass(repo.severity)}">${escapeHtml(repo.severity)}</span>
        </div>
        ${chevronSvg(expanded, "repo-chevron")}
      </button>
      ${expanded ? renderRepositoryTable(repo, dependencies, expandedDependencies) : ""}
    </article>
  `;
}

function renderRepositoryTable(repo, dependencies, expandedDependencies) {
  if (dependencies.length === 0) {
    return `
      <div class="repo-table-wrap">
        <article class="status-card">No vulnerable dependencies in this repository.</article>
      </div>
    `;
  }

  return `
    <div class="repo-table-wrap">
      <table class="dep-table">
        <thead>
          <tr>
            <th>Dependency</th>
            <th>Version</th>
            <th>
              <span class="dep-severity-head">
                <span>Severity</span>
                <span aria-hidden="true">&#8593;</span>
              </span>
            </th>
            <th>CVEs</th>
            <th>Exploit?</th>
            <th>Fix Version</th>
          </tr>
        </thead>
        <tbody>
          ${dependencies.map((dependency) => renderDependencyRows(repo, dependency, expandedDependencies)).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderDependencyRows(repo, dependency, expandedDependencies) {
  const dependencyKey = `${repo.key}::${dependency.key}`;
  const expanded = expandedDependencies.has(dependencyKey);

  const mainRow = `
    <tr>
      <td>
        <button
          class="dep-toggle"
          data-action="toggle-dependency"
          data-dependency-key="${escapeHtml(dependencyKey)}"
          aria-expanded="${expanded ? "true" : "false"}"
        >
          ${chevronSvg(expanded, "caret")}
          <span class="dep-name">${escapeHtml(dependency.name)}</span>
        </button>
      </td>
      <td>${escapeHtml(dependency.version || "-")}</td>
      <td><span class="pill dep-inline-pill ${severityClass(dependency.severity)}">${escapeHtml(dependency.severity)}</span></td>
      <td>${escapeHtml(String(dependency.cveCount))}</td>
      <td>${escapeHtml(dependency.exploit)}</td>
      <td>${escapeHtml(dependency.fixVersion || "-")}</td>
    </tr>
  `;

  if (!expanded) {
    return mainRow;
  }

  return `${mainRow}${renderNestedCves(dependency.cves)}`;
}

function renderNestedCves(cves) {
  const sortedCves = sortCves(cves);

  return `
    <tr class="nested-row">
      <td colspan="6">
        <table class="cve-table">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Severity</th>
              <th>Score</th>
              <th>Description</th>
              <th>Affected Versions</th>
              <th>Fixed In</th>
              <th>CWE</th>
            </tr>
          </thead>
          <tbody>
            ${sortedCves.map((cve) => renderCveRow(cve)).join("")}
          </tbody>
        </table>
      </td>
    </tr>
  `;
}

function renderCveRow(cve) {
  const primaryLink = cve.links[0]?.url;
  const idCell = primaryLink
    ? `<a class="cve-link" href="${escapeHtml(primaryLink)}" target="_blank" rel="noopener noreferrer">${escapeHtml(cve.id)}</a>`
    : `<span>${escapeHtml(cve.id)}</span>`;

  return `
    <tr>
      <td>${idCell}</td>
      <td><span class="pill ${severityClass(cve.severity)}">${escapeHtml(cve.severity)}</span></td>
      <td class="cve-score">${formatScore(cve.score)}</td>
      <td class="cve-desc">${escapeHtml(cve.description || "-")}</td>
      <td>${escapeHtml(cve.affectedVersions || "-")}</td>
      <td>${escapeHtml(cve.fixedIn || "-")}</td>
      <td>${escapeHtml(cve.cwe || "-")}</td>
    </tr>
  `;
}

function chevronSvg(expanded, className) {
  const path = expanded
    ? "M2.5 7.5L6 4l3.5 3.5"
    : "M2.5 4.5L6 8l3.5-3.5";

  return `
    <svg class="${className}" viewBox="0 0 12 12" aria-hidden="true" focusable="false">
      <path d="${path}" />
    </svg>
  `;
}

function escapeHtml(value) {
  const text = String(value);

  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
