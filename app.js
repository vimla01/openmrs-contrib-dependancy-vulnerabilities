import { loadReports } from "./loader.js";
import { renderLoadingState, renderRepositories, renderStatusBanner } from "./render.js";
import { sortDependencies, sortRepositories } from "./transform.js";

const state = {
  repositories: [],
  expandedRepos: new Set(),
  expandedDependencies: new Set(),
  warningMessages: [],
  sourceMessage: ""
};

const repoContainer = document.getElementById("repoContainer");
const statusBanner = document.getElementById("statusBanner");

init();

async function init() {
  wireEvents();
  await loadAndRender();
}

function wireEvents() {
  repoContainer.addEventListener("click", (event) => {
    const actionTarget = event.target.closest("[data-action]");
    if (!actionTarget) {
      return;
    }

    const action = actionTarget.getAttribute("data-action");

    if (action === "toggle-repo") {
      event.preventDefault();
      const repoKey = actionTarget.getAttribute("data-repo-key");
      toggleSet(state.expandedRepos, repoKey);
      renderAll();
      return;
    }

    if (action === "toggle-dependency") {
      event.preventDefault();
      const dependencyKey = actionTarget.getAttribute("data-dependency-key");
      toggleSet(state.expandedDependencies, dependencyKey);
      renderAll();
    }
  });
}

async function loadAndRender() {
  renderLoadingState(repoContainer);

  const payload = await loadReports();

  state.repositories = sortRepositories(payload.repositories);
  state.warningMessages = payload.warnings;
  state.sourceMessage = payload.sourceMessage;

  seedInitialExpansion();
  renderAll();
}

function seedInitialExpansion() {
  state.expandedRepos.clear();
  state.expandedDependencies.clear();

  const firstRepo = state.repositories[0];
  if (!firstRepo) {
    return;
  }

  state.expandedRepos.add(firstRepo.key);

  const firstDependency = sortDependencies(firstRepo.dependencies)[0];
  if (!firstDependency) {
    return;
  }

  state.expandedDependencies.add(`${firstRepo.key}::${firstDependency.key}`);
}

function renderAll() {
  renderStatusBanner(statusBanner, state.sourceMessage, state.warningMessages);
  renderRepositories({
    repoContainer,
    repositories: state.repositories,
    expandedRepos: state.expandedRepos,
    expandedDependencies: state.expandedDependencies
  });
}

function toggleSet(setRef, key) {
  if (!key) {
    return;
  }

  if (setRef.has(key)) {
    setRef.delete(key);
  } else {
    setRef.add(key);
  }
}
