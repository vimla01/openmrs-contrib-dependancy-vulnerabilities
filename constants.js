export const REPORT_FILES = [
  {
    key: "openmrs-core",
    name: "openmrs-core",
    path: "./data/openmrs-core.json"
  },
  {
    key: "openmrs-module-billing",
    name: "openmrs-module-billing",
    path: "./data/openmrs-module-billing.json"
  },
  {
    key: "openmrs-module-idgen",
    name: "openmrs-module-idgen",
    path: "./data/openmrs-module-idgen.json"
  }
];

export const LIVE_SOURCE = {
  owner: "openmrs",
  branchCandidates: ["main", "master"],
  artifactPattern: /(dependency[- ]?report|dependency|vulner|owasp|security)/i
};

export const SEVERITY_RANK = {
  Unknown: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4
};

export const VERSION_COLLATOR = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: "base"
});
