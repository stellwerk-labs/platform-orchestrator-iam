import http from "k6/http";
import { check } from "k6";
import exec from "k6/execution";

export const options = {
  vus: Number(__ENV.VUS || 1),
  duration: __ENV.DURATION || "10s",
  summaryTrendStats: ["avg", "p(95)", "p(99)", "max"],
  thresholds: {
    checks: ["rate==1"],
    http_req_failed: ["rate==0"],
  },
};

const target = __ENV.TARGET || "http://platform-orchestrator-iam-platform-orchestrator-iam:8080";
const params = { headers: { "Content-Type": "application/json" } };
const dataset = __ENV.DATASET || "hot";
const developerCount = Number(__ENV.DEVELOPER_COUNT || 5000);
const developersPerOrg = Number(__ENV.DEVELOPERS_PER_ORG || 50);
const projectsPerDeveloper = Number(__ENV.PROJECTS_PER_DEVELOPER || 5);
const checksPerRequest = Number(__ENV.CHECKS_PER_REQUEST || 1);
const expectedStatus = Number(__ENV.EXPECTED_STATUS || (dataset === "denied-projects" ? 403 : 204));

http.setResponseCallback(http.expectedStatuses(expectedStatus));

function padded(value, width) {
  return String(value).padStart(width, "0");
}

function requestBody() {
  if (dataset === "hot") {
    return JSON.stringify({
      user_id: __ENV.USER_ID,
      checks: Array.from({ length: checksPerRequest }, () => ({
        resource: __ENV.RESOURCE,
        permission: __ENV.PERMISSION || "read",
      })),
    });
  }

  const iteration = exec.scenario.iterationInTest;
  const developer = (iteration % developerCount) + 1;
  const org = Math.floor((developer - 1) / developersPerOrg) + 1;
  const targetDeveloper = dataset === "denied-projects"
    ? ((developer - 1 + developersPerOrg) % developerCount) + 1
    : developer;
  const checks = Array.from({ length: checksPerRequest }, (_, offset) => {
    const project = ((Math.floor(iteration / developerCount) + offset) % projectsPerDeveloper) + 1;
    const resource = dataset === "organizations"
      ? `organization:authorization-benchmark-org-${padded(org, 4)}`
      : `project:authorization-benchmark-project-${padded(targetDeveloper, 6)}-${project}`;
    return { resource, permission: __ENV.PERMISSION || "read" };
  });

  return JSON.stringify({
    user_id: `10000000-0000-4000-8000-${padded(developer, 12)}`,
    checks,
  });
}

export default function () {
  const response = http.post(`${target}/internal/authorize`, requestBody(), params);
  check(response, { "expected authorization result": (result) => result.status === expectedStatus });
}
