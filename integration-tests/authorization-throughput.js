import http from "k6/http";
import { check } from "k6";

export const options = {
  vus: Number(__ENV.VUS || 1),
  duration: __ENV.DURATION || "10s",
  summaryTrendStats: ["avg", "p(95)"],
};

const target = __ENV.TARGET || "http://platform-orchestrator-iam-platform-orchestrator-iam:8080";
const body = JSON.stringify({
  user_id: __ENV.USER_ID,
  checks: [{ resource: __ENV.RESOURCE, permission: __ENV.PERMISSION || "read" }],
});
const params = { headers: { "Content-Type": "application/json" } };

export default function () {
  const response = http.post(`${target}/internal/authorize`, body, params);
  check(response, { "authorized": (result) => result.status === 204 });
}
