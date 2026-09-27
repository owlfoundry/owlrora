import { expect, it } from "vitest";

import { catalogChoices, validateRouteTargets } from "./catalog-editor";

it("keeps discoverability separate from grants and includes organization-owned resources", () => {
  const choices = catalogChoices([
    { id: "own", name: "Own" },
    { deployment: { id: "system", name: "System" }, granted: false },
    { endpoint: { id: "endpoint", name: "Endpoint" }, granted: true },
  ]);
  expect(choices.map(({ id, granted }) => [id, granted])).toEqual([
    ["own", true],
    ["system", false],
    ["endpoint", true],
  ]);
});

it("validates complete route target tiers without rewriting stable identities", () => {
  const targets = [
    { id: "stable-1", deployment_id: "a", priority: 0, weight: 128 },
    { id: "stable-2", deployment_id: "b", priority: 0, weight: 128 },
  ];
  expect(() => validateRouteTargets(targets)).not.toThrow();
  expect(targets[0].id).toBe("stable-1");
  expect(() =>
    validateRouteTargets([...targets, { deployment_id: "c", priority: 0, weight: 1 }]),
  ).toThrow("256");
  expect(() => validateRouteTargets([targets[0], targets[0]])).toThrow("only once");
  expect(() => validateRouteTargets([{ deployment_id: "", priority: 0, weight: 1 }])).toThrow(
    "Select a deployment",
  );
  expect(() => validateRouteTargets([{ deployment_id: "a", priority: -1, weight: 1 }])).toThrow(
    "Priorities",
  );
});
