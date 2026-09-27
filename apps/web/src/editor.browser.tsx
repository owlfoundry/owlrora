// Browser-only regression harness: open /browser-tests.html on the Vite dev server.
// It is not an application entry point and never calls a real management API.
import { act, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { CatalogCommandForm } from "./catalog-editor";
import { SchemaCommandForm } from "./schema-form";
import { useApiResource } from "./ui";

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
const root = createRoot(document.getElementById("root")!);
const result = document.getElementById("result")!;
const passed: string[] = [];
function check(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}
async function render(node: ReactNode) {
  await act(async () => root.render(node));
}
function input(label: string): HTMLInputElement {
  const field = [...document.querySelectorAll("label")].find((item) =>
    item.textContent?.trim().startsWith(label),
  );
  const control = field?.querySelector("input");
  if (!control) throw new Error(`Missing input ${label}`);
  return control;
}
async function fill(control: HTMLInputElement, text: string) {
  if (control.disabled) {
    await act(async () =>
      control
        .closest(".schema-field")
        ?.querySelector<HTMLInputElement>('input[type="checkbox"]')
        ?.click(),
    );
  }
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(control, text);
    control.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function waitFor(predicate: () => boolean) {
  const deadline = performance.now() + 2000;
  while (!predicate()) {
    if (performance.now() >= deadline) throw new Error("Expected request did not start");
    await act(async () => new Promise((resolve) => setTimeout(resolve, 10)));
  }
}
async function submit() {
  await act(async () => {
    const confirmation = [
      ...document.querySelectorAll<HTMLInputElement>("input[type=checkbox]"),
    ].find((item) => item.parentElement?.textContent?.includes("I reviewed"));
    confirmation?.click();
  });
  await act(async () =>
    document
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })),
  );
}
function editor(id: string, etag: string, name: string) {
  return (
    <SchemaCommandForm
      operationId="system.pricing_policies.update"
      params={{ id }}
      etag={etag}
      initialValue={{ name, status: "active" }}
      cancelHref="/browser-tests.html"
      successHref="/browser-tests.html"
      submitLabel="Save"
    />
  );
}
function Resource({ path }: { path: string }) {
  const resource = useApiResource<{ name: string }>(path);
  return (
    <output>{resource.loading ? "loading" : `${resource.value?.name}:${resource.etag}`}</output>
  );
}
async function run() {
  let submitted: { path: string; tag: string | null; body: unknown } | null = null;
  window.fetch = async (path, options) => {
    submitted = {
      path: String(path),
      tag: new Headers(options?.headers).get("If-Match"),
      body: JSON.parse(String(options?.body)),
    };
    return new Response(JSON.stringify({ error: { code: "conflict", message: "Conflict" } }), {
      status: 412,
    });
  };
  await render(editor("a", '"a-1"', "Alpha"));
  await fill(input("Name"), "Alpha candidate");
  await render(editor("b", '"b-1"', "Beta"));
  check(input("Name").value === "Beta", "resource change retained another resource's candidate");
  await fill(input("Name"), "Beta candidate");
  await submit();
  await waitFor(() => submitted !== null);
  const sent = submitted as { path: string; tag: string | null; body: { name: string } } | null;
  check(
    sent?.path.includes("/b/") === true &&
      sent.tag === '"b-1"' &&
      sent.body.name === "Beta candidate",
    "candidate and source ETag separated",
  );
  await render(editor("b", '"b-2"', "Updated Beta"));
  check(
    input("Name").value === "Updated Beta",
    "new source ETag did not replace the editor session",
  );
  passed.push("resource and ETag transitions bind one editor session");

  const resolvers = new Map<string, (response: Response) => void>();
  window.fetch = (path) => new Promise<Response>((resolve) => resolvers.set(String(path), resolve));
  await render(<Resource path="/api/test/a" />);
  await render(<Resource path="/api/test/b" />);
  await act(async () =>
    resolvers.get("/api/test/a")!(new Response('{"name":"stale"}', { headers: { etag: '"old"' } })),
  );
  check(
    document.querySelector("output")?.textContent === "loading",
    "aborted response polluted the new resource",
  );
  await act(async () =>
    resolvers.get("/api/test/b")!(
      new Response('{"name":"current"}', { headers: { etag: '"new"' } }),
    ),
  );
  check(
    document.querySelector("output")?.textContent === 'current:"new"',
    "current representation lost its ETag",
  );
  passed.push("late previous-resource responses cannot publish stale evidence");

  for (const status of [400, 401, 403, 412]) {
    let finish: ((response: Response) => void) | undefined;
    window.fetch = () =>
      new Promise<Response>((resolve) => {
        finish = resolve;
      });
    await render(
      <SchemaCommandForm
        key={status}
        operationId="system.upstream_credentials.replace_secret"
        params={{ credential_id: "credential" }}
        etag='"credential-1"'
        cancelHref="/browser-tests.html"
        successHref="/browser-tests.html"
        submitLabel="Replace"
      />,
    );
    const secret = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    check(secret !== null, "write-only input is absent");
    await fill(secret, "test-only-secret-must-disappear");
    await submit();
    check(secret.value === "", "secret input retained plaintext while request was pending");
    await waitFor(() => finish !== undefined);
    await act(async () =>
      finish!(
        new Response(JSON.stringify({ error: { code: "rejected", message: "Rejected" } }), {
          status,
        }),
      ),
    );
    check(
      !document.body.innerHTML.includes("test-only-secret-must-disappear"),
      "error/conflict UI leaked secret input",
    );
    check(
      [...document.querySelectorAll<HTMLInputElement>('input[type="password"]')].every(
        (item) => item.value === "",
      ),
      "ordinary error repopulated secret input",
    );
  }
  passed.push("secret inputs clear before dispatch and stay cleared for 400/401/403/412");
  const keys: string[] = [];
  window.fetch = async (_path, options) => {
    keys.push(new Headers(options?.headers).get("Idempotency-Key")!);
    throw new TypeError("Simulated lost response after commit");
  };
  await render(
    <SchemaCommandForm
      key="retry"
      operationId="system.upstream_credentials.replace_secret"
      params={{ credential_id: "credential" }}
      cancelHref="/browser-tests.html"
      successHref="/browser-tests.html"
      submitLabel="Replace"
    />,
  );
  for (const [index, secret] of ["same-secret", "same-secret", "changed-secret"].entries()) {
    await fill(document.querySelector<HTMLInputElement>('input[type="password"]')!, secret);
    await submit();
    await waitFor(() => keys.length > index);
  }
  check(
    keys[0] === keys[1] && keys[1] !== keys[2],
    "re-entered secret lost its command identity or reused it for a different candidate",
  );
  passed.push("same-candidate secret retry preserves idempotency without retaining plaintext");
  submitted = null;
  window.fetch = async (path, options) => {
    if (options?.method === "POST") {
      submitted = {
        path: String(path),
        tag: new Headers(options.headers).get("If-Match"),
        body: JSON.parse(String(options.body)),
      };
      return new Response(
        JSON.stringify({ error: { code: "validation", message: "Graph rejected by server" } }),
        { status: 400 },
      );
    }
    const url = String(path);
    let items: unknown[] = [];
    let next_cursor: string | null = null;
    if (url.includes("available-deployments")) {
      items = [
        {
          deployment: {
            id: "system-denied",
            name: "Not granted",
            transport_kind: "openai_responses_http",
            capability_set: [],
          },
          granted: false,
        },
      ];
    } else if (url.includes("model-deployments")) {
      if (url.includes("cursor="))
        items = [
          {
            id: "second-page",
            name: "Second page",
            transport_kind: "openai_responses_http",
            capability_set: [],
          },
        ];
      else {
        items = [
          {
            id: "own",
            name: "Own deployment",
            transport_kind: "openai_responses_http",
            capability_set: [],
          },
        ];
        next_cursor = "next";
      }
    }
    return new Response(JSON.stringify({ items, next_cursor }));
  };
  await render(
    <CatalogCommandForm
      operationId="organization.model_routes.update"
      params={{ organization_id: "org", id: "route" }}
      etag='"route-1"'
      initialValue={{
        ingress_protocol_family: "openai_responses",
        required_base_capabilities: [],
        targets: [
          {
            id: "stable-target",
            deployment_id: "own",
            priority: 0,
            weight: 1,
            enabled: true,
            timeout_overrides: { body_timeout_ms: 2000 },
            narrowing_constraints: {},
          },
        ],
      }}
      cancelHref="/browser-tests.html"
      successHref="/browser-tests.html"
      submitLabel="Save route"
    />,
  );
  await waitFor(() => document.querySelector('option[value="system-denied"]') !== null);
  check(
    document.querySelector<HTMLOptionElement>('option[value="system-denied"]')!.disabled,
    "ungranted discovered deployment was selectable",
  );
  await act(async () =>
    input("Weight")
      .closest(".schema-field")!
      .querySelector<HTMLInputElement>('input[type="checkbox"]')!
      .click(),
  );
  await fill(input("Weight"), "2");
  await act(async () =>
    [...document.querySelectorAll("button")]
      .find((button) => button.textContent === "Load more choices")!
      .click(),
  );
  await waitFor(() => document.querySelector('option[value="second-page"]') !== null);
  await submit();
  await waitFor(() => submitted !== null);
  const routeSent = submitted as {
    tag: string;
    body: {
      targets: Array<{
        id: string;
        weight: number;
        timeout_overrides: { body_timeout_ms: number };
      }>;
    };
  } | null;
  check(
    routeSent?.tag === '"route-1"' &&
      routeSent.body.targets[0].id === "stable-target" &&
      routeSent.body.targets[0].weight === 2 &&
      routeSent.body.targets[0].timeout_overrides.body_timeout_ms === 2000,
    "route edit lost target identity, nested policy or source ETag",
  );
  check(
    document.body.textContent?.includes("Graph rejected by server") === true,
    "server graph validation was hidden",
  );
  passed.push(
    "route editor merges own/granted discovery, paginates, preserves target identity and surfaces server graph validation",
  );
  await act(async () => root.unmount());
  result.textContent = `PASS\n${passed.join("\n")}`;
}
void run().catch((error: unknown) => {
  result.textContent = `FAIL\n${error instanceof Error ? error.stack : String(error)}`;
});
