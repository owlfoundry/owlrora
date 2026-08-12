import {
  type FormEvent,
  type MouseEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";

import {
  ApiError,
  apiRequest,
  createIdempotencyKey,
  type ApiResponse,
  type JsonValue,
} from "./api";

export const NAVIGATION_EVENT = "owlrora:navigate";
export const BEFORE_NAVIGATION_EVENT = "owlrora:before-navigate";

export function requestNavigation(path: string): boolean {
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new Error("Console navigation must remain same-origin");
  }
  return window.dispatchEvent(
    new CustomEvent(BEFORE_NAVIGATION_EVENT, {
      cancelable: true,
      detail: { path },
    }),
  );
}

export function navigate(path: string, replace = false, bypassGuard = false): void {
  if (!bypassGuard && !requestNavigation(path)) return;
  if (replace) {
    window.history.replaceState(null, "", path);
  } else {
    window.history.pushState(null, "", path);
  }
  window.dispatchEvent(new Event(NAVIGATION_EVENT));
  window.scrollTo({ top: 0, behavior: "instant" });
}

export function Link({
  href,
  children,
  className,
  ariaCurrent,
}: {
  href: string;
  children: ReactNode;
  className?: string;
  ariaCurrent?: "page";
}) {
  function follow(event: MouseEvent<HTMLAnchorElement>): void {
    if (
      event.button === 0 &&
      !event.metaKey &&
      !event.ctrlKey &&
      !event.shiftKey &&
      !event.altKey
    ) {
      event.preventDefault();
      navigate(href);
    }
  }
  return (
    <a href={href} onClick={follow} className={className} aria-current={ariaCurrent}>
      {children}
    </a>
  );
}

export interface ResourceState<T> {
  loading: boolean;
  value: T | null;
  etag: string | null;
  error: ApiError | null;
  reload: () => void;
  replace: (response: ApiResponse<T>) => void;
}

export function useIdempotencyKey(): (candidate: unknown) => string {
  const current = useRef<{ fingerprint: string; key: string } | null>(null);
  return useCallback((candidate: unknown) => {
    const fingerprint = JSON.stringify(candidate);
    if (current.current === null || current.current.fingerprint !== fingerprint) {
      current.current = { fingerprint, key: createIdempotencyKey() };
    }
    return current.current.key;
  }, []);
}

export function useApiResource<T>(path: string): ResourceState<T> {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<{
    loading: boolean;
    value: T | null;
    etag: string | null;
    error: ApiError | null;
  }>({ loading: true, value: null, etag: null, error: null });

  useEffect(() => {
    const controller = new AbortController();
    void apiRequest<T>(path, { signal: controller.signal })
      .then((response) => {
        setState({
          loading: false,
          value: response.value,
          etag: response.etag,
          error: null,
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setState({
          loading: false,
          value: null,
          etag: null,
          error:
            error instanceof ApiError
              ? error
              : new ApiError(0, "network_error", "The server could not be reached."),
        });
      });
    return () => controller.abort();
  }, [path, revision]);

  const reload = useCallback(() => {
    setState({ loading: true, value: null, etag: null, error: null });
    setRevision((value) => value + 1);
  }, []);
  const replace = useCallback((response: ApiResponse<T>) => {
    setState({
      loading: false,
      value: response.value,
      etag: response.etag,
      error: null,
    });
  }, []);
  return { ...state, reload, replace };
}

export function useUnsavedChanges(active: boolean): () => void {
  const activeRef = useRef(active);
  useLayoutEffect(() => {
    activeRef.current = active;
  }, [active]);
  useEffect(() => {
    const confirmLeave = (event: Event) => {
      if (!activeRef.current || window.confirm("Discard the unsaved changes on this page?")) return;
      event.preventDefault();
    };
    const confirmUnload = (event: BeforeUnloadEvent) => {
      if (!activeRef.current) return;
      event.preventDefault();
      event.returnValue = true;
    };
    window.addEventListener(BEFORE_NAVIGATION_EVENT, confirmLeave);
    window.addEventListener("beforeunload", confirmUnload);
    return () => {
      window.removeEventListener(BEFORE_NAVIGATION_EVENT, confirmLeave);
      window.removeEventListener("beforeunload", confirmUnload);
    };
  }, []);
  return useCallback(() => {
    activeRef.current = false;
  }, []);
}

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  eyebrow?: string;
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow === undefined ? null : <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description === undefined ? null : <p className="page-description">{description}</p>}
      </div>
      {actions === undefined ? null : <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Panel({
  title,
  description,
  children,
  className = "",
}: {
  title?: string;
  description?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`.trim()}>
      {title === undefined ? null : <h2>{title}</h2>}
      {description === undefined ? null : <p className="panel-description">{description}</p>}
      {children}
    </section>
  );
}

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="state-card" role="status" aria-live="polite">
      <span className="loading-mark" aria-hidden="true" />
      <strong>{label}</strong>
      <span>Please wait for the authoritative server response.</span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="state-card empty-state">
      <strong>{title}</strong>
      <span>{description}</span>
      {action}
    </div>
  );
}

export function ApiErrorState({
  error,
  retry,
  compact = false,
}: {
  error: ApiError;
  retry?: () => void;
  compact?: boolean;
}) {
  const title =
    error.status === 403
      ? "This operation is not permitted"
      : error.status === 404
        ? "The resource was not found"
        : error.status === 401
          ? "Your session is no longer active"
          : "The request could not be completed";
  return (
    <div className={`alert alert-danger${compact ? " alert-compact" : ""}`} role="alert">
      <strong>{title}</strong>
      <span>{error.message}</span>
      {error.requestId === null ? null : (
        <span className="technical">Request {error.requestId}</span>
      )}
      {retry === undefined ? null : (
        <button className="button button-secondary" type="button" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Status({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone = ["active", "ready", "healthy", "accepted", "current"].includes(normalized)
    ? "success"
    : ["disabled", "suspended", "revoked", "failed", "rejected", "unavailable"].includes(normalized)
      ? "danger"
      : ["degraded", "pending", "unknown", "not_configured"].includes(normalized)
        ? "warning"
        : "neutral";
  return (
    <span className={`status status-${tone}`}>
      <span className="status-dot" aria-hidden="true" />
      {humanize(value)}
    </span>
  );
}

export function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function Id({ children }: { children: string }) {
  return <code className="resource-id">{children}</code>;
}

export function DefinitionList({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="definition-list">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function JsonBlock({
  value,
  label = "Structured value",
}: {
  value: JsonValue;
  label?: string;
}) {
  return (
    <pre className="json-block" aria-label={label}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Table({
  columns,
  rows,
  getKey,
}: {
  columns: Array<{ key: string; label: string; className?: string }>;
  rows: Array<Record<string, ReactNode>>;
  getKey: (row: Record<string, ReactNode>, index: number) => string;
}) {
  return (
    <div className="table-region" tabIndex={0}>
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} scope="col" className={column.className}>
                {column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={getKey(row, index)}>
              {columns.map((column) => (
                <td key={column.key} data-label={column.label} className={column.className}>
                  {row[column.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Pagination({
  canContinue,
  onContinue,
  label = "Load next page",
}: {
  canContinue: boolean;
  onContinue: () => void;
  label?: string;
}) {
  if (!canContinue) {
    return null;
  }
  return (
    <div className="pagination">
      <button className="button button-secondary" type="button" onClick={onContinue}>
        {label}
      </button>
    </div>
  );
}

export function Field({
  label,
  children,
  help,
  required = false,
}: {
  label: string;
  children: ReactNode;
  help?: string;
  required?: boolean;
}) {
  return (
    <label className="field">
      <span className="field-label">
        {label}
        {required ? <span aria-hidden="true"> *</span> : null}
      </span>
      <span className="field-control">{children}</span>
      {help === undefined ? null : <span className="field-help">{help}</span>}
    </label>
  );
}

export function FormError({ message }: { message: string | null }) {
  if (message === null) {
    return null;
  }
  return (
    <div className="alert alert-danger" role="alert">
      <strong>Review the form</strong>
      <span>{message}</span>
    </div>
  );
}

export function SubmitBar({
  submitting,
  submitLabel,
  cancelHref,
  danger = false,
}: {
  submitting: boolean;
  submitLabel: string;
  cancelHref: string;
  danger?: boolean;
}) {
  return (
    <div className="submit-bar">
      <button
        type="submit"
        className={`button ${danger ? "button-danger" : "button-primary"}`}
        disabled={submitting}
      >
        {submitting ? "Working…" : submitLabel}
      </button>
      <Link href={cancelHref} className="button button-secondary">
        Cancel
      </Link>
    </div>
  );
}

export function ConflictState({ candidate, reload }: { candidate: JsonValue; reload: () => void }) {
  return (
    <div className="conflict-view" role="alert">
      <div className="alert alert-warning">
        <strong>This resource changed while you were editing</strong>
        <span>
          OwlRora did not merge or replay the change. Copy any values you need, then load the
          current representation and deliberately reapply them.
        </span>
      </div>
      <h3>Your unsaved candidate</h3>
      <JsonBlock value={candidate} label="Unsaved candidate" />
      <button className="button button-primary" type="button" onClick={reload}>
        Load current representation
      </button>
    </div>
  );
}

export function OutcomeUnknownState({
  command,
  requestId,
  recoveryHref,
  committed = false,
}: {
  command: string;
  requestId: string;
  recoveryHref: string;
  committed?: boolean;
}) {
  return (
    <div className="conflict-view" role="alert">
      <div className="alert alert-warning">
        <strong>
          {committed ? "Command committed; response unavailable" : "Command outcome is unknown"}
        </strong>
        <span>
          {committed
            ? `OwlRora committed ${command}, but the one-time response could not be read.`
            : `The connection ended before OwlRora confirmed whether ${command} committed.`}{" "}
          Do not submit the same one-time command again: it could create usable material that was
          never disclosed.
        </span>
        <span className="technical">Request {requestId}</span>
      </div>
      <Panel
        title="Recover deliberately"
        description="Open the safe metadata view, identify any newly created or rotated candidate, disable or revoke potentially undisclosed material, then issue fresh material in a separate deliberate command."
      >
        <Link className="button button-primary" href={recoveryHref}>
          Inspect safe metadata
        </Link>
      </Panel>
    </div>
  );
}

export function OneTimeReveal({
  credentialClass,
  secret,
  metadata,
  doneHref,
  onDone,
}: {
  credentialClass: string;
  secret: string;
  metadata: ReactNode;
  doneHref: string;
  onDone?: () => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);
  const [navigationBlocked, setNavigationBlocked] = useState(false);
  const acknowledgedRef = useRef(false);
  useEffect(() => {
    acknowledgedRef.current = acknowledged;
  }, [acknowledged]);
  useEffect(() => {
    const blockNavigation = (event: Event) => {
      if (acknowledgedRef.current) return;
      event.preventDefault();
      setNavigationBlocked(true);
    };
    const blockUnload = (event: BeforeUnloadEvent) => {
      if (acknowledgedRef.current) return;
      event.preventDefault();
      event.returnValue = true;
    };
    window.addEventListener(BEFORE_NAVIGATION_EVENT, blockNavigation);
    window.addEventListener("beforeunload", blockUnload);
    return () => {
      window.removeEventListener(BEFORE_NAVIGATION_EVENT, blockNavigation);
      window.removeEventListener("beforeunload", blockUnload);
    };
  }, []);
  async function copy(): Promise<void> {
    await navigator.clipboard.writeText(secret);
    setCopied(true);
  }
  return (
    <Panel className="secret-reveal" title={`${credentialClass} created`}>
      {navigationBlocked ? (
        <div className="alert alert-warning" role="status">
          <strong>Acknowledge before leaving</strong>
          <span>Save the one-time value, then confirm the acknowledgement below.</span>
        </div>
      ) : null}
      <div className="alert alert-warning">
        <strong>Will not be shown again</strong>
        <span>
          Copy this value now and place it in a protected client profile or environment variable. It
          is held only in this page's memory and is discarded when you leave.
        </span>
      </div>
      {metadata}
      <div className="secret-value">
        <code>{secret}</code>
        <button className="button button-secondary" type="button" onClick={() => void copy()}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <label className="check-row">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => {
            setAcknowledged(event.target.checked);
            if (event.target.checked) setNavigationBlocked(false);
          }}
        />
        <span>I saved this value in an approved secret store.</span>
      </label>
      <button
        className="button button-primary"
        type="button"
        disabled={!acknowledged}
        onClick={() => (onDone === undefined ? navigate(doneHref, true) : onDone())}
      >
        Finish
      </button>
    </Panel>
  );
}

export function ConfirmAction({
  title,
  consequence,
  label,
  onConfirm,
  danger = false,
}: {
  title: string;
  consequence: string;
  label: string;
  onConfirm: () => Promise<void>;
  danger?: boolean;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (!confirmed || working) {
      return;
    }
    setWorking(true);
    setError(null);
    try {
      await onConfirm();
      setConfirmed(false);
    } catch (caught: unknown) {
      setError(
        caught instanceof ApiError
          ? caught
          : new ApiError(0, "network_error", "The server could not be reached."),
      );
    } finally {
      setWorking(false);
    }
  }
  return (
    <form className="confirm-action" onSubmit={(event) => void submit(event)}>
      <h3>{title}</h3>
      <p>{consequence}</p>
      {error === null ? null : <ApiErrorState error={error} compact />}
      <label className="check-row">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(event) => setConfirmed(event.target.checked)}
        />
        <span>I understand the target and resulting authority or lifecycle change.</span>
      </label>
      <button
        className={`button ${danger ? "button-danger" : "button-primary"}`}
        type="submit"
        disabled={!confirmed || working}
      >
        {working ? "Working…" : label}
      </button>
    </form>
  );
}
