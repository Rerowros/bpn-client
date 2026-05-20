import { AlertTriangle, CheckCircle2, Globe2, Power, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import type { ConnectionProgressModel, ServerIdentity } from "../appTypes";

export function SetupStep({
  title,
  status,
  detail,
  action,
}: {
  title: string;
  status: "ready" | "pending" | "blocked";
  detail: string;
  action?: ReactNode;
}) {
  const icon =
    status === "ready" ? (
      <CheckCircle2 size={18} aria-hidden="true" />
    ) : status === "blocked" ? (
      <AlertTriangle size={18} aria-hidden="true" />
    ) : (
      <RefreshCw size={18} aria-hidden="true" />
    );

  return (
    <div className={`setupStep ${status}`}>
      <span className="setupStepIcon">{icon}</span>
      <div>
        <strong>{title}</strong>
        <span>{detail}</span>
      </div>
      {action ? <div className="setupStepAction">{action}</div> : null}
    </div>
  );
}

export function ConnectionProgressView({ progress }: { progress: ConnectionProgressModel | null }) {
  if (!progress) {
    return null;
  }

  return (
    <div className="connectionProgress" aria-live="polite">
      <span>{progress.label}</span>
      <div className="progressSteps">
        {progress.steps.map((step) => (
          <span key={step.label} className={`progressStep ${step.state}`}>
            {step.state === "done" ? <CheckCircle2 size={12} aria-hidden="true" /> : null}
            {step.state === "active" ? <RefreshCw size={12} aria-hidden="true" /> : null}
            {step.label}
          </span>
        ))}
      </div>
    </div>
  );
}

export function RailButton({
  active,
  title,
  onClick,
  children,
}: {
  active: boolean;
  title: string;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button className={active ? "railItem active" : "railItem"} type="button" title={title} aria-label={title} onClick={onClick}>
      {children}
      <span>{title}</span>
    </button>
  );
}

export function IdentityBadge({
  identity,
  className,
  size,
  fallback,
}: {
  identity: ServerIdentity;
  className: string;
  size: number;
  fallback?: ReactNode;
}) {
  if (identity.countryCode) {
    return <span className={`${className} countryFlag flag-${identity.countryCode.toLowerCase()}`} aria-label={`${identity.countryCode} flag`} />;
  }
  return <span className={identity.flag ? `${className} hasFlag` : className}>{identity.flag ?? fallback ?? <Globe2 size={size} aria-hidden="true" />}</span>;
}

export function LegendItem({ tone, title, text }: { tone: string; title: string; text: string }) {
  return (
    <div className="legendItem">
      <PathBadge path={tone} label={title} />
      <span>{text}</span>
    </div>
  );
}

export function EmptyList({ icon, title, text }: { icon: ReactNode; title: string; text: string }) {
  return (
    <div className="emptyList">
      {icon}
      <strong>{title}</strong>
      <span>{text}</span>
    </div>
  );
}

export function StatusBadge({ connected, pending, status }: { connected: boolean; pending: boolean; status: string }) {
  return (
    <div className={connected ? "statusBadge connected" : pending ? "statusBadge pending" : "statusBadge"}>
      {connected ? <CheckCircle2 size={15} aria-hidden="true" /> : pending ? <RefreshCw size={15} aria-hidden="true" /> : <Power size={15} aria-hidden="true" />}
      <span>{status}</span>
    </div>
  );
}

export function PathBadge({ path, label }: { path: string; label: string }) {
  return <span className={`pathBadge ${path}`}>{label}</span>;
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="metric">
      <span>{icon}{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function StatusRow({ label, value, good }: { label: string; value: string; good?: boolean }) {
  return (
    <div className="statusRow">
      <span>{label}</span>
      <strong className={good ? "good" : undefined}>{value}</strong>
    </div>
  );
}

export function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="detailItem">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
