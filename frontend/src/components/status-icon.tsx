import { CheckCircle, Loader2, MinusCircle, XCircle, Clock } from "lucide-react";
import type { Scan } from "@/lib/api";

type Status = Scan["status"];

const STATUS_LABEL: Record<Status, string> = {
  pending: "Pending",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

interface StatusIconProps {
  status: Status;
  size?: number;
  withLabel?: boolean;
  className?: string;
}

export function StatusIcon({ status, size = 14, withLabel = false, className }: StatusIconProps) {
  const label = STATUS_LABEL[status] ?? status;

  let icon;
  let tone: string;
  switch (status) {
    case "completed":
      icon = <CheckCircle size={size} className="text-accent" aria-hidden="true" />;
      tone = "text-accent";
      break;
    case "running":
      icon = <Loader2 size={size} className="text-accent animate-spin motion-reduce:animate-none" aria-hidden="true" />;
      tone = "text-accent";
      break;
    case "failed":
      icon = <XCircle size={size} className="text-sev-critical" aria-hidden="true" />;
      tone = "text-sev-critical";
      break;
    case "cancelled":
      icon = <MinusCircle size={size} className="text-muted" aria-hidden="true" />;
      tone = "text-muted";
      break;
    case "pending":
    default:
      icon = <Clock size={size} className="text-muted" aria-hidden="true" />;
      tone = "text-muted";
      break;
  }

  if (!withLabel) {
    return (
      <span className={className} title={label} aria-label={label}>
        {icon}
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1.5 ${tone} ${className ?? ""}`}>
      {icon}
      <span className="text-xs">{label}</span>
    </span>
  );
}

export { STATUS_LABEL };
