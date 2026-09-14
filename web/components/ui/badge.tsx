import { cn } from "@/lib/utils";

type Intent = "neutral" | "danger" | "warning" | "info" | "success";

const INTENT: Record<Intent, string> = {
  neutral: "bg-slate-100 text-slate-700 border-slate-200",
  danger: "bg-red-50 text-red-700 border-red-200",
  warning: "bg-amber-50 text-amber-700 border-amber-200",
  info: "bg-sky-50 text-sky-700 border-sky-200",
  success: "bg-emerald-50 text-emerald-700 border-emerald-200",
};

export function Badge({
  intent = "neutral",
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { intent?: Intent }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium",
        INTENT[intent],
        className,
      )}
      {...props}
    />
  );
}
