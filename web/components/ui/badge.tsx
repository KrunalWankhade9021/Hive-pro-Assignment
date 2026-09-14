import { cn } from "@/lib/utils";

/** A thin, neutral outline chip — dense and quiet, no filled background.
 *  Used for scoring-factor chips. Severity is handled separately (left spine
 *  + outline pill), so this stays deliberately monochrome. */
export function Chip({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border border-line px-2 py-0.5 text-[11px] font-medium text-muted",
        className,
      )}
      {...props}
    />
  );
}
