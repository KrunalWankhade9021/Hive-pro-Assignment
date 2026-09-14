import { cn } from "@/lib/utils";

/** A flat dossier card: white surface, hairline border, no drop shadow. */
export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("rounded-md border border-line bg-card", className)}
      {...props}
    />
  );
}
