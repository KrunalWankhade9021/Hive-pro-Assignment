import { cn } from "@/lib/utils";

/** A raised panel: one step of elevation off the page ground, hairline edge, no
 *  drop shadow. Depth separates content; borders only where an edge is real. */
export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-lg border border-line bg-surface", className)} {...props} />;
}
