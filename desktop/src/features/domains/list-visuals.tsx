import { AppWindow, Globe, Network, Send, ShieldCheck, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ListIcon, StateTone } from "./domain-lists";

const ICONS: Record<ListIcon, LucideIcon> = {
  globe: Globe,
  wireguard: ShieldCheck,
  outline: Send,
  network: Network,
  app: AppWindow,
};

const TONES: Record<StateTone, string> = {
  green: "bg-green-500",
  yellow: "bg-yellow-500",
  red: "bg-red-500",
  orange: "bg-orange-500",
  muted: "bg-muted-foreground/50",
};

export function ListIconView({ icon, className }: { icon: ListIcon; className?: string }) {
  const Icon = ICONS[icon];
  return <Icon aria-hidden className={cn("size-4 shrink-0 text-primary", className)} />;
}

/** A list's state: a coloured dot and its label. */
export function ListState({ tone, label, className }: { tone: StateTone; label: string; className?: string }) {
  if (label === "") return null;
  return (
    <span className={cn("flex min-w-0 items-center gap-1 text-muted-foreground", className)}>
      <span aria-hidden className={cn("size-1.5 shrink-0 rounded-full", TONES[tone])} />
      <span className="truncate">{label}</span>
    </span>
  );
}
