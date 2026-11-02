import { CircleCheck, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/** One titled group of settings. */
export function SettingsSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">{children}</CardContent>
    </Card>
  );
}

/** Explanatory small print under a control. */
export function Note({ children, tone = "muted" }: { children: ReactNode; tone?: "muted" | "warning" }) {
  return (
    <p className={cn("text-xs", tone === "warning" ? "text-orange-500" : "text-muted-foreground")}>{children}</p>
  );
}

/** The outcome of an action: a confirmation or an error. */
export function Outcome({ kind, children }: { kind: "ok" | "error"; children: ReactNode }) {
  const Icon = kind === "ok" ? CircleCheck : TriangleAlert;
  return (
    <p
      role={kind === "error" ? "alert" : "status"}
      className={cn("flex items-start gap-1.5 text-xs", kind === "ok" ? "text-green-600" : "text-destructive")}>
      <Icon className="mt-px size-3.5 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  );
}

/** A labelled row: the label on the left, the control on the right. */
export function SettingRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <span>{label}</span>
      <div className="flex items-center gap-2">{children}</div>
    </div>
  );
}
