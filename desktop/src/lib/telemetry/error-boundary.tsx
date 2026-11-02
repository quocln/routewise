"use client";

import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { reportUiError } from "./report-ui";

interface Props {
  children: ReactNode;
}

interface State {
  failed: boolean;
}

/**
 * Catches errors thrown while rendering, reports them to the Rust core and
 * shows a way back instead of a blank window.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    reportUiError({
      kind: "render",
      message: `${error.name}: ${error.message}`,
      stack: error.stack,
      componentStack: info.componentStack ?? undefined,
    });
  }

  render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    return (
      <div role="alert" className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
        <p className="text-sm font-medium">Something went wrong.</p>
        <p className="text-muted-foreground text-xs">The error was recorded. Reloading usually fixes it.</p>
        <Button size="sm" onClick={() => window.location.reload()}>
          Reload
        </Button>
      </div>
    );
  }
}
