"use client";

import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export interface Option {
  value: string;
  label: string;
}

/** A single-choice dropdown over plain string options. */
export function OptionSelect({
  value,
  options,
  onValueChange,
  label,
  help,
  disabled,
  className,
}: {
  value: string;
  options: Option[];
  onValueChange: (value: string) => void;
  /** Accessible name of the control. */
  label: string;
  /** Tooltip explaining what choosing does. */
  help?: string;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <Select
      value={value}
      items={options}
      disabled={disabled}
      onValueChange={(next) => {
        if (next !== null) onValueChange(next);
      }}>
      <SelectTrigger size="sm" aria-label={label} title={help} className={className}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent alignItemWithTrigger={false}>
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
