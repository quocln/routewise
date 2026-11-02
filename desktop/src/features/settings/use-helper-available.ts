import { useSettings, useStatus } from "@/lib/rpc/queries";

/** Whether the helper answers, so settings that go through it can be changed. */
export function useHelperAvailable(): boolean {
  const status = useStatus();
  const settings = useSettings();
  return settings.isSuccess && !status.isError;
}
