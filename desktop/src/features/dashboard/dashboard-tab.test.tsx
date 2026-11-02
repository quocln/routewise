import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SystemStatsSample } from "@/lib/native/native-commands";
import { diskLevel, formatDisk, formatMemory, formatRate, lineRuns, niceRateScale, withSample } from "./system-stats";

let reply: () => unknown = () => [];

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (command: string) => {
    if (command !== "system_stats_history") return Promise.reject(new Error(`unexpected ${command}`));
    try {
      return Promise.resolve(reply());
    } catch (error) {
      return Promise.reject(error);
    }
  },
  isTauri: () => true,
}));

let pushSample: ((event: { payload: SystemStatsSample }) => void) | undefined;
vi.mock("@tauri-apps/api/event", () => ({
  listen: (_name: string, handler: (event: { payload: SystemStatsSample }) => void) => {
    pushSample = handler;
    return Promise.resolve(() => {});
  },
}));

const { DashboardTab } = await import("./dashboard-tab");

const GIB = 1024 ** 3;
const NOW = 1_800_000_000_000;

function sample(over: Partial<SystemStatsSample> = {}): SystemStatsSample {
  return {
    timeMs: NOW,
    cpuPercent: 61,
    memoryPercent: 75,
    memoryUsedBytes: 12 * GIB,
    memoryTotalBytes: 16 * GIB,
    diskPercent: 40,
    diskUsedBytes: 200e9,
    diskTotalBytes: 500e9,
    network: { up: 1_000, down: 2_400_000 },
    ...over,
  };
}

function renderTab() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <DashboardTab />
    </QueryClientProvider>,
  );
}

describe("system figures", () => {
  it("spells a rate in powers of 1000", () => {
    expect(formatRate(999)).toBe("999 B/s");
    expect(formatRate(1_000)).toBe("1.0 KB/s");
    expect(formatRate(2_400_000)).toBe("2.4 MB/s");
  });

  it("counts memory in powers of 1024 and disk in powers of 1000", () => {
    expect(formatMemory(16 * GIB)).toBe("16.0 GB");
    expect(formatDisk(500e9)).toBe("500 GB");
  });

  it("scales a network axis to a clean number and never below idle noise", () => {
    expect(niceRateScale(0)).toBe(1_000);
    expect(niceRateScale(1_001)).toBe(2_000);
    expect(niceRateScale(4_200_000)).toBe(5_000_000);
    expect(niceRateScale(7_000_000)).toBe(10_000_000);
  });

  it("breaks a line at an unread value and at a pause, so nothing is invented", () => {
    const runs = lineRuns([0, 2_000, 4_000, 6_000, 60_000, 62_000], [1, null, 3, 4, 5, 6]);
    expect(runs.map((run) => run.map((point) => point.value))).toEqual([[1], [3, 4], [5, 6]]);
  });

  it("adds a sample to the window, dropping the oldest and ignoring one it has", () => {
    const full = Array.from({ length: 150 }, (_, i) => sample({ timeMs: i }));
    const next = withSample(full, sample({ timeMs: 150 }));
    expect(next).toHaveLength(150);
    expect(next[0].timeMs).toBe(1);
    expect(next[149].timeMs).toBe(150);
    expect(withSample(next, sample({ timeMs: 150 }))).toBe(next);
    expect(withSample(undefined, sample({ timeMs: 1 }))).toHaveLength(1);
  });

  it("calls a disk worrying only when it is nearly full", () => {
    expect(diskLevel(84)).toBe("ok");
    expect(diskLevel(85)).toBe("warning");
    expect(diskLevel(95)).toBe("critical");
  });
});

describe("DashboardTab", () => {
  beforeEach(() => {
    reply = () => [sample({ timeMs: NOW - 2_000, cpuPercent: 50 }), sample()];
  });

  it("shows the latest CPU, memory, disk and network figures", async () => {
    renderTab();
    const cpu = await screen.findByRole("region", { name: "CPU" });
    expect(await within(cpu).findByText("61%")).toBeInTheDocument();
    const memory = screen.getByRole("region", { name: "Memory" });
    expect(within(memory).getByText("75%")).toBeInTheDocument();
    expect(within(memory).getByText("12.0 GB of 16.0 GB")).toBeInTheDocument();
    const disk = screen.getByRole("region", { name: "Disk" });
    expect(within(disk).getByText("200 GB of 500 GB")).toBeInTheDocument();
    expect(within(disk).getByText("300 GB free")).toBeInTheDocument();
    expect(within(disk).getByRole("meter", { name: "Disk used" })).toHaveAttribute("aria-valuenow", "40");
    const network = screen.getByRole("region", { name: "Network" });
    expect(within(network).getByText("2.4 MB/s")).toBeInTheDocument();
    expect(within(network).getByText("Download")).toBeInTheDocument();
    expect(within(network).getByText("1.0 KB/s")).toBeInTheDocument();
    expect(within(network).getByText("Upload")).toBeInTheDocument();
  });

  it("says a figure is not known yet instead of showing zero", async () => {
    reply = () => [sample({ cpuPercent: null, network: null })];
    renderTab();
    const cpu = await screen.findByRole("region", { name: "CPU" });
    await waitFor(() => expect(within(cpu).getByText("—")).toBeInTheDocument());
    expect(within(screen.getByRole("region", { name: "Network" })).getAllByText("—")).toHaveLength(2);
  });

  it("warns with words, not only color, when the disk is nearly full", async () => {
    reply = () => [sample({ diskPercent: 90, diskUsedBytes: 450e9 })];
    renderTab();
    expect(await screen.findByText("Getting full")).toBeInTheDocument();
    expect(screen.queryByText("Almost full")).toBeNull();
  });

  it("draws one line per unbroken run", async () => {
    reply = () => [
      sample({ timeMs: NOW - 60_000 }),
      sample({ timeMs: NOW - 58_000 }),
      sample({ timeMs: NOW - 2_000 }),
      sample(),
    ];
    renderTab();
    const cpu = await screen.findByRole("region", { name: "CPU" });
    await waitFor(() => expect(within(cpu).getAllByTestId("chart-line")).toHaveLength(2));
  });

  it("reads out every series from the keyboard", async () => {
    renderTab();
    const network = await screen.findByRole("region", { name: "Network" });
    await waitFor(() => expect(within(network).getByText("2.4 MB/s")).toBeInTheDocument());
    const chart = within(network).getByRole("group");
    fireEvent.focus(chart);
    const readout = within(network).getByRole("status");
    expect(readout).toHaveTextContent("2.4 MB/sDownload");
    expect(readout).toHaveTextContent("1.0 KB/sUpload");
    fireEvent.blur(chart);
    expect(within(network).queryByRole("status")).toBeNull();
  });

  it("moves to an earlier sample with the arrow key", async () => {
    renderTab();
    const cpu = await screen.findByRole("region", { name: "CPU" });
    await waitFor(() => expect(within(cpu).getByText("61%")).toBeInTheDocument());
    const chart = within(cpu).getByRole("group");
    fireEvent.focus(chart);
    expect(within(cpu).getByRole("status")).toHaveTextContent("61%");
    fireEvent.keyDown(chart, { key: "ArrowLeft" });
    expect(within(cpu).getByRole("status")).toHaveTextContent("50%");
  });

  it("offers the same figures as a table, newest first", async () => {
    const user = userEvent.setup();
    renderTab();
    await screen.findByRole("region", { name: "CPU" });
    await user.click(screen.getByRole("button", { name: "Show table" }));
    const rows = await screen.findAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(rows[1]).toHaveTextContent("61%");
    expect(rows[2]).toHaveTextContent("50%");
    expect(screen.queryByRole("region", { name: "CPU" })).toBeNull();
  });

  it("shows a pushed sample without asking the shell again", async () => {
    let asked = 0;
    reply = () => {
      asked += 1;
      return [sample()];
    };
    renderTab();
    const cpu = await screen.findByRole("region", { name: "CPU" });
    await waitFor(() => expect(within(cpu).getByText("61%")).toBeInTheDocument());
    const askedBefore = asked;
    act(() => pushSample?.({ payload: sample({ timeMs: NOW + 2_000, cpuPercent: 12 }) }));
    await waitFor(() => expect(within(cpu).getByText("12%")).toBeInTheDocument());
    expect(asked).toBe(askedBefore);
  });

  it("says when the figures cannot be read", async () => {
    reply = () => {
      throw new Error("no figures");
    };
    renderTab();
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not read the system figures");
  });
});
