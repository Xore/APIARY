export interface RuntimeStatus {
  Uptime: string;
  Heap: string;
  Reserved: string;
  ContainerUsage: string;
  ContainerLimit: string;
  Goroutines: number;
}

export interface StoredEvent {
  Time: string;
  Sensor: string;
  SrcIP: string;
  Country?: string;
  Proto?: string;
  Port?: string;
  Command?: string;
  Path?: string;
  Alert?: string;
  Session?: string;
  Shasum?: string;
  Detail: string;
}

export interface EventsPage {
  Total: number;
  Page: number;
  Pages: number;
  PerPage: number;
  Events: StoredEvent[];
}

async function json<T>(path: string): Promise<T> {
  const response = await fetch(path, { cache: "no-store", headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json() as Promise<T>;
}

export const events = (params = new URLSearchParams()): Promise<EventsPage> => json(`/api/events?${params}`);
export const runtime = (): Promise<RuntimeStatus> => json("/api/runtime");
export const stats = <T = unknown>(): Promise<T> => json<T>("/api/stats");
export const alerts = <T = unknown[]>(): Promise<T> => json<T>("/api/alerts");

export function stream(onUpdate: () => void): () => void {
  const source = new EventSource("/api/stream");
  source.addEventListener("update", onUpdate);
  return () => source.close();
}
