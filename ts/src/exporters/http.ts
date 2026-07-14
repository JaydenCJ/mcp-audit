/**
 * Shared HTTP delivery used by the OTLP, Splunk HEC and Datadog exporters.
 * Uses the global fetch available in Node.js >= 18. Requests are only made
 * when an event is exported — importing this module has no side effects.
 */

export interface HttpPostOptions {
  url: string;
  headers: Record<string, string>;
  body: string;
  /** Abort the request after this many milliseconds. Default 5000. */
  timeoutMs?: number;
}

/** POST a payload; throws on network failure or non-2xx status. */
export async function httpPost(options: HttpPostOptions): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000);
  try {
    const response = await fetch(options.url, {
      method: "POST",
      headers: options.headers,
      body: options.body,
      signal: controller.signal,
    });
    if (!response.ok) {
      // Drain the body so the socket can be reused, then fail loudly.
      const text = await response.text().catch(() => "");
      throw new Error(`HTTP ${response.status} from ${options.url}: ${text.slice(0, 200)}`);
    }
    // Consume the body to completion; some collectors send a JSON ack.
    await response.arrayBuffer().catch(() => undefined);
  } finally {
    clearTimeout(timer);
  }
}
