import { events, AppBlock, EventInput } from "@slflows/sdk/v1";

export const httpRequestBlock: AppBlock = {
  name: "HTTP Request",
  description:
    "Makes an HTTP request using the GCP access token for authorization",
  category: "HTTP",

  inputs: {
    default: {
      name: "Trigger",
      description: "Triggers the HTTP request",
      config: {
        url: {
          name: "URL",
          description: "The URL to send the request to",
          type: "string",
          required: true,
        },
        method: {
          name: "HTTP Method",
          description: "HTTP method to use",
          type: "string",
          required: false,
          default: "GET",
        },
        headers: {
          name: "Additional Headers",
          description:
            'Additional HTTP headers as JSON object (e.g., {"x-custom-header": "value"})',
          type: {
            type: "object",
            additionalProperties: {
              type: "string",
            },
          },
          required: false,
        },
        body: {
          name: "Request Body",
          description: "Request body content (for POST, PUT, PATCH methods)",
          type: "string",
          required: false,
        },
      },
      async onEvent(input: EventInput): Promise<void> {
        const accessToken = input.app.signals.accessToken as string | undefined;

        if (!accessToken) {
          throw new Error(
            "No GCP access token available. Ensure the app is fully configured and synced.",
          );
        }

        const {
          url,
          method,
          headers: extraHeaders,
          body,
        } = input.event.inputConfig;

        const requestHeaders: Record<string, string> = {
          Authorization: `Bearer ${accessToken}`,
          ...((extraHeaders as Record<string, string>) ?? {}),
        };

        if (body !== undefined && body !== null) {
          requestHeaders["Content-Type"] = "application/json";
        }

        const response = await fetch(url, {
          method: (method as string) ?? "GET",
          headers: requestHeaders,
          body:
            body !== undefined && body !== null
              ? JSON.stringify(body)
              : undefined,
        });

        const responseText = await response.text();
        let responseBody: unknown;
        try {
          responseBody = JSON.parse(responseText);
        } catch {
          responseBody = responseText;
        }

        if (!response.ok) {
          throw new Error(
            `HTTP request failed: ${response.status} ${response.statusText} - ${responseText}`,
          );
        }

        await events.emit({
          statusCode: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body: responseBody,
        });
      },
    },
  },

  outputs: {
    default: {
      name: "Response",
      description: "The HTTP response",
      type: {
        type: "object",
        properties: {
          statusCode: { type: "number" },
          headers: { type: "object" },
          body: {},
        },
      },
    },
  },
};
