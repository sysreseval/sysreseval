// The calls of the browser to the portal: JSON requests with the CSRF header, the errors as
// ApiError, the NDJSON stream of a start read line by line, the WebSocket URLs.

// The portal refuses every non-GET /api request and every WebSocket without this header
// (the WebSockets are checked on their Origin instead: nothing to add there).
const CSRF_HEADER = 'X-Requested-With';
const CSRF_VALUE = 'sre-web';

export class ApiError extends Error {
  // status: the HTTP status; data: the JSON body {error, status, retry_after?} when there was one
  constructor(status, message, data) {
    super(message);
    this.status = status;
    this.data = data || {};
  }
}

// A request whose Response is returned as is (the NDJSON streams, the SVG of the schema).
// `json` is sent as the JSON body, `body` as is.  A non-2xx answer is
// raised as an ApiError built from the JSON body of the portal; 401 goes back to the login page.
export async function fetchRaw(method, url, {json, body, headers} = {}) {
  const options = {method, headers: {...(headers || {})}, credentials: 'same-origin'};
  if (method !== 'GET' && method !== 'HEAD') {
    options.headers[CSRF_HEADER] = CSRF_VALUE;
  }
  if (json !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(json);
  } else if (body !== undefined) {
    options.body = body;
  }
  let response;
  try {
    response = await fetch(url, options);
  } catch (e) {
    throw new ApiError(0, e.message || 'network error');
  }
  if (response.status === 401) {
    window.location.href = '/login';
    throw new ApiError(401, 'not logged in');
  }
  if (!response.ok) {
    let data = {};
    try {
      data = await response.json();
    } catch (e) {
      data = {};
    }
    throw new ApiError(response.status, data.error || `HTTP ${response.status}`, data);
  }
  return response;
}

// A JSON call: the parsed body, or null for an empty answer (204).
export async function request(method, url, options = {}) {
  const response = await fetchRaw(method, url, options);
  if (response.status === 204) {
    return null;
  }
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

export const get = (url) => request('GET', url);
export const post = (url, json) => request('POST', url, json === undefined ? {} : {json});
export const put = (url, json) => request('PUT', url, {json});
export const del = (url) => request('DELETE', url);

// Read an NDJSON response (one JSON object per line) and call onEvent for each object.
// Returns the last object whose phase is "result" (null when the stream ended without one).
export async function readNdjson(response, onEvent) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let result = null;
  const handle = (line) => {
    line = line.trim();
    if (!line) {
      return;
    }
    let event;
    try {
      event = JSON.parse(line);
    } catch (e) {
      return;   // not JSON: ignored, like the Qt dialog
    }
    if (event.phase === 'result') {
      result = event;
    }
    onEvent(event);
  };
  for (;;) {
    const {value, done} = await reader.read();
    if (done) {
      break;
    }
    buffer += decoder.decode(value, {stream: true});
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      handle(buffer.slice(0, index));
      buffer = buffer.slice(index + 1);
    }
  }
  buffer += decoder.decode();
  handle(buffer);
  return result;
}

// The WebSocket URL of a path of this site: ws:// or wss:// after the protocol of the page.
export function wsUrl(path) {
  const scheme = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
  return scheme + window.location.host + path;
}

// Add query parameters to a URL (the values are encoded; undefined / null values are skipped).
export function withQuery(url, params) {
  const pairs = [];
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== undefined && value !== null && value !== '') {
      pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
    }
  }
  if (!pairs.length) {
    return url;
  }
  return url + (url.includes('?') ? '&' : '?') + pairs.join('&');
}
