type EventDTO = {
  id?: string;
  title: string;
  description?: string;
  date: string;
  participants?: string[];
};

const TOKEN_KEY = "evenster_token";

export function saveToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function logout() {
  localStorage.removeItem(TOKEN_KEY);
}

function authHeader() {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

export async function fetchEvents(): Promise<EventDTO[]> {
  const res = await fetch("/api/events", { headers: { ...authHeader() } });
  if (!res.ok) throw new Error("failed to fetch events");
  return res.json();
}

export async function login(username: string, password: string): Promise<{ token: string; userId: string } | null> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) return null;
  const body = await res.json();
  if (body.token) {
    saveToken(body.token);
    return { token: body.token, userId: body.userId };
  }
  return null;
}

export async function createEvent(payload: EventDTO): Promise<EventDTO> {
  const res = await fetch("/api/events", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeader() },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "create failed");
  }
  return res.json();
}

export async function registerToEvent(eventId: string, userId: string): Promise<boolean> {
  const res = await fetch(`/api/events/${eventId}/register?userId=${encodeURIComponent(userId)}`, {
    method: "POST",
    headers: { ...authHeader() }
  });
  return res.ok;
}