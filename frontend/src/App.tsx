import React, { useEffect, useState } from "react";
import { fetchEvents, login as apiLogin, createEvent, registerToEvent, logout as apiLogout, getToken } from "./lib/api";

type User = { token: string; userId: string } | null;

export default function App(){
  const [events, setEvents] = useState<any[]>([]);
  const [user, setUser] = useState<User>(() => {
    const token = getToken();
    return token ? { token, userId: "unknown" } : null;
  });

  async function load(){
    try {
      const ev = await fetchEvents();
      setEvents(ev);
    } catch (e) {
      console.error(e);
    }
  }

  useEffect(() => { load() }, []);

  async function handleLogin(){
    const username = prompt("username") || "guest";
    const password = prompt("password") || "pass";
    const u = await apiLogin(username, password);
    if (u?.token) setUser(u);
    else alert("login failed");
  }

  async function handleLogout(){
    apiLogout();
    setUser(null);
  }

  async function handleCreate(){
    if (!user) return alert("connectez-vous d'abord");
    const title = prompt("titre") || "Nouvel évènement";
    const description = prompt("description") || "";
    const date = new Date().toISOString();
    try {
      const ev = await createEvent({ title, description, date });
      setEvents(prev => [ev, ...prev]);
    } catch (e) {
      alert("Erreur création : " + (e as Error).message);
    }
  }

  async function handleRegister(evId: string){
    if (!user) return alert("connectez-vous d'abord");
    const ok = await registerToEvent(evId, user.userId);
    if (ok) {
      alert("Inscription OK");
      await load();
    } else alert("Impossible de s'inscrire");
  }

  return (
    <div className="app">
      <div className="header">
        <h1>Evenster — événements</h1>
        <div>
          {user ? (
            <>
              <span>Bonjour {user.userId}</span>
              <button style={{marginLeft:8}} onClick={handleLogout}>Déconnexion</button>
            </>
          ) : <button onClick={handleLogin}>Se connecter</button>}
          <button style={{marginLeft:8}} onClick={handleCreate}>Créer événement</button>
        </div>
      </div>

      <div>
        {events.length === 0 && <div>Chargement...</div>}
        <ul>
          {events.map(ev => (
            <li key={ev.id} style={{padding:8,borderBottom:"1px solid #eee"}}>
              <strong>{ev.title}</strong> <br/>
              <small>{ev.description}</small> <br/>
              <em>{ev.date}</em>
              <div>
                participants: {ev.participants?.length || 0}
                <button style={{marginLeft:8}} onClick={() => handleRegister(ev.id)}>S'inscrire</button>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}