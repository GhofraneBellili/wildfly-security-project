import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { fetchEvent, registerToEvent } from "../lib/api";
import { useAuth } from "../contexts/AuthContext";

export default function EventDetails() {
  const { id } = useParams();
  const { user } = useAuth();
  const [event, setEvent] = useState<any>(null);

  useEffect(() => {
    if (!id) return;
    fetchEvent(id).then(setEvent).catch(() => setEvent(null));
  }, [id]);

  if (!event) return <div>Chargement...</div>;

  async function handleRegister() {
    if (!user) return alert("Connectez-vous d'abord");
    const ok = await registerToEvent(event.id, user.userId);
    if (ok) {
      alert("Inscription réussie");
    } else alert("Impossible de s'inscrire");
  }

  return (
    <div className="bg-white p-6 rounded shadow">
      <h1 className="text-2xl font-bold">{event.title}</h1>
      <p className="text-sm text-gray-600">{event.description}</p>
      <p className="mt-2 text-xs text-gray-500">{event.date}</p>
      <div className="mt-4">
        <button className="btn" onClick={handleRegister}>S'inscrire</button>
      </div>
    </div>
  );
}