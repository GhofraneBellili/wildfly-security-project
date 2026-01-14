import React, { useState } from "react";
import { createEvent } from "../lib/api";
import { useNavigate } from "react-router-dom";

export default function CreateEvent() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [date, setDate] = useState("");
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title) return alert("titre requis");
    setLoading(true);
    try {
      const ev = await createEvent({ title, description, date });
      nav(`/events/${ev.id}`);
    } catch (err: any) {
      alert(err?.message || "Erreur création");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto bg-white p-6 rounded shadow">
      <h1 className="text-xl font-bold mb-4">Créer un événement</h1>
      <form onSubmit={handleSubmit} className="space-y-3">
        <input className="w-full p-2 border rounded" placeholder="Titre" value={title} onChange={e => setTitle(e.target.value)} />
        <textarea className="w-full p-2 border rounded" placeholder="Description" value={description} onChange={e => setDescription(e.target.value)} />
        <input className="w-full p-2 border rounded" placeholder="Date ISO" value={date} onChange={e => setDate(e.target.value)} />
        <button type="submit" className="btn" disabled={loading}>{loading ? "Création..." : "Créer"}</button>
      </form>
    </div>
  );
}