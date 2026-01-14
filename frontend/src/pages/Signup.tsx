import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { registerApi, loginApi } from "../lib/api";
import { useAuth } from "../contexts/AuthContext";

export default function Signup() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username || !password) return alert("username et password requis");
    if (password !== confirm) return alert("les mots de passe ne correspondent pas");
    setLoading(true);
    try {
      const res = await registerApi(username, password);
      if (res?.token) {
        login(res.token, res.userId);
        nav("/");
      } else {
        const l = await loginApi(username, password);
        login(l.token, l.userId);
        nav("/");
      }
    } catch (err: any) {
      const msg = err?.response?.data?.error || err.message || "Erreur inscription";
      alert(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto bg-white p-6 rounded shadow">
      <h1 className="text-xl font-bold mb-4">Créer un compte</h1>
      <form onSubmit={handleSubmit} className="space-y-3">
        <input className="w-full p-2 border rounded" placeholder="Nom d'utilisateur" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" className="w-full p-2 border rounded" placeholder="Mot de passe" value={password} onChange={e => setPassword(e.target.value)} />
        <input type="password" className="w-full p-2 border rounded" placeholder="Confirmer mot de passe" value={confirm} onChange={e => setConfirm(e.target.value)} />
        <button type="submit" className="btn" disabled={loading}>{loading ? "Création..." : "Créer un compte"}</button>
      </form>
    </div>
  );
}