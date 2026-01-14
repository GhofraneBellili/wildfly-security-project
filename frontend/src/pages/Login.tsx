import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { loginApi } from "../lib/api";
import { useAuth } from "../contexts/AuthContext";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("alice");
  const [password, setPassword] = useState("password");
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await loginApi(username, password);
      login(res.token, res.userId);
      nav("/");
    } catch (err) {
      alert("Erreur de connexion");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto bg-white p-6 rounded shadow">
      <h1 className="text-xl font-bold mb-4">Connexion</h1>
      <form onSubmit={handleSubmit} className="space-y-3">
        <input className="w-full p-2 border rounded" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" className="w-full p-2 border rounded" value={password} onChange={e => setPassword(e.target.value)} />
        <button type="submit" className="btn" disabled={loading}>{loading ? "Connexion..." : "Se connecter"}</button>
      </form>
    </div>
  );
}