import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export default function Navbar() {
  const { user, logout } = useAuth();
  const nav = useNavigate();

  return (
    <header className="bg-white shadow">
      <div className="container flex items-center justify-between py-4">
        <Link to="/" className="text-2xl font-bold">Evenster</Link>
        <nav className="flex items-center gap-3">
          <Link to="/" className="text-sm">Accueil</Link>
          <Link to="/create" className="text-sm">Créer</Link>
          {!user ? (
            <>
              <Link to="/login" className="text-sm">Se connecter</Link>
              <Link to="/signup" className="text-sm">S'inscrire</Link>
            </>
          ) : (
            <>
              <span className="text-sm">Bonjour {user.userId}</span>
              <button className="btn" onClick={() => { logout(); nav("/"); }}>Déconnexion</button>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}