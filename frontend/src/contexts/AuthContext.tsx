import React, { createContext, useContext, useEffect, useState } from "react";
import { setAuthToken } from "../lib/api";

type User = { token: string; userId: string } | null;

const KEY = "evenster_token";

const AuthContext = createContext<{
  user: User;
  login: (token: string, userId: string) => void;
  logout: () => void;
}>({
  user: null,
  login: () => {},
  logout: () => {}
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User>(() => {
    const t = localStorage.getItem(KEY);
    return t ? { token: t, userId: localStorage.getItem("evenster_user") || "unknown" } : null;
  });

  useEffect(() => {
    setAuthToken(user?.token ?? null);
  }, [user]);

  const login = (token: string, userId: string) => {
    localStorage.setItem(KEY, token);
    localStorage.setItem("evenster_user", userId);
    setUser({ token, userId });
  };

  const logout = () => {
    localStorage.removeItem(KEY);
    localStorage.removeItem("evenster_user");
    setUser(null);
  };

  return <AuthContext.Provider value={{ user, login, logout }}>{children}</AuthContext.Provider>;
};

export const useAuth = () => useContext(AuthContext);