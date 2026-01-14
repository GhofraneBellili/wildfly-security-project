import React from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchEvents } from "../lib/api";
import EventCard from "../components/EventCard";

export default function Home() {
  const { data, isLoading, error } = useQuery(["events"], fetchEvents, { staleTime: 60_000 });

  if (isLoading) return <div>Chargement des événements…</div>;
  if (error) return <div>Erreur lors du chargement</div>;

  return (
    <div>
      <h1 className="text-3xl font-bold mb-4">Événements</h1>
      <div className="grid gap-4">
        {data?.map(ev => <EventCard key={ev.id} event={ev} />)}
      </div>
    </div>
  );
}