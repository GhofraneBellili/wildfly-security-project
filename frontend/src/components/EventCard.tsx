import React from "react";
import { Link } from "react-router-dom";
import type { EventDTO } from "../lib/api";

export default function EventCard({ event }: { event: EventDTO }) {
  return (
    <article className="bg-white p-4 rounded shadow-sm">
      <h2 className="text-xl font-semibold">{event.title}</h2>
      <p className="text-sm text-gray-600">{event.description}</p>
      <div className="mt-2 flex items-center justify-between">
        <small className="text-xs text-gray-500">{event.date}</small>
        <Link to={`/events/${event.id}`} className="text-sm text-blue-600">Voir</Link>
      </div>
    </article>
  );
}