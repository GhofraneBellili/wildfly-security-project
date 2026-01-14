package com.evenster.service;

import com.evenster.model.Event;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class EventService {

    private final Map<String, Event> store = new ConcurrentHashMap<>();

    public EventService() {
        // seed data
        Event e1 = new Event("Concert: Stars Live", "Un concert en plein air", LocalDateTime.now().plusDays(10));
        Event e2 = new Event("Atelier développeurs", "Workshop: Spring Boot & React", LocalDateTime.now().plusDays(5));
        create(e1);
        create(e2);
    }

    public List<Event> listAll() {
        return new ArrayList<>(store.values());
    }

    public Optional<Event> getById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public Event create(Event event) {
        if (event.getId() == null || event.getId().isEmpty()) {
            event.setId(UUID.randomUUID().toString());
        }
        store.put(event.getId(), event);
        return event;
    }

    public boolean registerUser(String eventId, String userId) {
        Event e = store.get(eventId);
        if (e == null) return false;
        if (e.getParticipants().contains(userId)) return false;
        e.getParticipants().add(userId);
        return true;
    }
}