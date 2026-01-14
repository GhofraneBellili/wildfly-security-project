package com.evenster.controller;

import com.evenster.model.Event;
import com.evenster.service.EventService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/events")
public class EventController {

    private final EventService service;

    public EventController(EventService service) {
        this.service = service;
    }

    @GetMapping
    public List<Event> list() {
        return service.listAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Event> get(@PathVariable String id) {
        return service.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<Event> create(@Valid @RequestBody Event event) {
        Event created = service.create(event);
        return ResponseEntity.ok(created);
    }

    @PostMapping("/{id}/register")
    public ResponseEntity<String> register(@PathVariable String id, @RequestParam String userId) {
        boolean ok = service.registerUser(id, userId);
        if (ok) return ResponseEntity.ok("registered");
        return ResponseEntity.badRequest().body("cannot register");
    }
}