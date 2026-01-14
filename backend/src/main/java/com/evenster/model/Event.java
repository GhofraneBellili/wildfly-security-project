package com.evenster.model;

import jakarta.validation.constraints.NotBlank;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class Event {
    private String id = UUID.randomUUID().toString();

    @NotBlank
    private String title;

    private String description;
    private LocalDateTime date;
    private Set<String> participants = new HashSet<>();

    public Event() {}

    public Event(String title, String description, LocalDateTime date) {
        this.title = title;
        this.description = description;
        this.date = date;
    }

    // getters & setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public LocalDateTime getDate() { return date; }
    public void setDate(LocalDateTime date) { this.date = date; }
    public Set<String> getParticipants() { return participants; }
    public void setParticipants(Set<String> participants) { this.participants = participants; }
}