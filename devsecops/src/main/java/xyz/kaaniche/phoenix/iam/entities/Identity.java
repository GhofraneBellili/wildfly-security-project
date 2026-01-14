package xyz.kaaniche.phoenix.iam.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import xyz.kaaniche.phoenix.core.entities.SimplePKEntity;

import java.security.Principal;
import java.util.Date;

@Entity
@Table(name = "identity")
public class Identity extends SimplePKEntity<Long> implements Principal {

    @Column(name = "username", nullable = false, unique = true)
    @NotBlank
    @Size(max = 50)
    private String username;

    @Column(name = "email", nullable = false, unique = true)
    @NotBlank
    @Email
    @Size(max = 100)
    private String email;

    // CRITICAL FIX: Prevent password hash from being serialized
    @JsonIgnore  // Prevents JSON serialization
    @Column(name = "password_hash", nullable = false)
    @NotBlank
    private String passwordHash;

    @Column(name = "first_name")
    @Size(max = 50)
    private String firstName;

    @Column(name = "last_name")
    @Size(max = 50)
    private String lastName;

    @Column(name = "enabled", nullable = false)
    @NotNull
    private Boolean enabled = true;

    @Column(name = "created_at", nullable = false)
    @NotNull
    private Date createdAt;

    @Column(name = "updated_at")
    private Date updatedAt;

    // CRITICAL FIX: Prevent MFA secret from being serialized AND encrypt in database
    @JsonIgnore
    @Convert(converter = xyz.kaaniche.phoenix.iam.security.EncryptedFieldConverter.class)
    @Column(name = "mfa_secret")
    private String mfaSecret;

    @Column(name = "requires_mfa")
    private Boolean requiresMfa = false;

    @Column(name = "roles")
    private Long roles = 0L;

    // Constructors
    public Identity() {
        this.createdAt = new Date();
    }

    // Getters and Setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    // CRITICAL FIX: Only allow reading internally, never via JSON
    @JsonIgnore
    public String getPasswordHash() {
        return passwordHash;
    }

    // CRITICAL FIX: Only allow setting via JSON (for registration/password change)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    // CRITICAL FIX: Never expose MFA secret
    @JsonIgnore
    public String getMfaSecret() {
        return mfaSecret;
    }

    @JsonIgnore
    public void setMfaSecret(String mfaSecret) {
        this.mfaSecret = mfaSecret;
    }

    public Boolean getRequiresMfa() {
        return requiresMfa;
    }

    public void setRequiresMfa(Boolean requiresMfa) {
        this.requiresMfa = requiresMfa;
    }

    public Long getRoles() {
        return roles;
    }

    public void setRoles(Long roles) {
        this.roles = roles;
    }

    // REMOVED: This method was a critical security vulnerability
    // public String getPassword() { return passwordHash; }
    
    // ADDED: Safe method for authentication (internal use only)
    @JsonIgnore
    public boolean checkPassword(String plainPassword) {
        // This should delegate to your password hashing utility
        return xyz.kaaniche.phoenix.iam.security.Argon2Utility.check(
            this.passwordHash, 
            plainPassword.toCharArray()
        );
    }

    // Principal methods
    @Override
    @JsonIgnore
    public String getName() {
        return username;
    }

    // Utility methods
    public String getFullName() {
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        } else if (firstName != null) {
            return firstName;
        } else if (lastName != null) {
            return lastName;
        } else {
            return username;
        }
    }

    @Override
    public String toString() {
        return "Identity{" +
                "id=" + getId() +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", enabled=" + enabled +
                ", createdAt=" + createdAt +
                '}';
        // NOTE: Intentionally NOT including passwordHash or mfaSecret in toString
    }
}