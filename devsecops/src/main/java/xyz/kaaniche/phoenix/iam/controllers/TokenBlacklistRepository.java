package xyz.kaaniche.phoenix.iam.controllers;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import xyz.kaaniche.phoenix.iam.entities.TokenBlacklist;

import java.time.LocalDateTime;
import java.util.Optional;

@ApplicationScoped
public class TokenBlacklistRepository {

    @PersistenceContext
    private EntityManager entityManager;

    public void blacklistToken(String jti, LocalDateTime expirationTime, String revokedBy, String reason) {
        TokenBlacklist blacklist = new TokenBlacklist();
        blacklist.setJti(jti);
        blacklist.setExpirationTime(expirationTime);
        blacklist.setRevokedAt(LocalDateTime.now());
        blacklist.setRevokedBy(revokedBy);
        blacklist.setReason(reason);
        entityManager.persist(blacklist);
    }

    public boolean isTokenBlacklisted(String jti) {
        Long count = entityManager.createQuery(
                "SELECT COUNT(t) FROM TokenBlacklist t WHERE t.jti = :jti AND t.expirationTime > :now",
                Long.class)
                .setParameter("jti", jti)
                .setParameter("now", LocalDateTime.now())
                .getSingleResult();
        return count > 0;
    }

    public Optional<TokenBlacklist> findByJti(String jti) {
        try {
            TokenBlacklist blacklist = entityManager.createQuery(
                    "SELECT t FROM TokenBlacklist t WHERE t.jti = :jti",
                    TokenBlacklist.class)
                    .setParameter("jti", jti)
                    .getSingleResult();
            return Optional.of(blacklist);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public void cleanupExpiredTokens() {
        entityManager.createQuery("DELETE FROM TokenBlacklist t WHERE t.expirationTime < :now")
                .setParameter("now", LocalDateTime.now())
                .executeUpdate();
    }
}
