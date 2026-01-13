package xyz.kaaniche.phoenix.iam.controllers;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;
import java.util.List;

@ApplicationScoped
public class AuditLogRepository {

    @PersistenceContext
    private EntityManager entityManager;

    public void save(AuditLog auditLog) {
        entityManager.persist(auditLog);
    }

    public List<AuditLog> findByUserId(String userId) {
        return entityManager.createQuery("SELECT a FROM AuditLog a WHERE a.userId = :userId ORDER BY a.timestamp DESC", AuditLog.class)
                .setParameter("userId", userId)
                .getResultList();
    }
}
