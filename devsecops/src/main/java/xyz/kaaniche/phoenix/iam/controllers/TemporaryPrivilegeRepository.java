package xyz.kaaniche.phoenix.iam.controllers;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import xyz.kaaniche.phoenix.iam.entities.TemporaryPrivilege;

import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class TemporaryPrivilegeRepository {

    @PersistenceContext
    private EntityManager entityManager;

    public void save(TemporaryPrivilege privilege) {
        if (privilege.getId() == null) {
            entityManager.persist(privilege);
        } else {
            entityManager.merge(privilege);
        }
    }

    public Optional<TemporaryPrivilege> findById(Long id) {
        TemporaryPrivilege privilege = entityManager.find(TemporaryPrivilege.class, id);
        return Optional.ofNullable(privilege);
    }

    public List<TemporaryPrivilege> findAll() {
        return entityManager.createQuery("SELECT t FROM TemporaryPrivilege t", TemporaryPrivilege.class)
                .getResultList();
    }

    public List<TemporaryPrivilege> findByRequesterId(String requesterId) {
        return entityManager.createQuery("SELECT t FROM TemporaryPrivilege t WHERE t.requesterId = :requesterId ORDER BY t.requestTime DESC", TemporaryPrivilege.class)
                .setParameter("requesterId", requesterId)
                .getResultList();
    }

    public List<TemporaryPrivilege> findByStatus(String status) {
        return entityManager.createQuery("SELECT t FROM TemporaryPrivilege t WHERE t.status = :status", TemporaryPrivilege.class)
                .setParameter("status", status)
                .getResultList();
    }
}
