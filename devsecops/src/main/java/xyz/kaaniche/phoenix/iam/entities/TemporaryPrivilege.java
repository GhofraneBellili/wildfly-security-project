package xyz.kaaniche.phoenix.iam.entities;

import jakarta.persistence.*;
import xyz.kaaniche.phoenix.core.entities.SimplePKEntity;

import java.time.LocalDateTime;

@Entity
@Table(name = "temporary_privileges")
public class TemporaryPrivilege extends SimplePKEntity<Long> {

    @Column(name = "requester_id", nullable = false)
    private String requesterId;

    @Column(name = "privilege_type", nullable = false)
    private String privilegeType;

    @Column(name = "resource_id")
    private String resourceId;

    @Column(name = "request_time", nullable = false)
    private LocalDateTime requestTime;

    @Column(name = "expiration_time", nullable = false)
    private LocalDateTime expirationTime;

    @Column(name = "approver_id")
    private String approverId;

    @Column(name = "approval_time")
    private LocalDateTime approvalTime;

    @Column(nullable = false)
    private String status; // PENDING, APPROVED, REVOKED, EXPIRED

    @Column(name = "justification")
    private String justification;

    // Constructors
    public TemporaryPrivilege() {}

    public TemporaryPrivilege(String requesterId, String privilegeType, String resourceId,
                            LocalDateTime expirationTime, String justification) {
        this.requesterId = requesterId;
        this.privilegeType = privilegeType;
        this.resourceId = resourceId;
        this.expirationTime = expirationTime;
        this.justification = justification;
    }

    // Getters and Setters
    public String getRequesterId() {
        return requesterId;
    }

    public void setRequesterId(String requesterId) {
        this.requesterId = requesterId;
    }

    public String getPrivilegeType() {
        return privilegeType;
    }

    public void setPrivilegeType(String privilegeType) {
        this.privilegeType = privilegeType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public LocalDateTime getRequestTime() {
        return requestTime;
    }

    public void setRequestTime(LocalDateTime requestTime) {
        this.requestTime = requestTime;
    }

    public LocalDateTime getExpirationTime() {
        return expirationTime;
    }

    public void setExpirationTime(LocalDateTime expirationTime) {
        this.expirationTime = expirationTime;
    }

    public String getApproverId() {
        return approverId;
    }

    public void setApproverId(String approverId) {
        this.approverId = approverId;
    }

    public LocalDateTime getApprovalTime() {
        return approvalTime;
    }

    public void setApprovalTime(LocalDateTime approvalTime) {
        this.approvalTime = approvalTime;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getJustification() {
        return justification;
    }

    public void setJustification(String justification) {
        this.justification = justification;
    }
}
