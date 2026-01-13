package xyz.kaaniche.phoenix.iam.boundaries;

import jakarta.annotation.security.RolesAllowed;
import jakarta.ejb.Stateless;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import xyz.kaaniche.phoenix.iam.controllers.AuditLogRepository;
import xyz.kaaniche.phoenix.iam.controllers.TemporaryPrivilegeRepository;
import xyz.kaaniche.phoenix.iam.entities.AuditLog;
import xyz.kaaniche.phoenix.iam.entities.TemporaryPrivilege;
import xyz.kaaniche.phoenix.iam.security.IdentityUtility;

import java.time.LocalDateTime;
import java.util.List;

@Path("/jit")
@Stateless
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class JITAccessEndpoint {

    @Inject
    private TemporaryPrivilegeRepository tempPrivilegeRepo;

    @Inject
    private AuditLogRepository auditLogRepo;

    @POST
    @Path("/request")
    @RolesAllowed({"USER"}) // Any authenticated user can request JIT access
    public Response requestJITAccess(TemporaryPrivilege request) {
        String currentUser = IdentityUtility.getCurrentUser();

        // Set request details
        request.setRequesterId(currentUser);
        request.setRequestTime(LocalDateTime.now());
        request.setStatus("PENDING");

        tempPrivilegeRepo.save(request);

        auditLogRepo.save(new AuditLog(currentUser, "JIT_REQUEST",
            "JIT access requested for " + request.getPrivilegeType(), "SYSTEM"));

        return Response.ok("{\"message\":\"JIT access request submitted\"}").build();
    }

    @GET
    @Path("/requests")
    @RolesAllowed({"ADMIN"})
    public Response getPendingRequests() {
        List<TemporaryPrivilege> pendingRequests = tempPrivilegeRepo.findAll()
            .stream()
            .filter(req -> "PENDING".equals(req.getStatus()))
            .toList();

        return Response.ok(pendingRequests).build();
    }

    @POST
    @Path("/approve/{requestId}")
    @RolesAllowed({"ADMIN"})
    public Response approveJITAccess(@PathParam("requestId") Long requestId) {
        String approver = IdentityUtility.getCurrentUser();

        TemporaryPrivilege request = tempPrivilegeRepo.findById(requestId).orElse(null);
        if (request == null) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity("{\"error\":\"Request not found\"}").build();
        }

        request.setApproverId(approver);
        request.setApprovalTime(LocalDateTime.now());
        request.setStatus("APPROVED");

        tempPrivilegeRepo.save(request);

        auditLogRepo.save(new AuditLog(approver, "JIT_APPROVE",
            "JIT access approved for " + request.getRequesterId(), "SYSTEM"));

        return Response.ok("{\"message\":\"JIT access approved\"}").build();
    }

    @POST
    @Path("/revoke/{requestId}")
    @RolesAllowed({"ADMIN"})
    public Response revokeJITAccess(@PathParam("requestId") Long requestId) {
        String revoker = IdentityUtility.getCurrentUser();

        TemporaryPrivilege request = tempPrivilegeRepo.findById(requestId).orElse(null);
        if (request == null) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity("{\"error\":\"Request not found\"}").build();
        }

        request.setStatus("REVOKED");
        tempPrivilegeRepo.save(request);

        auditLogRepo.save(new AuditLog(revoker, "JIT_REVOKE",
            "JIT access revoked for " + request.getRequesterId(), "SYSTEM"));

        return Response.ok("{\"message\":\"JIT access revoked\"}").build();
    }

    @GET
    @Path("/my-access")
    @RolesAllowed({"USER"})
    public Response getMyJITAccess() {
        String currentUser = IdentityUtility.getCurrentUser();

        List<TemporaryPrivilege> myAccess = tempPrivilegeRepo.findAll()
            .stream()
            .filter(req -> currentUser.equals(req.getRequesterId()) &&
                          "APPROVED".equals(req.getStatus()) &&
                          LocalDateTime.now().isBefore(req.getExpirationTime()))
            .toList();

        return Response.ok(myAccess).build();
    }
}
