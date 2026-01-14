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
import java.util.Set;

@Path("/jit")
@Stateless
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class JITAccessEndpoint {

    private static final Set<String> ALLOWED_PRIVILEGES =
            Set.of("READ_ONLY", "SUPPORT", "OPERATOR");

    private static final int MAX_JIT_DURATION_HOURS = 8;

    @Inject
    private TemporaryPrivilegeRepository tempPrivilegeRepo;

    @Inject
    private AuditLogRepository auditLogRepo;

    /* =====================================================
       REQUEST JIT ACCESS
       ===================================================== */
    @POST
    @Path("/request")
    @RolesAllowed({"USER"})
    public Response requestJITAccess(TemporaryPrivilege input) {

        String currentUser = IdentityUtility.getCurrentUser();

        // Validate input (prevent mass assignment)
        if (input == null || input.getPrivilegeType() == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"Invalid request\"}").build();
        }

        if (!ALLOWED_PRIVILEGES.contains(input.getPrivilegeType())) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("{\"error\":\"Privilege not allowed\"}").build();
        }

        LocalDateTime expiration = input.getExpirationTime();
        if (expiration == null ||
            expiration.isAfter(LocalDateTime.now().plusHours(MAX_JIT_DURATION_HOURS))) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"Invalid expiration time\"}").build();
        }

        TemporaryPrivilege request = new TemporaryPrivilege();
        request.setRequesterId(currentUser);
        request.setPrivilegeType(input.getPrivilegeType());
        request.setExpirationTime(expiration);
        request.setRequestTime(LocalDateTime.now());
        request.setStatus("PENDING");

        tempPrivilegeRepo.save(request);

        auditLogRepo.save(new AuditLog(
                currentUser,
                "JIT_REQUEST",
                "Requested privilege: " + sanitize(input.getPrivilegeType()),
                "SYSTEM"
        ));

        return Response.ok("{\"message\":\"JIT access request submitted\"}").build();
    }

    /* =====================================================
       LIST PENDING REQUESTS (ADMIN)
       ===================================================== */
    @GET
    @Path("/requests")
    @RolesAllowed({"ADMIN"})
    public Response getPendingRequests() {

        List<TemporaryPrivilege> pending = tempPrivilegeRepo.findAll()
                .stream()
                .filter(req -> "PENDING".equals(req.getStatus()))
                .toList();

        return Response.ok(pending).build();
    }

    /* =====================================================
       APPROVE JIT ACCESS
       ===================================================== */
    @POST
    @Path("/approve/{requestId}")
    @RolesAllowed({"ADMIN"})
    public Response approveJITAccess(@PathParam("requestId") Long requestId) {

        String approver = IdentityUtility.getCurrentUser();

        TemporaryPrivilege request = tempPrivilegeRepo.findById(requestId).orElse(null);
        if (request == null || !"PENDING".equals(request.getStatus())) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\":\"Request not found or already processed\"}")
                    .build();
        }

        request.setApproverId(approver);
        request.setApprovalTime(LocalDateTime.now());
        request.setStatus("APPROVED");

        tempPrivilegeRepo.save(request);

        auditLogRepo.save(new AuditLog(
                approver,
                "JIT_APPROVE",
                "Approved JIT for user: " + sanitize(request.getRequesterId()),
                "SYSTEM"
        ));

        return Response.ok("{\"message\":\"JIT access approved\"}").build();
    }

    /* =====================================================
       REVOKE JIT ACCESS
       ===================================================== */
    @POST
    @Path("/revoke/{requestId}")
    @RolesAllowed({"ADMIN"})
    public Response revokeJITAccess(@PathParam("requestId") Long requestId) {

        String revoker = IdentityUtility.getCurrentUser();

        TemporaryPrivilege request = tempPrivilegeRepo.findById(requestId).orElse(null);
        if (request == null || "REVOKED".equals(request.getStatus())) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\":\"Request not found\"}").build();
        }

        request.setStatus("REVOKED");
        tempPrivilegeRepo.save(request);

        auditLogRepo.save(new AuditLog(
                revoker,
                "JIT_REVOKE",
                "Revoked JIT for user: " + sanitize(request.getRequesterId()),
                "SYSTEM"
        ));

        return Response.ok("{\"message\":\"JIT access revoked\"}").build();
    }

    /* =====================================================
       VIEW MY ACTIVE JIT ACCESS
       ===================================================== */
    @GET
    @Path("/my-access")
    @RolesAllowed({"USER"})
    public Response getMyJITAccess() {

        String currentUser = IdentityUtility.getCurrentUser();
        LocalDateTime now = LocalDateTime.now();

        List<TemporaryPrivilege> myAccess = tempPrivilegeRepo.findAll()
                .stream()
                .filter(req ->
                        currentUser.equals(req.getRequesterId()) &&
                        "APPROVED".equals(req.getStatus()) &&
                        req.getExpirationTime() != null &&
                        now.isBefore(req.getExpirationTime())
                )
                .toList();

        return Response.ok(myAccess).build();
    }

    /* =====================================================
       UTILS
       ===================================================== */
    private String sanitize(String input) {
        return input == null ? "null" : input.replaceAll("[\\n\\r]", "_");
    }
}
