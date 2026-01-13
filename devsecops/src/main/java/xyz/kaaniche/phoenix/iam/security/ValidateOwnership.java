package xyz.kaaniche.phoenix.iam.security;

import jakarta.ws.rs.NameBinding;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@NameBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface ValidateOwnership {
    /**
     * Index of the path parameter containing the user ID (0-based)
     */
    int userIdParamIndex() default -1;

    /**
     * Name of the query parameter containing the user ID
     */
    String userIdQueryParam() default "";

    /**
     * Name of the JWT claim containing the resource owner ID
     */
    String extractFromJwtClaim() default "";
}
