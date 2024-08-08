 import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class LoginApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginApiApplication.class, args);
    }
}

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import javax.validation.Valid;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class LoginController {

    @Autowired
    private UserDetailsService userDetailsService;

    @PostMapping("/login")
    @Secured("ROLE_USER")
    public ResponseEntity<?> login(@Valid @RequestBody Map<String, String> userCredentials) {
        // Validate user input
        if (userCredentials == null || userCredentials.isEmpty() ||
                userCredentials.get("username") == null || userCredentials.get("password") == null) {
            return new ResponseEntity<>("Invalid request", HttpStatus.BAD_REQUEST);
        }

        try {
            // Authenticate user
            String username = userCredentials.get("username");
            String password = userCredentials.get("password");
            Authentication authentication = userDetailsService.loadUserByUsername(username)
                .map(user -> new UsernamePasswordAuthenticationToken(user, password))
                .orElseThrow(() -> new UsernameNotFoundException(username));

            // Set authentication in SecurityContextHolder
            SecurityContextHolder.getContext().setAuthentication(authentication);

            return new ResponseEntity<>("Login successful", HttpStatus.OK);
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>("Invalid username or password", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            // Log the exception
            // e.g. logger.error("Error while authenticating user", e);
            return new ResponseEntity<>("Internal Server Error", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}