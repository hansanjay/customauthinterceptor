package com.tsd.auth.filter.service;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.tsd.sdk.request.Credentials;
import org.tsd.sdk.request.OTPDetails;
import org.tsd.sdk.response.AuthResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tsd.auth.filter.helper.SecurityHelper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;


@Service
public class CustomerAuthService {

	private static ConcurrentHashMap<String,OTPDetails> otpStorage = new ConcurrentHashMap<>();
	
	@Autowired
	private SecurityHelper helper;
	
	@Scheduled(fixedDelay = 60000L)
    public void clearExpiredOTPs() {
        otpStorage.forEach((key, value) -> {
            if (!value.getRequest().isValid()) {
                otpStorage.remove(key);
                System.out.println("Removed expired OTP for key: " + key);
            }
        });
    }
	
	public AuthResponse isAuthenticated(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String[] parts = authHeader.split(" ");
                if (parts.length != 2) {
                    return new AuthResponse(false, "Invalid Authorization header format");
                }

                String token = parts[1];
                Map<String, Object> claims = decodeJwtToken(token);

//                if (isTokenExpired(claims)) {
//                    return new AuthResponse(false, "Authentication Token Expired");
//                } else {
//                    
//                }
                Map<String, Object> user = (Map<String, Object>) claims.get("user");
                if (user != null) {
                    Long userId = (Long) user.get("id"); // Assuming `id` is of type Integer
                    // Uncomment and use dbHelper if needed:
                    // int id = dbHelper.isUserActive(userId);

                    request.setAttribute("_X_AUTH_ID", userId);
                    return new AuthResponse(true, "User session validated", claims.get("sub").toString());
                } else {
                    return new AuthResponse(false, 
                            String.format("User %s is not authorized to use this application.", user),
                            null);
                }
            } else {
                return new AuthResponse(false, "Authentication header not found in the request.");
            }
        } catch (Exception ex) {
            return new AuthResponse(false, "Invalid Authentication Token. " + ex.getMessage());
        }
    }
	
	public Claims decodeJwtToken(String jwtToken) {
        // Split the JWT token into parts
        String[] parts = jwtToken.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token format");
        }

        String payload = parts[1];
        String decodedPayload;

        // Decode the payload
        try {
            decodedPayload = new String(Base64.getUrlDecoder().decode(payload));
        } catch (IllegalArgumentException e) {
            // Add padding and retry
            decodedPayload = new String(Base64.getUrlDecoder().decode(payload + "=="));
        }

        // Parse the payload data
        Map<String, Object> payloadData;
        try {
            payloadData = new ObjectMapper().readValue(decodedPayload, Map.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse payload", e);
        }

        // Lookup credentials using the subject field from the payload
        String subject = payloadData.get("sub").toString();
        Credentials credentials = helper.lookupCredentials(subject);

        // Create the signing key
        Key key = Keys.hmacShaKeyFor(credentials.getClientSecret().getBytes());

        // Parse and verify the JWT
        return Jwts.parserBuilder()
                   .setSigningKey(key)
                   .build()
                   .parseClaimsJws(jwtToken)
                   .getBody();
    }
	
	private boolean isTokenExpired(Map<String, Object> claims) {
        Date issueDate = (Date) claims.get("iat");
        Date expiry = (Date) claims.get("expiry");
        if (expiry != null) {
            return expiry.before(new Date());
        } else if (issueDate != null) {
            LocalDateTime minus30Minutes = LocalDateTime.now().minus(30, ChronoUnit.MINUTES);
            Date minus30Date = Date.from(minus30Minutes.atZone(ZoneId.systemDefault()).toInstant());
            return issueDate.before(minus30Date);
        } else {
            return false;
        }
    }
	
}