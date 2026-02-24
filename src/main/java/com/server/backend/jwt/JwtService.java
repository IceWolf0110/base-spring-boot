package com.server.backend.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String TOKEN_TYPE = "type";

    private static final String ACCESS_TOKEN_TYPE = "access";
    private static final String REFRESH_TOKEN_TYPE = "refresh";

    private final long accessExpiration = Duration.ofMinutes(5).toMillis();
    private final long refreshExpiration = Duration.ofMinutes(15).toMillis();

    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE, ACCESS_TOKEN_TYPE);
        return createToken(claims, userDetails, accessExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE, REFRESH_TOKEN_TYPE);
        return createToken(claims, userDetails, refreshExpiration);
    }

    private String createToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean isAccessToken(String token) {
        String type = extractClaim(token, claims -> claims.get(TOKEN_TYPE, String.class));
        return ACCESS_TOKEN_TYPE.equals(type);
    }

    public boolean isRefreshToken(String token) {
        String type = extractClaim(token, claims -> claims.get(TOKEN_TYPE, String.class));
        return REFRESH_TOKEN_TYPE.equals(type);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        return isTokenUsernameValid(token, userDetails) && !isTokenExpired(token);
    }

    public boolean isTokenUsernameValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername());
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        var keyBytes = Base64.getDecoder().decode(getSecretKey());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private String getSecretKey() {
        var key = System.getenv("JWT_SECRET_KEY");
        return Base64.getEncoder()
                .encodeToString(key.getBytes(StandardCharsets.UTF_8));
    }
}
