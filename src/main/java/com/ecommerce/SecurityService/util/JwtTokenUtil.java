package com.ecommerce.SecurityService.util;

import com.ecommerce.SecurityService.repository.entity.JwtUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -3301605591108950415L;
    private static final String TYPE = "type";

    private Clock clock = DefaultClock.INSTANCE;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration.minutes:10}")
    private Long expiration;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public String getTokenType(String token) {
        return getClaimFromToken(token, claims -> claims.get(TYPE, String.class));
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
            .setSigningKey(secret)
            .parseClaimsJws(token)
            .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(clock.now());
    }

    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    public String generateAuthToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(TYPE, TokenType.AUTH.name());

        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDateAuthToken(createdDate);

        return doGenerateToken(claims, userDetails.getUsername(), createdDate, expirationDate);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(TYPE, TokenType.REFRESH.name());

        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDateRefreshToken(createdDate);

        return doGenerateToken(claims, userDetails.getUsername(), createdDate, expirationDate);
    }

    private String doGenerateToken(Map<String, Object> claims, String subject, Date createdDate, Date expirationDate) {

        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setIssuedAt(createdDate)
            .setExpiration(expirationDate)
            .signWith(SignatureAlgorithm.HS512, secret)
            .compact();
    }

    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getIssuedAtDateFromToken(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
            && (!isTokenExpired(token));
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        JwtUser user = (JwtUser) userDetails;
        final String username = getUsernameFromToken(token);
        final Date created = getIssuedAtDateFromToken(token);
        return (
            username.equals(user.getUsername())
                && !isTokenExpired(token)
                && !isCreatedBeforeLastPasswordReset(created, new Date(Long.parseLong(user.getLastPasswordResetDate())))
        );
    }

    private Date calculateExpirationDateAuthToken(Date createdDate) {
        return new Date(createdDate.getTime() + expiration * 60000);
    }

    /**
     * Refresh token valid for 4 time more time than auth token
     * e.g. if auth token is valid for 10 min, refresh token will be valid for 30 min
     */
    private Date calculateExpirationDateRefreshToken(Date createdDate) {
        return new Date(createdDate.getTime() + expiration * 3 * 60000);
    }
}
