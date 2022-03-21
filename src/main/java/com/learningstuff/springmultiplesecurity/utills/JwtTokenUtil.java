package com.learningstuff.springmultiplesecurity.utills;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learningstuff.springmultiplesecurity.payloads.CustomPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.Date;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ১৭/৩/২২
 * Time: ৬:২২ PM
 * To change this template use File | Settings | File and Code Templates.
 */

@Slf4j
@AllArgsConstructor
public class JwtTokenUtil {

    public static String generateToken(CustomPrincipal principal) {

        Date issuedAt = new Date();
        Date expiryDate = calculateExpirationDate(86400000);

        return Jwts.builder()
                .claim("CURRENT_USER", principal)
                .setSubject(principal.getUsername())
                .setIssuedAt(issuedAt)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, "secret")
                .compact();
    }

    private static Date calculateExpirationDate(long expirationTime) {
        return new Date(System.currentTimeMillis() + expirationTime);
    }

    public static boolean isValidToken(String token) {
        return !StringUtils.isEmpty(token) && !isTokenExpired(token);
    }

    private static boolean isTokenExpired(String token) {
        return getExpirationDate(token).before(new Date());
    }

    private static Claims getAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey("secret")
                .parseClaimsJws(token)
                .getBody();
    }

    private static Date getExpirationDate(String token) {
        return getAllClaims(token).getExpiration();
    }

    public static String getUsername(String token) {
        return getAllClaims(token).getSubject();
    }

    public static CustomPrincipal getTokenHolderDetails(String token) {
        return new ObjectMapper().convertValue(getAllClaims(token).get("CURRENT_USER"), CustomPrincipal.class);
    }

}
