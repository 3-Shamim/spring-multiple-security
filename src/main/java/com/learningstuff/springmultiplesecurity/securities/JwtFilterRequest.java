package com.learningstuff.springmultiplesecurity.securities;

import com.learningstuff.springmultiplesecurity.payloads.CustomPrincipal;
import com.learningstuff.springmultiplesecurity.utills.JwtTokenUtil;
import com.learningstuff.springmultiplesecurity.utills.SecurityUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ১৭/৩/২২
 * Time: ৫:১৫ PM
 * To change this template use File | Settings | File and Code Templates.
 */

@Slf4j
public class JwtFilterRequest extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        log.info("Bearer token authentication processing for {}", request.getRequestURL());

        SecurityUtil.getTokenFromRequestHeader(request).ifPresent(token -> {

            try {

                if (JwtTokenUtil.isValidToken(token)) {
                    if (SecurityContextHolder.getContext().getAuthentication() == null) {

                        CustomPrincipal customPrincipal = JwtTokenUtil.getTokenHolderDetails(token);

                        if (customPrincipal != null) {
                            UsernamePasswordAuthenticationToken authentication = SecurityUtil.getAuthentication(customPrincipal);
                            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(authentication);

                            log.info("Successfully authenticate with bearer token.");
                        }

                    }
                }

            } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException | ExpiredJwtException e) {
                log.error(e.getMessage());
            }

        });

        chain.doFilter(request, response);
    }

}
