package com.learningstuff.springmultiplesecurity.securities;

import com.learningstuff.springmultiplesecurity.payloads.CustomPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ১৭/৩/২২
 * Time: ৫:১৫ PM
 * To change this template use File | Settings | File and Code Templates.
 */

@Slf4j
public class APIKeyFilterRequest extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String apiKey = request.getHeader("api-key");

        log.info("API key authentication processing for {}", request.getRequestURL());

        // Once we get the token validate it.
        if (SecurityContextHolder.getContext().getAuthentication() == null && StringUtils.isNotEmpty(apiKey)) {

            log.info("Try to authenticate with API Key.");

            // if token is valid configure Spring Security to manually set
            // authentication
            if (apiKey.equals("84bfd081-28f4-44fd-81d7-311a5bce1ba4")) {

                CustomPrincipal customPrincipal = new CustomPrincipal();

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        customPrincipal, null, new ArrayList<>());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // After setting the Authentication in the context, we specify
                // that the current user is authenticated. So it passes the
                // Spring Security Configurations successfully.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                log.info("Successfully authenticate with API Key.");

            }
        }

        chain.doFilter(request, response);
    }

}
