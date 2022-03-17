package com.learningstuff.springmultiplesecurity.securities;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ১৭/৩/২২
 * Time: ৪:০৮ PM
 * To change this template use File | Settings | File and Code Templates.
 */

@Slf4j
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {


    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        log.error("Responding with unauthorized error. Message - {}", e.getMessage());

        httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpServletResponse.getOutputStream().println("Unauthenticated");

    }

}
