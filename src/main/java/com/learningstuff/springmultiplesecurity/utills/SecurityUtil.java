package com.learningstuff.springmultiplesecurity.utills;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Optional;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ২১/৩/২২
 * Time: ১০:১৫ AM
 * To change this template use File | Settings | File and Code Templates.
 */

@Slf4j
public class SecurityUtil {

    public static Optional<String> getTokenFromRequestHeader(HttpServletRequest request) {

        String header = request.getHeader("Authorization");

        log.info("Authorization bearer token: {}", header);

        if (StringUtils.isNotEmpty(header) && header.startsWith("Bearer ")) {
            return Optional.of(header.replace("Bearer ", ""));
        }

        log.error("Invalid bearer authorization token header.");
        return Optional.empty();
    }


    public static <T> UsernamePasswordAuthenticationToken getAuthentication(T user) {
        return new UsernamePasswordAuthenticationToken(
                user,
                null,
                new ArrayList<>()
        );
    }

}
