package com.learningstuff.springmultiplesecurity.controllers;

import com.learningstuff.springmultiplesecurity.payloads.CustomPrincipal;
import com.learningstuff.springmultiplesecurity.payloads.LoginRequest;
import com.learningstuff.springmultiplesecurity.utills.JwtTokenUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ১৭/৩/২২
 * Time: ৬:১৩ PM
 * To change this template use File | Settings | File and Code Templates.
 */

@RequestMapping(value = "")
@RestController
public class SecurityController {

    @PostMapping(value = "/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {

        if ("admin".equals(loginRequest.getUsername()) && "pass".equals(loginRequest.getPassword())) {

            String token = JwtTokenUtil.generateToken(new CustomPrincipal(loginRequest.getUsername()));

            return ResponseEntity.ok(token);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Username and password are incorrect.");
    }

}
