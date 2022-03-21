package com.learningstuff.springmultiplesecurity.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by IntelliJ IDEA.
 * User: Md. Shamim
 * Email: mdshamim723@gmail.com
 * Date: ১৭/৩/২২
 * Time: ৩:৪৫ PM
 * To change this template use File | Settings | File and Code Templates.
 */

@RequestMapping(value = "/api/v1/courses")
@RestController
public class CourseControllerV1 {

    @GetMapping(value = "")
    public ResponseEntity<?> getAllCourser() {
        return ResponseEntity.ok("All courses from v1.");
    }

}
