package com.jwtProject.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloController {


    @GetMapping("/hello")
    public ResponseEntity<String> hello(){

        System.out.println("======= Hello RestController 들어옴 =======");
        return ResponseEntity.ok("hello");
    }

}
