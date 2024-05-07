package com.ggomg.project.base.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class HelloController {

    @GetMapping("/hello")
    public ResponseEntity<Object> health() {
        return ResponseEntity.status(HttpStatus.OK).body("hello");
    }

    @GetMapping("/token/hello")
    public ResponseEntity<Object> health2() {
        return ResponseEntity.status(HttpStatus.OK).body("hello");
    }
}
