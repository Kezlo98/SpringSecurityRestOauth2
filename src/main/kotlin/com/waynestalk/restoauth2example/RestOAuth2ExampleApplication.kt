package com.waynestalk.restoauth2example

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity

@SpringBootApplication
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class RestOAuth2ExampleApplication

fun main(args: Array<String>) {
    runApplication<RestOAuth2ExampleApplication>(*args)
}
