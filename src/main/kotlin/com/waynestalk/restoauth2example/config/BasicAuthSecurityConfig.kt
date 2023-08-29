package com.waynestalk.restoauth2example.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
class BasicAuthSecurityConfig(
) : WebSecurityConfigurerAdapter() {

    private val WHITELIST_PATH: Array<String> = arrayOf("/login/**","/register")

    override fun configure(http: HttpSecurity) {
        http
            .csrf().disable()

            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            .and()
            .authorizeRequests {
                it.antMatchers(*WHITELIST_PATH).permitAll()
            }
            .httpBasic().and()
            .formLogin().disable()
            .authorizeRequests()
            .anyRequest().authenticated()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder{
        return BCryptPasswordEncoder()
    }
}