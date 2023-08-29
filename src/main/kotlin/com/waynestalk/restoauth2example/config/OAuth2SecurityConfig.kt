package com.waynestalk.restoauth2example.config

import com.waynestalk.restoauth2example.auth.JWTValidatorFilter
import com.waynestalk.restoauth2example.auth.RestOAuth2AccessDeniedHandler
import com.waynestalk.restoauth2example.auth.RestOAuth2AuthenticationEntryPoint
import com.waynestalk.restoauth2example.auth.RestOAuth2AuthenticationFilter
import com.waynestalk.restoauth2example.constant.SecurityConstant
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

@Configuration
@Order(2)
class OAuth2SecurityConfig(
    private val jwtValidatorFilter: JWTValidatorFilter,
    private val restfulOAuth2AuthenticationFilter: RestOAuth2AuthenticationFilter
) : WebSecurityConfigurerAdapter() {

    val WHITELIST_PATH: Array<String> = arrayOf("/login/**","/register")

    override fun configure(http: HttpSecurity) {
        http
            .requestMatcher { t ->
                val auth = t.getHeader(HttpHeaders.AUTHORIZATION)
                auth?.startsWith(SecurityConstant.BEARER) == true
            }
            .csrf().disable()

            .addFilterBefore(jwtValidatorFilter, BasicAuthenticationFilter::class.java)
            .addFilterBefore(restfulOAuth2AuthenticationFilter, BasicAuthenticationFilter::class.java)

            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            .and()
            .authorizeRequests {
                it.antMatchers(*WHITELIST_PATH).permitAll()
            }

            .exceptionHandling()
            .authenticationEntryPoint(RestOAuth2AuthenticationEntryPoint())
            .accessDeniedHandler(RestOAuth2AccessDeniedHandler())

            .and()
            .authorizeRequests()
            .anyRequest().authenticated()
    }
}