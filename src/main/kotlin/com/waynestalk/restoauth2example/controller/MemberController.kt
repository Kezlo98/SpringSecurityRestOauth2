package com.waynestalk.restoauth2example.controller

import com.waynestalk.restoauth2example.auth.TokenManager
import com.waynestalk.restoauth2example.model.Member
import com.waynestalk.restoauth2example.repository.MemberRepository
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.security.Principal
import javax.servlet.http.HttpServletRequest

@RestController
class MemberController(
    private val authorizedClientRepository: OAuth2AuthorizedClientRepository,
    private val tokenManager: TokenManager,
    private val passwordEncoder: PasswordEncoder,
    private val memberRepository: MemberRepository
) {
    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    fun user(principal: Principal): UserResponse {
        return when(principal){
            is OAuth2AuthenticationToken -> UserResponse(
                tokenManager.getUserName(
                    principal.principal.attributes,
                    principal.authorizedClientRegistrationId
                ),
                principal.principal.attributes["name"] as String
            )
            else -> UserResponse(principal.name,"")
        }
    }

    data class UserResponse(val email: String, val name: String)

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    fun admin(principal: Principal, request: HttpServletRequest): AdminResponse {
        val authentication = principal as OAuth2AuthenticationToken
        val authorizedClient = authorizedClientRepository.loadAuthorizedClient<OAuth2AuthorizedClient>(
            authentication.authorizedClientRegistrationId,
            authentication,
            request
        )
        return AdminResponse(
            tokenManager.getUserName(
                authentication.principal.attributes,
                authentication.authorizedClientRegistrationId
            ),
            authentication.principal.attributes["name"] as String,
            authorizedClient.accessToken.tokenValue,
            authorizedClient.refreshToken?.tokenValue ?: ""
        )
    }

    data class AdminResponse(val email: String, val name: String, val accessToken: String, val refreshToken: String)

    @PostMapping("/register")
    fun registerUser(@RequestBody member: Member): ResponseEntity<String> {
        return try {
            member.pwd = passwordEncoder.encode(member.pwd)
            member.registrationId = "basic"
            val savedCustomer = memberRepository.save(member)
            ResponseEntity("Given user details are successfully registered", HttpStatus.OK)

        } catch (ex: Exception) {
            ResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR)
        }
    }
}