package com.waynestalk.restoauth2example.config

import com.waynestalk.restoauth2example.repository.MemberRepository
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.stereotype.Component

@Component
class CustomAuthenticationProvider(
    private val memberRepository: MemberRepository,
    private val passwordEncoder: PasswordEncoder
): AuthenticationProvider {
    override fun authenticate(authentication: Authentication?): Authentication {
        if (authentication == null){
            throw BadCredentialsException("Invalid authentication!")
        }
        return when (authentication){
            is OAuth2AuthenticationToken  -> return authentication
            else -> authenticateBasicAuth(authentication)
        }

    }

    fun authenticateBasicAuth(authentication: Authentication): UsernamePasswordAuthenticationToken{
        val username = authentication.name;
        val pwd = authentication.credentials.toString()
        val customer = memberRepository.findByUserNameAndAndRegistrationId(username,"basic");
        if(customer != null){
            if(passwordEncoder.matches(pwd,customer.pwd)){
                return UsernamePasswordAuthenticationToken(username,pwd,getGrantedAuthorities(customer.authorities))
            }else {
                throw BadCredentialsException("Invalid Password!")
            }
        } else {
            throw BadCredentialsException("No user registered with this details!")
        }
    }

    fun getGrantedAuthorities(authorities: Collection<String>): List<GrantedAuthority>{
        val grantedAuthority = ArrayList<GrantedAuthority>()
        for (authority in authorities){
            grantedAuthority.add(SimpleGrantedAuthority(authority))
        }

        return grantedAuthority
    }

    override fun supports(authentication: Class<*>): Boolean {
        return UsernamePasswordAuthenticationToken::class.java.isAssignableFrom(authentication) ||
                OAuth2AuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}