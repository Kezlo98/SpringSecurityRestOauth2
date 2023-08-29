package com.waynestalk.restoauth2example.auth

import com.waynestalk.restoauth2example.repository.MemberRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Component

@Component
class MemberUserDetailsService(private val memberRepository: MemberRepository) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val member = memberRepository.findByUsername(username)
            ?: throw UsernameNotFoundException("$username was not found")

        val authority = member.authorities.map { SimpleGrantedAuthority(it) }
        return User(member.username, "", authority)
    }

    fun loadUserByUsernameAndPassword(username: String, pwd: String): UserDetails {
        val member = memberRepository.findByUsername(username)
            ?: throw UsernameNotFoundException("$username was not found")

        if (member.pwd?.equals(pwd) != true) {
            throw UsernameNotFoundException("Password for $username was incorrect")
        }

        val authority = member.authorities.map { SimpleGrantedAuthority(it) }
        return User(member.username, "", authority)
    }

    fun loadUserByUsernameAndRegistrationId(username: String, registrationId: String): UserDetails {
        val member = memberRepository.findByUserNameAndAndRegistrationId(username, registrationId)
            ?: throw UsernameNotFoundException("$username and $registrationId was not found")

        val authority = member.authorities.map { SimpleGrantedAuthority(it) }
        return User(member.username, "", authority)
    }
}