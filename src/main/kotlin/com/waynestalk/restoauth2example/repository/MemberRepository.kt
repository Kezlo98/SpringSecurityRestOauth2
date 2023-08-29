package com.waynestalk.restoauth2example.repository

import com.waynestalk.restoauth2example.model.Member
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query

interface MemberRepository : JpaRepository<Member, Long> {
    @Query("SELECT m FROM Member m JOIN FETCH m.authorities WHERE m.username = (:username)")
    fun findByUsername(username: String): Member?

    @Query("SELECT m FROM Member m JOIN FETCH m.authorities WHERE m.username = (:username) and m.registrationId = (:registrationId)")
    fun findByUserNameAndAndRegistrationId(username: String, registrationId: String): Member?
}