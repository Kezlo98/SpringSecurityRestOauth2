package com.waynestalk.restoauth2example.model

import javax.persistence.*

@Entity
data class Member(
    @Column(unique = true) val username: String,
    var registrationId: String? = "basic",
    val name: String,
    @ElementCollection val authorities: Collection<String>,
    var pwd: String? = null,
    @Id @GeneratedValue var id: Long? = null
)