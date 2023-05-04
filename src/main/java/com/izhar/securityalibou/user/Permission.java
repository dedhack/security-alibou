package com.izhar.securityalibou.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {

    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),

    MANAGER_READ("admin:read"),
    MANAGER_UPDATE("admin:update"),
    MANAGER_CREATE("admin:create"),
    MANAGER_DELETE("admin:delete")
    ;

    @Getter
    private final String permission;
}
