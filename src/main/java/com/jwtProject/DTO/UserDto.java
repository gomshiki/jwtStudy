package com.jwtProject.DTO;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@ToString
public class UserDto {

    private String userId;

    private String password;

    public UserDto(String userId, String password) {
        this.userId = userId;
        this.password = password;
    }
}
