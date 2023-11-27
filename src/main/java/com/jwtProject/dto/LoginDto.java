package com.jwtProject.dto;


import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginDto {

    @NotNull    // Validation 어노테이션
    @Size(min = 3, max = 50) // Validation 어노테이션
    private String username;

    @NotNull
    @Size(min = 3, max = 100)
    private String password;
}
