package com.jwtProject.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;


/**
 * Token 정보를 Response 할 때 사용
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenDto {
    private String token;
}
