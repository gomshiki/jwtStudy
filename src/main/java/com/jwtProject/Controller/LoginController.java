package com.jwtProject.Controller;

import com.jwtProject.DTO.UserDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class LoginController {

    @PostMapping("/login")
    public String doLogin(UserDto userDto){

        System.out.println("userDto = " + userDto.toString());

        return null;

    }
}
