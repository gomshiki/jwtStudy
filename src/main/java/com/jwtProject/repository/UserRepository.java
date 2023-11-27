package com.jwtProject.repository;

import com.jwtProject.domain.User;
import com.jwtProject.dto.UserDto;
import jakarta.persistence.Entity;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {


    // username 을 기준으로 User 정보를 가져올 권한정보도 같이 가져옴
    @EntityGraph(attributePaths = "authorities") // 쿼리 수행 시 Lazy 조회가 아닌, Eager 조회로 authorities 정보를 같이 가져옴
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}
