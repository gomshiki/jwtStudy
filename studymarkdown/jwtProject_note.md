# Spring Security를 이용해 JWT 로그인구현해보기


# 1. 프로젝트 생성 및 테스트 컨트롤러 구현
### 1) Build.gradle 에 필요한 dependency 추가

```java
dependencies {  
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")  
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")  
    implementation("org.springframework.boot:spring-boot-starter-web")  
    implementation("org.springframework.boot:spring-boot-starter-security")  
    implementation("org.springframework.boot:spring-boot-starter-validation")  
  

    // jwt 관련 디펜던시 추가
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")  
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.5")  
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.5")  
  
    compileOnly("org.projectlombok:lombok")  
    developmentOnly("org.springframework.boot:spring-boot-devtools")  
    runtimeOnly("com.h2database:h2")  
    annotationProcessor("org.projectlombok:lombok")  
    testImplementation("org.springframework.boot:spring-boot-starter-test")  
  

```


### 2) 테스트용 controller 생성
```java
@RestController  
@RequestMapping("/api")  
public class HelloController {  

    @GetMapping("/hello")  
    public ResponseEntity<String> hello(){  
   
        return ResponseEntity.ok("hello");  
    }  
  
}
```



### 3) Postman 으로 테스트
![[Pasted image 20231129205716.png]]






# 2. Security 과 Data 설정
### 1) 401 unauthorized 해결을 위한 Security 설정
#### - SecurityConfig.class 생성
```java
@Configuration  
@EnableWebSecurity  
@EnableMethodSecurity // 1. 웹 보안을 활성화 해주는 어노테이션 추가
public class SecurityConfig {  
     /** 
     1-1. WebSecuirityConfigureAdapter 를 extends 받아 Configure를 구현해야하나 
         Spring Security가 업데이트되면서 비권장하게 돼어 직접 메서드를 구현
     */
    private final TokenProvider tokenProvider;  
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;  
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;  

	// 생성자 주입 반기
    public SecurityConfig(TokenProvider tokenProvider,  
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,  
            JwtAccessDeniedHandler jwtAccessDeniedHandler) {  
        this.tokenProvider = tokenProvider;  
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;  
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;  
    }  
  
    @Bean  
    public PasswordEncoder  passwordEncoder(){  
        return new BCryptPasswordEncoder();  
    }  

	// 3. h2-console 및 favicon 하위 요청은 Security에 의해 걸러지지 않는 코드
    @Bean  
    public WebSecurityCustomizer configure() {  
        
        return (web) -> web.ignoring()  
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**"))  
                .requestMatchers(new AntPathRequestMatcher("/favicon.ico"));  
    }  

    @Bean  
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {  
  
        httpSecurity  
                .csrf(AbstractHttpConfigurer::disable)  
                .exceptionHandling((handling) ->  
                        handling.authenticationEntryPoint(jwtAuthenticationEntryPoint)  
                                .accessDeniedHandler(jwtAccessDeniedHandler)  
                )  
                .headers((header) -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))  
                .sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  
                .authorizeHttpRequests((registry) ->  
                        registry.requestMatchers(  
                                new AntPathRequestMatcher("/api/hello"),   // 2. 입력된 url 만 접근 가능하도록 추가
                                new AntPathRequestMatcher("/api/authenticate"),  
                                new AntPathRequestMatcher("/api/signup")  
                                        )  
                                .permitAll()  
                                .anyRequest().authenticated()  
                )  
                .apply(new JwtSecurityConfig(tokenProvider));  
                return httpSecurity.build();  
    }  
}
```




#### - application.yml 설정
```yml

spring:  
  
  h2:  
    console:  
      enabled: true  
  
  datasource:  
    url: jdbc:h2:mem:testdb  
    driver-class-name: org.h2.Driver  
    username: sa  
    password:  
  
  jpa:  
    database-platform: org.hibernate.dialect.H2Dialect  
    hibernate:  
      ddl-auto: create-drop   # SessionFactory가 시작될 때 Drop, Create, Alter 를 진행하고, 종료될때 Drop을 진행
    properties:  
      hibernate:  # 콘솔창에서 sql을 보기좋게 해주는 설정을 추가
        format_sql: true  
        show_sql: true  
    defer-datasource-initialization: true  
  
jwt:  
  header: Authorization  
  #HS512 알고리즘을 사용할 것이기 때문에 512bit, 즉 64byte 이상의 secret key를 사용해야 한다.  
  #echo 'silvernine-tech-spring-boot-jwt-tutorial-secret-silvernine-tech-spring-boot-jwt-tutorial-secret'|base64  secret: c2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQtc2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQK  
  token-validity-in-seconds: 86400  
  
logging:  
  level:  
    me.silvernine: DEBUG # 로깅레벨을 디버그로 설정

```





#### - Entity 추가 - User.class, Authority.class

```java
@Entity  
@Table(name = "users") // h2 데이터베이스에 user는 예약어로 지정되어 있어 user명 사용 불가함  
@AllArgsConstructor  
@Getter  
@NoArgsConstructor  
@Builder  
public class User {  
  
    @JsonIgnore  
    @Id    
    @Column(name = "user_id")  
    @GeneratedValue(strategy = GenerationType.IDENTITY)  // 자동증가
    private Long userId;  
    
    @Column(name = "username", length = 50, unique = true)  
    private String username;  
    
    @JsonIgnore  
    @Column(name = "password", length = 100)  
    private String password;  
    
    @Column(name = "nickname", length = 50)  
    private String nickname;  
    
    @JsonIgnore  
    @Column(name = "activated")  
    private boolean activated;  
    
    @ManyToMany  // 다대다 관계를 중간에 user_authority 조인 테이블을 만들어 1:N - N:1 로 정리
    @JoinTable(  
            name = "user_authority",  
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "user_id")},  
            inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName ="authority_name")}  
    )  
    
    private Set<Authority> authorities;  
  
}
```



#### - 테이블 관계도
* User <-> Authority :  N : N 으로 다대다 관계입니다. 이를 중간에 user_authority(조인테이블)을 이용해 (1:N - N:1) 관계로 정리

![[Pasted image 20231129213154.png]]



```java
@Entity  
@Table(name = "authority")  
@Getter  
@Builder  
@AllArgsConstructor  
@NoArgsConstructor  
public class Authority {  
  
    @Id  
    @Column(name = "authority_name", length = 50)  
    private String authorityName;  // 권한명
    
}
```


#### - 쿼리문 작성(data.sql)
* 아래 쿼리는 스프링 부트 실행할때 마다 실행됩니다.
```sql
insert into "USERS" (username, password, nickname, activated) values ('admin', '$2a$08$lDnHPz7eUkSi6ao14Twuau08mzhWrL4kyZGGU5xfiGALO/Vxd5DOi', 'admin', 1);  
insert into "USERS" (username, password, nickname, activated) values ('user', '$2a$08$UkVvwpULis18S19S5pZFn.YHPZt3oaqHZnDwqbCW9pft6uFtkXKDC', 'user', 1);  
  
insert into authority (authority_name) values ('ROLE_USER');  
insert into authority (authority_name) values ('ROLE_ADMIN');  
  
insert into user_authority (user_id, authority_name) values (1, 'ROLE_USER');  
insert into user_authority (user_id, authority_name) values (1, 'ROLE_ADMIN');  
insert into user_authority (user_id, authority_name) values (2, 'ROLE_USER');
```