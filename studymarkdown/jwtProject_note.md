

# 1. 프로젝트 생성 및 테스트 컨트롤러 구현
### 1) Build.gradle 에 필요한 dependency 추가

```java
dependencies {  
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")  
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")  
    implementation("org.springframework.boot:spring-boot-starter-web")  
    implementation("org.springframework.boot:spring-boot-starter-security")  
    implementation("org.springframework.boot:spring-boot-starter-validation")  
  
    compileOnly("org.projectlombok:lombok")  
    developmentOnly("org.springframework.boot:spring-boot-devtools")  
    runtimeOnly("com.h2database:h2")  
    annotationProcessor("org.projectlombok:lombok")  
    testImplementation("org.springframework.boot:spring-boot-starter-test")  
  

```
<br>

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

<br>

### 3) Postman 으로 테스트
<img src="./images/Pasted image 20231129205716.png">

<br><br>
# 2. Security 과 Data 설정

<br>

### 1) 401 unauthorized 해결을 위한 Security 설정
#### - SecurityConfig.class 생성
```java
@Configuration  
@EnableWebSecurity   // 1. 웹 보안을 활성화 해주는 어노테이션 추가
public class SecurityConfig {  

	// 2. h2-console 과 favicon에 접근하는 건 security에 걸러지지않도록 설정
    @Bean  
    public WebSecurityCustomizer configure() {  
        
        return (web) -> web.ignoring()  
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**"))  
                .requestMatchers(new AntPathRequestMatcher("/favicon.ico"));  
    }  

    @Bean  
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {  
  
        httpSecurity  
                .authorizeHttpRequests((registry) ->  
                        registry.requestMatchers(  
                                new AntPathRequestMatcher("/api/hello"),   // 2. 입력된 url 만 접근 가능하도록 추가
                                new AntPathRequestMatcher("/api/authenticate"),  
                                new AntPathRequestMatcher("/api/signup")  
                                        )  
                                .permitAll()  
                                .anyRequest().authenticated()  
                );
                
                return httpSecurity.build();  
    }  
}
```

<br>



#### - application.yml 설정
```yml

spring:  
  # console 창 색상 변경 옵션  
  output:  
    ansi:  
      enabled: always  
      
  # Spring boot 실행 시점에 data.sql 수행하는 옵션  
  sql:  
    init:  
      mode: always  
  
  h2:  
    console:  
      enabled: true  
  
  datasource:  
    url: jdbc:h2:tcp://localhost/~/jwtProject  
    driver-class-name: org.h2.Driver  
    username: sa  
    password:  
  
  jpa:  
    database-platform: org.hibernate.dialect.H2Dialect  
    hibernate:  
      ddl-auto: create-drop  
    properties:  
      hibernate:  
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
    me.silvernine: DEBUG

```

<br>




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

<br>

#### - 테이블 관계도
* User <-> Authority :  N : N 으로 다대다 관계입니다. 이를 중간에 user_authority(조인테이블)을 이용해 (1:N - N:1) 관계로 정리
* <img src="./images/Pasted image 20231129213154.png">


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

<br>


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

<br><br>


#   3. JWT 코드, Security 설정 추가

<br>

## 1) JWT 설정 추가
#### - application.yml에 JWT 설정 추가

```yml

jwt:  
  header: Authorization  
  token-validity-in-seconds: 86400  
  
```
<br>

<img src="./images/Pasted image 20231130125421.png">

<br>

- #HS512 알고리즘을 사용할 것이기 때문에 512bit, 즉 64byte 이상의 secret key를 사용해야 합니다.
    - Secret 값은 터미널에서 특정 문자열을 Base64로 인코딩한 값 입니다.
- <img src="./images/Pasted image 20231130125836.png">
- #token-validity-in-seconds 은 86400초로 설정합니다.

<br>

#### - build.gradle에 JWT 관련 라이브러리 추가

```java

dependencies {
   // jwt 관련 라이브러리 추가
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")  
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.5")  
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.5")
    
    }  
```

<br>


## 2)  JWT 관련 코드 개발

<br>

### (1) `TokenProvider.class` : 토큰의 생성, 유효성 검증 등을 담당

* InitializingBean 을 상속받아 **afterPropertiesSet** 을 Override한 이유
    * 1) Bean 이 생성이 되고(Component Scan)
    * 2) 의존성 주입(생성자 주입)을 받은 후
    * 3) 주입받은 secret 값을 Base64 Decode해서 key 변수에 할당위함

<br>

```java
@Component  
public class TokenProvider implements InitializingBean { 

  private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);  
  
    private static final String AUTHORITIES_KEY = "auth"; 
  
    private final String secret;  
    private final long tokenValidityInMilliseconds;  
  
    private Key key;

	// 생성자 주입
    public TokenProvider(  
            @Value("${jwt.secret}") String secret,  
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInMilliseconds) {  
        this.secret = secret;  
        this.tokenValidityInMilliseconds = tokenValidityInMilliseconds * 1000;  
    }  


	@Override  
	    public void afterPropertiesSet() throws Exception {  
	        byte[] keyBytes = Decoders.BASE64.decode(secret);  
	        this.key = Keys.hmacShaKeyFor(keyBytes);  
	    }  
}
```

<br>

#### String creatToken(Authentication) 메서드 생성
- **Authentication 객체 정보를 받아  토큰을 생성** 하는 createToken 메서드 추가 (Authentication 객체 = Spring Security 에서 제공)
    - 1) Authentication 객체에서 부여된 권한을 스트림 API를 이용해서 한개의 문자열로 반환하도록 초기화
    - 2) application.yml에서 설정한 만료시간을 **token-validity-in-seconds** 메서드 시간에 더한후 setExpiration(validity) 에 입력
    - Jwts 토큰을 생성후 리턴

```java

    // Authentication 객체의 권한정보를 이용해 토큰을 생성하는 createToken 메서드 추가  
    public String createToken(Authentication authentication) {
  
        // authentication 초기화
        String authorities = authentication.getAuthorities().stream()  
                .map(GrantedAuthority::getAuthority)  
                .collect(Collectors.joining(","));  
  
        long now = (new Date()).getTime();  
  
        // application.yml 에서 정의한 token 만료 시간을 호출 시간 설정  
        Date validity = new Date(now + this.tokenValidityInMilliseconds);  
  
  
        // Jwt 토큰을 생성 후 리턴  
        return Jwts.builder()  
                .setSubject(authentication.getName())  
                .claim(AUTHORITIES_KEY, authorities)  
                .signWith(key, SignatureAlgorithm.HS512)  
                .setExpiration(validity)  
                .compact();  
  
  
  
    }  
```

<br>

#### Authentication getAuthentication(String token) 메서드 생성

* 토큰을 파라미터로 받아 Claim을 만들어줍니다.
* Claim에서 권한정보를 빼내 유저 객체를 생성(Principal)
* 유저 객체, 토큰, 권한정보를 갖는 Authentication 객체르 생성 후 반환

```java
public Authentication getAuthentication(String token) {  
  
    // 파라미터로 받아온 token을 이용해서 Claim 생성  
    Claims claims = Jwts  
            .parserBuilder()  
            .setSigningKey(key)  
            .build()  
            .parseClaimsJws(token)  
            .getBody();  
  
    // Claim에서 권한정보들을 빼냄  
    Collection<? extends GrantedAuthority> authorities =  
            Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))  
                .map(SimpleGrantedAuthority::new)  
                .collect(Collectors.toList());  
  
    // 빼낸 권한정보를 이용해 유저를 생성  
    User principal = new User(claims.getSubject(), "", authorities);  
  
    // 유저정보, 토큰, 권한정보를 가진 Authentication 객체 리턴  
    return new UsernamePasswordAuthenticationToken(principal, token, authorities);  
  
}
```
<br>

#### boolean validateToken(String token) 메서드 생성

- 토큰의 유효성 검증
- 토큰을 파싱하고 파싱중 발생하는 Exception() 을 캐치
- 문제가 있는 경우 false 반환, 업스면 true 반환

```java

public boolean validateToken(String token){  
    try {  
        Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);  
        return true;  
    } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {  
        logger.info("잘못된 JWT 서명입니다.");  
    } catch (ExpiredJwtException e){  
        logger.info("만료된 JWT 토큰입니다.");  
    } catch (UnsupportedJwtException e){  
        logger.info("지원되지 않는 JWT 토큰입니다.");  
    } catch (IllegalArgumentException e){  
        logger.info("JWT 토큰이 잘못되었습니다.");  
    }  
  
    return false;  
}

```
<br>

### (2) JwtFilter.class : customFilter for JWT

- **GenericFilterBean** 을 extends 해서 **doFilter()** 를 override 해줍니다.
- 앞서 구현한 TokenProvider를 주입받습니다.



```java  


public class JwtFilter extends GenericFilterBean {  
  
    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);  
  
    public static final String AUTHORIZATION_HEADER = "Authorization";  
  
    private TokenProvider tokenProvider;  
  
    public JwtFilter(TokenProvider tokenProvider) {  
        this.tokenProvider = tokenProvider;  
    }  
    
  @Override  
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) 
            throws IOException, ServletException {  
	 } 
    
}


```
<br>

#### void doFilter(ServletRequest, ServletResponse, FilterChain) 메서드 구현

- 필터링 로직은 **doFilter()** 안에 구현
    - doFilter() 역할 : 토큰의 인증정보(Authentication)를 SecurityContext에 저장하는 역할 수행

- ServletRequest 에서 토큰을 받아옵니다.
- 받아온 토큰을 tokenProvider.validateToken(jwt) 로 유효성 검증을 합니다.
- 토큰이 정상이라면 tokenProvider.getAuthentication(jwt) 로 토큰에서 Authentication 객체를  받아옵니다
- SecurityContextHolder.getContext().setAuthentication(authentication) 코드와 같이 Security Context에 받아온 Authentication을 저장해줍니다.

```java

  @Override  
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)  
            throws IOException, ServletException {  
  
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;  
  
        // Reques에서 토큰을 받아옴  
        String jwt = resolveToken(httpServletRequest);  
  
        String requestURI = httpServletRequest.getRequestURI();  
  
        // 받아온 jwt 토큰을 validateToken 메서드로 유효성 검증  
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {  
  
            // 토큰이 정상이라면 Authentication 객체를 받아옴  
            Authentication authentication = tokenProvider.getAuthentication(jwt);  
  
            // SecurityContext에 저장  
            SecurityContextHolder.getContext().setAuthentication(authentication);  
            logger.debug("Security Context에 '{}' 인증정보를 저장했습니다., uri: {}", authentication.getName(),  
                    requestURI);  
        } else {  
            logger.debug("유효한 JWT 토큰이 없습니다, uri : {}", requestURI);  
        }  
  
        filterChain.doFilter(servletRequest, servletResponse);  
  
    }
```
<br>


#### String resolveToken(HttpServletRequest request) 메서드 구현

- Request Header 에서 토큰 정보를 가져오기 위한 메서드

```java
  
    private String resolveToken(HttpServletRequest request) {  
  
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);  
  
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {  
            return bearerToken.substring(7);  
        }  
        return null;  
    }  
}
```

<br>


### (3) JwtSecurityConfig.class : SecurityConfig에 TokenProvider와 JwtFilter를 적용하기위한 클래스입니다.
- **SecurityConfigurerAdapter** 를 extends 받아 **configure()** override 합니다.
- TokenProvider 를 주입받습니다.
- **configure()** 에 new JwtFilter(tokenProvider) 를 통해 Security 로직에 해당 필터를 등록 합니다.

```java

public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {  
  
    private  TokenProvider tokenProvider;  
  
    // TokenProvider 생성자 주입  
    public JwtSecurityConfig(TokenProvider tokenProvider) {  
  
        this.tokenProvider = tokenProvider;  
    }  
  
    @Override  
    public void configure(HttpSecurity http) {  
  
        JwtFilter customFilter = new JwtFilter(tokenProvider);  
  
        // JwtFilter를 이용해 Spring Security 필터에 등록  
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);  
    }  
}
```

<br>

### (4) JwtAuthenticationEntiryPoint.class : 유효한 자격증명을 제공하지 않고, 접근하려할 때 401 Unauthorized 에러를 반환하는 클래스


```java
@Component  
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {  
  
    @Override  
    public void commence(HttpServletRequest request, HttpServletResponse response,  
            AuthenticationException authException) throws IOException, ServletException {  
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);  
    }  
}
```

- **AuthenticationEntryPoint**를 상속받아 **commence()** 메서드를 override 합니다.
    - **HttpServletResponse** 인터페이스의 **SC_UNAUTHORIZED(401)** 를 response.sendError()에 담습니다.



### (5) JwtAccessDeniedHandler.class :  필요한 권한이 없는 경우에 403 Forbidden 에러를 반환하는 클래스

```java
@Component  
public class JwtAccessDeniedHandler implements AccessDeniedHandler {  
  
    @Override  
    public void handle(HttpServletRequest request, HttpServletResponse response,  
            AccessDeniedException accessDeniedException) throws IOException, ServletException {  
        response.sendError(HttpServletResponse.SC_FORBIDDEN);  
    }  
}

```

- **AccessDeniedHandler**를 implements 받아 **handle()** 메서드를 @override 합니다.
    - **HttpServletResponse** 인터페이스의 **SC_FORBIDDEN(403)** 에러를 response.sendError()에 담습니다.

<br>


## 3) Jwt 관련 생성한 5개의 클래스를 Security Config 에 추가하기

<br>

### 1) SecurityConfig.class 수정

- @EnableMethodSecurity : @PreAuthorize 어노테이션을 메서드 단위로 추가히가위해 적용
- **TokenProvider, JwtAuthenticationEntryPoint, JwtAccessDeniedHandler** 의존성 주입
- PasswordEncoder는 **BCryptPasswordEncoder** 를 사용
- 토큰 사용을 위해서  **csrf설정을 disable 해줘야함**
- Exception 을 처리할 때 앞서 만들었던 **JwtAuthenticationEntryPoint**, **JwtAccessDeniedHandler** 클래스를 추가
- 로그인 API, 회원가입 API 토큰이 없는 상태에서 요청이 들어오기 때문에 모두 *permitAll()* 설정
- configure() 에서 HttpSecurity.addFilterBefore()로 JwtFilter(tokenProvider)를 등록했던 **JwtSecurityConfig** 설정 추가

```java

@Configuration  
@EnableWebSecurity  
@EnableMethodSecurity
public class SecurityConfig {  


    private final TokenProvider tokenProvider;  
    private final JwtAuthenticationEntryPoint   jwtAuthenticationEntryPoint;  
    private final JwtAccessDeniedHandler    jwtAccessDeniedHandler;  

	// 앞서 정의한 TokenProvider, JwtAuthenticationEntiryPoint, JwtAccessDeniedHandler 의존성 주입 받기
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
  
    @Bean  
    public WebSecurityCustomizer configure() {  
        return (web) -> web.ignoring()  
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**"))  
                .requestMatchers(new AntPathRequestMatcher("/favicon.ico"));  
    }  
  
    @Bean  
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {  
  
        httpSecurity  
                .csrf(AbstractHttpConfigurer::disable)  // csrf를 disable() 설정
  
                .exceptionHandling(
	                (handling) ->  // exceptionHandling 시 앞서 정의한 클래스를 추가
                        handling.authenticationEntryPoint(jwtAuthenticationEntryPoint)  
                                .accessDeniedHandler(jwtAccessDeniedHandler)  
                )  
				// H2-console 을 위한 설정 추가, 
                .headers((header) -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))  

				// 세션을 사용하지 안ㅇ힉 ㅒㄸ문에 STATELESSfh 설정
                .sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  
  
			  
                .authorizeHttpRequests((registry) ->  
                        registry.requestMatchers(  
  
                                new AntPathRequestMatcher("/api/hello"),  
                                new AntPathRequestMatcher("/api/authenticate"),  
                                new AntPathRequestMatcher("/api/signup")  
                                        )  
                                .permitAll()  
                                .anyRequest().authenticated()  
                )  
  
                .apply(new JwtSecurityConfig(tokenProvider));  // JwtSecurityConfig 설정 추가
  
  
                return httpSecurity.build();  
    }  
}


```


<br><br>



# 3. DTO, Repository, 로그인 구현

## 1) DTO 구현

### (1) LoginDto.class : 로그인 정보를 담을 Dto
- Validation을 위한 어노테이션 @NotNull, @Size 추가

```java

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

```

<br>

### (2) TokenDto.class : Token 정보를 Response 할 때 사용

```java

@Getter  
@AllArgsConstructor  
@NoArgsConstructor  
@Builder  
public class TokenDto {  

    private String token;  
    
}

```

<br>

### (3) UserDto.class : 회원가입 시 사용
```java

@Getter  
@ToString  
@RequiredArgsConstructor  
public class UserDto {  
  
    @NotNull  
    @Size(min = 3, max = 50)  
    private String username;  
  
  
    @JsonProperty(access = Access.WRITE_ONLY)  
    @NotNull  
    @Size(min = 3, max = 100)  
    private String password;  
  
    @NotNull  
    @Size(min = 3, max =50)  
    private String nickname;  
  
}

```

<br>

## 2) Repository 구현

### (1) UserRepository : User 엔티티에 매핑되는 레포지토리

- JpaRepository 를 extends 하면서 save, findAll 과 같은 메소드를 사용할 수 있습니다.
- `findOneWithAuthoritiesByUsername(String username)` : 유저명을 기준으로 User 가져오고 이때, 권한정보(authorities)도 같이 가져옵니다.
- @EntityGraph 어노테이션  : query 가 수행 될 때 Lazy 조회가 아닌 Eager 조회로 authorities 정보를 가져옵니다.

```java

public interface UserRepository extends JpaRepository<User, Long> {  
  
  
    // username 을 기준으로 User 정보를 가져올 권한정보도 같이 가져옴  
    @EntityGraph(attributePaths = "authorities") // 쿼리 수행 시 Lazy 조회가 아닌, Eager 조회로 authorities 정보를 같이가져옴  
    Optional<User> findOneWithAuthoritiesByUsername(String username);  
    
}
```

<br>

## 3) Service 구현

### (1) CustomUserDetailsService : SpringSecurity의 UserDetailsService를 인터페이스의  구현체
- UserDetailsService를 상속받고, **loadUserByUsername()** 메서드를 override 해 로그인 시 DB 에 유저정보와 권한정보를 가져오도록 구현합니다.
- 앞서 정의한 UserRepository 를 주입받습니다.
- 로그인 시 **DB 에서 유저정보와 권한정보를 가져오도록** **userRepository.findOneWithAuthritiesByUsername()** 메서드를 이용합니다.
- Stream map 을 통해 파라미터로 받은 **username** 과 DB에서 조회된 유저정보 **User**를 createUser()메서드를 이용해 **User** 엔티티를 생성해줍니다.

```java
  
@Component("userDetailsService")  
public class CustomUserDetailsService implements UserDetailsService {  
  
    private final UserRepository userRepository;  
  
    public CustomUserDetailsService(UserRepository userRepository) {  
        this.userRepository = userRepository;  
    }  
  
    @Override // UserDetailsService 클래스의 loadUserByUsername 오버라이딩  
    @Transactional  
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {  
        return userRepository.findOneWithAuthoritiesByUsername(username)// 로그인 시 DB 유저정보와 권한정보를 가져옴  
                .map(user -> createUser(username, user)) // 데이터베이스에서 가져온 정보를 기준으로 createUser 메서드 수행  
                .orElseThrow(()-> new UsernameNotFoundException(username + "-> 데이터베이스에서 찾을 수 없습니다."));  
    }  
  
    private org.springframework.security.core.userdetails.User createUser(String username,  
            User user) {  
        // DB 에서 가져온 유저가 활성화 상태가 아니라면  
        if (!user.isActivated()) {  
            throw new RuntimeException(username+ "-> 활성화되어 있지 않습니다.");  
        }  
        // 해당 유저가 활성화 상태라면  
        List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream() // getAuthorities() : 유저의 권한정보  
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName())) //  
                .collect(Collectors.toList());  
  
        return new org.springframework.security.core.userdetails.User(user.getUsername(),  // 유저명  
                user.getPassword(),  // 비밀번호를 가진  
                grantedAuthorities); // 유저 객체를 리턴  
    }  
  
  
}

```

<br>


## 4) 로그인 API 구현

### (1) AuthController : 권한 검증

- TokenProvider, AuthenticationManagerBuilder 를 주입받습니다.
- LoginDto를 이용해 username과 password를 받고 UsernamePasswordAuthenticationToken을 생성합니다.
- authenticationToken을 이용해서 authentication 객체를 생성하기 위해 authenticate 메서드가 실행될 때
    - CustomUserDetailsService 에서 구현한 loadUserByUsername 메서드가 실행되고 최종적으로 Authentication 객체가 생성됩니다.
- 생성된 Authentication 객체를 SecurityContext에 저장하고, Authentication 객체를  createToken 메서드를 통해  JWT Token을 생성합니다.
- 생성된 Jwt 토큰을 Response Header와 TokenDto(jwt)를 이용해 ResponseBody에도 넣어 반환합니다.

```java

@RestController  
@RequestMapping("/api")  
public class AuthController {  
  
    private final TokenProvider tokenProvider;  
    private final AuthenticationManagerBuilder authenticationManagerBuilder;  
  
    public AuthController(TokenProvider tokenProvider,  
            AuthenticationManagerBuilder authenticationManagerBuilder) {  
        this.tokenProvider = tokenProvider;  
        this.authenticationManagerBuilder = authenticationManagerBuilder;  
    }  
  
    @PostMapping("/authenticate")  
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {  

		// LoginDto를 이용해 username과 password를 받고 UsernamePasswordAuthenticationToken을 생성합니다.
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(  
                loginDto.getUsername(), loginDto.getPassword());  

		// authenticationToken을 이용해서 authentication 객체를 생성하기 위해 authenticate 메서드가 실행될 때, 
		// CustomUserDetailsService 에서 구현한 loadUserByUsername 메서드가 실행되고 최종적으로 Authentication 객체가 생성됩니다.
        Authentication authentication = authenticationManagerBuilder.getObject()  
                .authenticate(authenticationToken);  

		//  생성된 Authentication 객체를 SecurityContext에 저장합니다.
        SecurityContextHolder.getContext().setAuthentication(authentication);  

		//  Authentication 객체를  createToken 메서드를 통해  JWT Token을 생성합니다.
        String jwt = tokenProvider.createToken(authentication);  

		
        HttpHeaders httpHeaders = new HttpHeaders();  

		// 생성된 Jwt 토큰을 Response Header에 넣어줍니다.
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);  

		// TokenDto 를 이용해 ResponseBody 에도 넣어 리턴합니다.
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);  
    }  
}
```

<br>


# 4. Postman 으로 테스트

## 1. authenticate  POST 요청

- admin 계정정보는 처음 data.sql 의 insert 문이 서버가 시작될 때 자동 실행되어 DB에 저장된 상태입니다.
<img src="./images/Pasted image 20231202141719.png">


- ##### Postman 기능을 이용해 Response 데이터 전역변수에 저장해서 다른 Requests에서 사용할 수 있습니다.
<img src="./images/Pasted image 20231202142016.png">





# 4. 회원가입, 권한 검증

## 1) 회원가입 API 생성

### (1) SecurityUtil 클래스 생성 : 간단한 유틸리티 메서드 구현 클래스

**getCurrentUsername()** : SecurityContext의 Authentication 객체를 이용해 username을 반환하는 유틸성 메서드
    - SecurityContextHolder 에서 Authentication 객체를 꺼냄
    - authentication - getPrincipal() - getUsername() 순서대로 유저명을 꺼내 반환


```java

public class SecurityUtil {  
  
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);  
  
    private SecurityUtil() {  
    }  
  
    public static Optional<String> getCurrentUsername(){  
    
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();  
  
        if (authentication == null) {  
            logger.debug("Security Context에 인증 정보가 없습니다.");  
            return Optional.empty();  
        }  
  
        String username = null;  
        if (authentication.getPrincipal() instanceof UserDetails) {  
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();  
             username = springSecurityUser.getUsername();  
        } else if (authentication.getPrincipal() instanceof String) {  
            username = (String) authentication.getPrincipal();  
        }  
  
        return Optional.ofNullable(username);  
    }  
}

```

<br>

>
> SecurityContext 에 Authentication 객체가 저장되는 시점은 JwtFilter의 doFilter() 메서드에서 
> Redquest가 들어올 때 Authentication 객체를 저장해서 사용합니다.
>


```java
	public void doFilter(...){...}
		 SecurityContextHolder.getContext().setAuthentication(authentication);
	 }
	
```

<br>

### (2) UserService 클래스 생성 : 회원가입, 유저정보 조회 등 메서드 구현 클래스

- UserRepository, PasswordEncoder 를 주입받습니다.
- **signup()** 메서드는 회원가입 로직을 수행하는 메서드입니다.
    - username 이 DB에 저장돼있는지 확인합니다.
    - Authority와 User 정보를 생성해서 UserRepository의 save() 메서드를 통해 DB에 저장 후 User 를 반환합니다.
    - 회원가입된 User는 "ROLE_USER" 권한정보를 가지고 있습니다.
        -  data.sql에 생성되는 admin 계정은 "USER", "ADMIN_ROLE" 두개의 권한정보를 가지고 있습니다.
- **getUserWithAuthorities(String username), getMyUserWithAuthorities()** : 권한정보를 가져오는 메서드
    - **getUserWithAuthorities(String username)** : 어떠한  username이든 원하는 username 기준으로 정보(User, authorities)를 가져옵니다.
    - **getMyUserWithAuthorities()** : 현재 SecurityContext에 저장된 username에 해당하는  정보(User, authorities)만 가져옵니다.

```java
@Service  
public class UserService {  
  
    private final UserRepository userRepository;  
    private final PasswordEncoder passwordEncoder;  
  
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {  
        this.userRepository = userRepository;  
        this.passwordEncoder = passwordEncoder;  
    }  
  
    // 회원가입 로직 수행  
    @Transactional  
    public User signup(UserDto userDto) {  
  
        // UserDto의 username을 이용해 DB에 존재하는지 확인  
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null)  
                != null) {  
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");  
        }  
        // DB에 존재하지 않으면 권한정보 생성  
        Authority authority = Authority.builder().authorityName("ROLE_USER").build();  
  
        // 권한정보를 포함한 User 정보를 생성  
        User user = User.builder()  
                .username(userDto.getUsername())  
                .password(passwordEncoder.encode(userDto.getPassword()))  
                .nickname(userDto.getNickname())  
                .authorities(Collections.singleton(authority))  
                .activated(true)  
                .build();  
  
        // 최정 설정한 User 정보를 DB에 저장  
        return userRepository.save(user);  
    }  
  
    // 유저, 권한정보를 가져오는 메서드 1    // username을 기준으로 정보를 가져옴  
    @Transactional(readOnly = true)  
    public Optional<User> getUserWithAuthorities(String username) {  
        return userRepository.findOneWithAuthoritiesByUsername(username);  
    }  
  
    // 유저, 권한정보를 가져오는 메서드 2    // SecurityContext에 저장된 username 정보만 가져옴  
    @Transactional(readOnly = true)  
    public Optional<User> getMyUserWithAuthorities(){  
        return SecurityUtil.getCurrentUsername()  
                .flatMap(userRepository::findOneWithAuthoritiesByUsername);  
    }  
}
```
<br>


### (3) UserController : UserService 메서드를 호출

- **signup(@Valid @RequestBody UserDto userDto)** : 회원가입 수행
- **getMyUserInfo()**
    - @PreAuthorize("hasAnyRole('USER', 'ADMIN')") : 두 가지 권한을 모두 호출할 수 있습니다.
- **getUserInfo()**
    -  @PreAuthorize("hasAnyRole('ADMIN')")  :  ADMIN 권한만 호출할 수 있습니다.

```java

@RestController  
@RequestMapping("/api")  
public class UserController {  
  
    private final UserService userService;  
  
    public UserController(UserService userService) {  
        this.userService = userService;  
    }  
  
    // 회원가입  
    @PostMapping("/signup")  
    public ResponseEntity<User> signup(@Valid @RequestBody UserDto userDto) {  
        return ResponseEntity.ok(userService.signup(userDto));  
    }  
  
    @GetMapping("/user")  
    @PreAuthorize("hasAnyRole('USER','ADMIN')") // 두 권한을 호출할 수 있는 API    
    public ResponseEntity<User> getMyUserInfo() {  
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());  
    }  
  
    @GetMapping("/user/{username}")  
    @PreAuthorize("hasAnyRole('ADMIN')") // ADMIN 권한만 호출할 수 있는 API    
    public ResponseEntity<User> getUserInfo(@PathVariable String username) {  
        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());  
    }  
}
```



<br>


## 2) 검증

### (1) 회원가입 API 검증

- workflow
    - UserController.class - signup(@Valid @RequestBody UserDto userDto)
        - UserService
            - UserRepository - findOneWithAuthoritiesByUsername(userDto.getUsername()) : 기존 DB에 저장되어 있는지 검증
                -  Authority.builder().authorityName("ROLE_USER").build() : DB 에 없다면 권한정보 생성
            - User.builder()   : 유저 정보 생성 후 반환
              .username(userDto.getUsername())  
              .password(passwordEncoder.encode(userDto.getPassword()))  
              .nickname(userDto.getNickname())  
              .authorities(Collections.singleton(authority))  
              .activated(true)  
              .build();

<br>


#### - POSTMAN Request - Response 결과
<img src="./images/Pasted image 20231203135657.png">

<br>

#### - 권한 정보 및 유저정보 DB 저장 확인
<img src="./images/Pasted image 20231203142445.png">

<br>

### (2) 계정 권한에 따른 두 개의 API 검증

- authenticate Request 시 tests 탭에서 response 파싱을 통해 토큰 정보를 담아놓았떤 **jwt_tutorial_token** 변수를 Authorization - Bearer Token에 정의 [[#1. authenticate POST 요청]]
- 먼저 authenticate request 으로 받아온 토큰을 이용해 jskim 계정으로 새롭게 request 시 정상적으로 값을 반환 하는 것을 확인할 수 있습니다.
<img src="./images/Pasted image 20231203143756.png">
