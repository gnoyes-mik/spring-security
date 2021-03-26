# spring-security



## 목표

- Spring Security 작동 방식 이해
- Spring Security + JWT 를 이용한 로그인 서비스 구현
- Oauth2.0을 이용한 Social provider(Google, Naver, Kakao, Apple 등) 로그인 & 회원가입 서비스 구현

<br>

## 진행 사항

- H2 DB 연동 및 ORM(JPA)
- Account Entity에 대한 Create, Read, Update API
- Test 계정 생성을 위한 API( [Get] /test/create  요청 시 test 계정 생성)
- @ControllerAdvice를 이용한 GlobalExceptionHandler 및 Exception에 따른 Json 형태의 Response 
- Spring Security

    - JWT 토큰 기반 인증 방식을 사용해 API 요청 제한
    - JWT Filter 추가
    - Authorization 관련 Exception Handling [[ISSUE-02]](https://github.com/jeff-seyong/spring-security#issue02)
  
- Architecture 변경..[URL](https://github.com/jeff-seyong/dev-note/blob/main/spring/spring%20security/Spring%20Security%20Authentication%20Architecture.md)

<br>

## 개념

### Spring Security

Spring Security는 Spring 기반의 **<u>어플리케이션 보안(인증과 권한, 인가 등)을 담당</u>**하는 Spring 하위 프레임워크이다.

Spring Security는 Request에 대해서 '인증'과 '인가'를 담당하여 처리하는데 그 방식에는 적용 위치에 따라 2가지로 나뉜다.

- Interceptor 방식
  - Dispatcher Servlet과 Controller 사이에 위치하여 Request를 가로채어 처리
- Filter 방식
  - Application Filters에 Filter를 추가하여 Dispatcher Servlet에 도달하기 전에 처리하는 방식

<br>

### JWT(Json Web Token)

- 속성 정보 (Claim)를 JSON 데이터 구조로 표현한 토큰으로 RFC7519 표준

- 서버와 클라이언트 간 정보를 주고 받을 때 <u>HTTP 리퀘스트 헤더에 JSON 토큰을 넣은 후 서버는 별도의 인증 과정없이 헤더에 포함되어 있는 JWT 정보를 통해 인증</u>

<br>

### Spring Security + JWT 동작 방식

- Applications Filter에 JWT 필터를 추가하여 인증 인가를 처리하는 방식



1. 먼저, 클라이언트는 로그인 후 JWT Token을 발급 받는다.
2. 이 후 API를 요청할 때 헤더(x-auth-token)에 JWT Token 값을 넣어 요청을 하게 되는데
3. 잘못된 JWT token으로 접근할 경우 Filter에서 걸러지게되어 요청이 제한되고
4. 그렇지 않은 경우는 통과하여 해당 서버에 Resource를 요청할 수 있다.
5. 통과한 해당 유저는 SecurityContextHolder에 Authentication 객체 형태로 추가되어 인증된 유저로 등록된다



먼저, SecurityConfigurerAdapter를 상속받는 JWTConfigurer 클래스에 필터를 설정한 후

```java
@RequiredArgsConstructor
public class JWTConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final JwtAuthTokenProvider jwtAuthTokenProvider;
    
    @Override
    public void configure(HttpSecurity http) {
        JWTFilter customFilter = new JWTFilter(jwtAuthTokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

WebSecurityConfig 설정에서 필터를 사용할 것을 설정한다

```java
// ...
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
				// 생략 ...
                .and()
                .authorizeRequests()
                .antMatchers("/api/login", "/test/**", "/h2-console").permitAll()

                .antMatchers("/api/**").hasAnyAuthority(UserRole.NORMAL_USER.getRole())
                .anyRequest().authenticated()

            	// *********필터를 설정한다****************
                .and()
                .apply(securityConfigurerAdapter());
        		// **************************************
    }
    
    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(jwtAuthTokenProvider);
    }
}
```

이후 사용자의 모든 요청은 JWT 필터를 통과하게 된다

[JWT Filter](src/main/java/com/gnoyes/springsecurity/component/security/JWTFilter.java)에서는 doFilter라는 메소드를 오버라이딩하여 정의하는데 여기서 걸러주는 것은

ServletRequest의 Token이 담겨있는 헤더를 봤을 때,

- JWT의 signature가 유효한지
- JWT token이 유효한지
- 만료된 JWT는 아닌지
- 지원하지 않는 JWT는 아닌지
- JWT token의 속성값이 잘못된건 아닌지

를 판단하여, 잘못되었다면 Request Attribute에 해당 exception을 설정해준 뒤 JwtAuthenticationEntryPoint에서 처리를 한다

<br>

로그인 시 JWT를 발급해주는 과정은 다음과 같다.

먼저, JWTConfiguration을 통해 미리 정의해둔 secret key 기반으로 JwtAuthTokenProvider를 Bean으로 등록한다. secret key는 application.yml에 정의되어있다[[ISSUE-01]](https://github.com/jeff-seyong/spring-security#issue01)

```java
@Configuration
public class JwtConfiguration {

    @Value("$jwt.secret")
    private String secret;

    @Bean
    public JwtAuthTokenProvider JwtProvider(){
        return new JwtAuthTokenProvider(secret);
    }
}
```



Login이 성공하게되면 JwtAuthToeknProvider를 통해 Token을 생성하고 Login Request의 Response에 해당 Token을 담아 보내준다

```java
// AccountController.java
@RestController
@RequiredArgsConstructor
public class AccountController {
    final private AccountService accountService;

    @PostMapping("/api/login")
    public ResponseEntity<LoginSuccess> login(@RequestBody LoginRequestDto loginRequestDto) throws Exception {
        AccountDto accountDto = accountService.login(loginRequestDto.getUserName(), loginRequestDto.getPassword());

        JwtAuthToken jwtAuthToken = accountService.createAuthToken(accountDto);

        return new ResponseEntity<>(
                LoginSuccess.builder()
                        .userName(accountDto.getUserName())
                        .role(accountDto.getRole())
                        .message("Login Success")
                        .jwtAuthToken(jwtAuthToken.getToken())
                        .build()
                , HttpStatus.OK);
    }
}

// AccountService.java
@Service
@RequiredArgsConstructor
public class AccountService implements UserDetailsService {

    private final JwtAuthTokenProvider jwtAuthTokenProvider;

    private final static long LOGIN_RETENTION_MINUTES = 30;
    
    public JwtAuthToken createAuthToken(AccountDto accountDto) {
        Date expiredDate = Date
            .from(LocalDateTime.now().plusMinutes(LOGIN_RETENTION_MINUTES)
            .atZone(ZoneId.systemDefault())
            .toInstant());

        return jwtAuthTokenProvider.createAuthToken(accountDto.getUserName(),
                                                    accountDto.getRole(),
                                                    expiredDate);
    }
}

```

<br>
<br>


## Issue

### Issue01

#### JWT Secret Key Length

JWT Token을 생성할 때, 필요로하는 속성을 정의한 후 HMAC 알고리즘을 이용해 Token을 암호화 한다.

암호화 할때는 secret key  값이 필요한데 해당 프로젝트에서는 application.yml에 secret key 를 임의로 정의해 주었다.

하지만 다음과 같은 에러가 발생했다.

```text
 The specified key byte array is 88 bits which is not secure enough for any JWT HMAC-SHA algorithm.  The JWT JWA Specification (RFC 7518, Section 3.2) states that keys used with HMAC-SHA algorithms MUST have a size >= 256 bits (the key size must be greater than or equal to the hash output size).  Consider using the io.jsonwebtoken.security.Keys#secretKeyFor(SignatureAlgorithm) method to create a key guaranteed to be secure enough for your preferred HMAC-SHA algorithm.  See https://tools.ietf.org/html/rfc7518#section-3.2 for more information.
```

>지정된 key 바이트 배열은 88비트로 <u>JWT HMAC-SHA 알고리즘에 대해 충분히 안전하지 않다.</u>
>
>JWT JWA 사양(RFC 7518, 섹션 3.2)에는 HMAC-SHA 알고리즘에 사용되는 키의 크기가 = 256비트여야 한다고 명시되어 있습니다
>
><u>(키 크기는 해시 출력 크기보다 크거나 같아야 함).</u>



때문에 실제로 JWT를 사용할때는 secret key를 암호화 알고리즘 조건에 맞게 길게 설정해주어야 한다!

※ 해당 프로젝트는 스터디용 프로젝트이므로 임의로 정의한 secret key를 3배 늘려주었다..

```java
// application.yml
// jwt:
//   secret: SecretOfGnoyesIs20200121xxxxSecretOfGnoyesIs20200121
         
// JwtAuthTokenProvider.java
public class JwtAuthTokenProvider {
    @Getter
    private final Key key;
    
	public JwtAuthTokenProvider(String secret) {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < 3; i++) sb.append(secret);
      this.key = Keys.hmacShaKeyFor(sb.toString().getBytes());
  }
    // ...
}
```

<br>

### Issue02

#### Authorization 관련 Exception Handling

@ContorllerAdvice와 @ExceptionHandler를 이용하여 GlobalExceptionHandler를 만들고, 전역에서 발생하는 Exception을 핸들링을 하고 있었다.

그러나 AuthenticationEntryPoint를 구현해서 작성한 JwtAuthenticationEntryPoint에서 `throw new CustomException`을 발생 시켜도 GlobalExceptionHandler에서 이를 잡아내지 못하였다.

이유는 Authorization 관련 Exception 경우, Request가 DispatcherServlet에 도달하기 전에 Filter에서 발생하는 Exception이기 때문에 GlobalExceptionHandler에서 알아차릴 수 없었던 것이였다.

따라서 JwtFilter의 doFilter 메소드에서 try catch로 Exception을 걸러낸 뒤, servletRequest의 attirbute로 설정해주어 JwtAuthenticationEntryPoint에서 각 Exception을 핸들링 해주었다

```java
// JWTFilter.java

@Slf4j
public class JWTFilter extends GenericFilterBean {

    private static final String AUTHORIZATION_HEADER = "x-auth-token";
    private static final String AUTHORITIES_KEY = "role";

    private JwtAuthTokenProvider jwtAuthTokenProvider;

    JWTFilter(JwtAuthTokenProvider jwtAuthTokenProvider) {
        this.jwtAuthTokenProvider = jwtAuthTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String token = request.getHeader(AUTHORIZATION_HEADER);

        if (token != null) {
            JwtAuthToken jwtAuthToken = jwtAuthTokenProvider.convertAuthToken(token);

            Claims claims = null;

            try {
                claims = Jwts.parserBuilder().setSigningKey(jwtAuthTokenProvider.getKey()).build().parseClaimsJws(token).getBody();
            } catch (SecurityException e) {
                log.info("Invalid JWT signature.");
                request.setAttribute("exception", ErrorCode.INVALID_JWT_SIGNATURE.getCode());
            } catch (MalformedJwtException e) {
                log.info("Invalid JWT token.");
                request.setAttribute("exception", ErrorCode.INVALID_JWT_TOKEN.getCode());
            } catch (ExpiredJwtException e) {
                log.info("Expired JWT token.");
                request.setAttribute("exception", ErrorCode.EXPIRED_JWT_TOKEN.getCode());
            } catch (UnsupportedJwtException e) {
                log.info("Unsupported JWT token.");
                request.setAttribute("exception", ErrorCode.UNSUPPORTED_JWT_TOKEN.getCode());
            } catch (IllegalArgumentException e) {
                log.info("JWT token compact of handler are invalid.");
                request.setAttribute("exception", ErrorCode.ILLEGAL_ARGUMENT.getCode());
            }

            if (claims != null) {
                Authentication authentication = getAuthentication(jwtAuthToken, claims);

                // 인증 성공시 SecurityContext에 Authentication 객체를 추가해줌
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
```



```java
// JwtAuthenticationEntryPoint.java

@Slf4j
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        final String exception = (String) request.getAttribute("exception");

        log.error("[JwtAuthenticationEntryPoint] " + exception);

        if (ErrorCode.INVALID_JWT_SIGNATURE.getCode().equals(exception)) {
            setResponse(response, ErrorCode.INVALID_JWT_SIGNATURE);
        } else if (ErrorCode.INVALID_JWT_TOKEN.getCode().equals(exception)) {
            setResponse(response, ErrorCode.INVALID_JWT_TOKEN);
        } else if (ErrorCode.EXPIRED_JWT_TOKEN.getCode().equals(exception)) {
            setResponse(response, ErrorCode.EXPIRED_JWT_TOKEN);
        } else if (ErrorCode.UNSUPPORTED_JWT_TOKEN.getCode().equals(exception)) {
            setResponse(response, ErrorCode.UNSUPPORTED_JWT_TOKEN);
        } else if (ErrorCode.ILLEGAL_ARGUMENT.getCode().equals(exception)) {
            setResponse(response, ErrorCode.ILLEGAL_ARGUMENT);
        } else {
            setResponse(response, ErrorCode.AUTHENTICATION_FAILED);
        }


    }

    private void setResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code(errorCode.getCode())
                .status(errorCode.getStatus())
                .message(errorCode.getMessage())
                .build();

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().println(objectMapper.writeValueAsString(errorResponse));
    }
}
```





