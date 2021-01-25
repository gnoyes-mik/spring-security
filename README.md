# spring-security



## 목표

- Spring Security 작동 방식 이해
- Spring Security + JWT 를 이용한 로그인 서비스 구현
- Oauth2.0을 이용한 Social provider(Google, Naver, Kakao, Apple 등) 로그인 & 회원가입 서비스 구현



## 진행 사항

- H2 DB 연동 및 ORM(JPA)
- Account Entity에 대한 Create, Read, Update API
- Test 계정 생성을 위한 API( [Get] /test/create  요청 시 test 계정 생성)
- @ControllerAdvice를 이용한 GlobalExceptionHandler 및 Exception에 따른 Json 형태의 Response 
- Spring Security

    - JWT 토큰 기반 인증 방식을 사용해 API 요청 제한
    - JWT Filter 추가
    - Authorization 관련 Exception Handling [[ ISSUE-02 ]](###[ISSUE-02]-Authorization-관련-Exception-Handling-Issue)
    - 



## 개념

### Spring Security

Spring Security는 Spring 기반의 **<u>어플리케이션 보안(인증과 권한, 인가 등)을 담당</u>**하는 Spring 하위 프레임워크이다.

Spring Security는 Request에 대해서 '인증'과 '인가'를 담당하여 처리하는데 그 방식에는 적용 위치에 따라 2가지로 나뉜다.

- Interceptor 방식
  - Dispatcher Servlet과 Controller 사이에 위치하여 Request를 가로채어 처리
- Filter 방식
  - Application Filters에 Filter를 추가하여 Dispatcher Servlet에 도달하기 전에 처리하는 방식



### JWT(Java Web Token)



### Spring Security + JWT 작동 방식





## 개발 이슈

### [ISSUE-01] JWT Secret Key Length



### [ISSUE-02] Authorization 관련 Exception Handling Issue

