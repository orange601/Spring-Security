# Spring-Security
:leaves: Spring-Security 안전하게 사용하기
- https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter

## CORS 정책 ##
- 아래는 [모질라 문서](https://developer.mozilla.org/ko/docs/Web/HTTP/CORS) 내용이다.
- CORS란 HTTP헤더에 기반한 매카니즘이다. 
- 서버가 다른 origin의 브라우저에게자신의 자원이 로드될 수 있도록 헤더에 표시해주는 방법이다. 
- 이 과정을 위해 브라우저는 preflight요청을먼저 보내 자신이 요청할 수 있는 메소드와 origin을 확인한다. 
- 또한 axios와 같이 XMLHttpRequest를 사용한다면 기본적으로 same-origin에 대해서만 브라우저가 올바른 서버로 간주하기 때문에 Access-Control-Allow-Origin헤더가 적절하게 set되어 있어야 한다. 


## @EnableWebSecurity ##
1. Spring Boot 를 사용하고 있을 경우 SecurityAutoConfiguration 에서 import 되는 WebSecurityEnablerConfiguration 에 의해 자동으로 세팅 되므로 추가하지 않아도 된다.

## WebSecurityConfigurerAdapter ##
1. 5.7.X 부터 WebSecurityConfigurerAdapter Deprecate
    - 현재 Spring Boot 2.6.7 기준 Spring Security 5.6.3 을 사용하고 있지만 추후 5.7.X 부터 WebSecurityConfigurerAdapter 가 Deprecate 될 예정

2. WebSecurityConfigurerAdapter 를 상속받지 않고 적용
    - SecurityFilterChain 를 Bean 으로 선언하는 방법
    - 이때 HttpSecurity 를 주입받아 사용
````java
@Configuration
public class SecurityConfig {

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web.ignoring().antMatchers("/resources/**");
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf().disable()
        .headers()
          .frameOptions().disable().and()
        .authorizeRequests()
          .antMatchers("/user/**").hasRole("USER")
          .anyRequest().authenticated().and()
        .formLogin()
          .loginPage("/user/login").permitAll()
          .defaultSuccessUrl("/index").and()
        .logout()
          .logoutUrl("/user/logout").and()
        .build();
  }

}
````

## ant pattern 을 이용한 ignore 처리 권장되지 않음 ##
    - WARN 로그가 발생
    - 이 로그는 Spring Security 5.5.x 에 추가되었다.
    - 추가로 리소스에 대해서 SecurityContext 를 세션에서 찾는것을 방지하여 성능 최적화 방법을 유지하려면 Resource 용 SecurityFilterChain 을 추가하는 방법을 제시

1. Resource 용 SecurityFilterChain 적용
    - WebSecurityCustomizer 설정을 제거하며 @Order(0)을 추가하여 먼저 FilterChain을 타도록 지정
    - resources(css, js 등) 의 경우 securityContext 등에 대한 조회가 불필요 하므로 disable
````java
@Bean
@Order(0)
public SecurityFilterChain resources(HttpSecurity http) throws Exception {
  return http.requestMatchers(matchers -> matchers
      .antMatchers("/resources/**"))
    .authorizeHttpRequests(authorize -> authorize
      .anyRequest().permitAll())
    .requestCache(RequestCacheConfigurer::disable)
    .securityContext(AbstractHttpConfigurer::disable)
    .sessionManagement(AbstractHttpConfigurer::disable)
    .build();
}
````


### 개념 공부하기 ###
- https://velog.io/@kai6666/Spring-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0Spring-Security-%EA%B8%B0%EB%B3%B8-%EA%B0%9C%EB%85%90%EA%B3%BC-%EA%B5%AC%EC%A1%B0
