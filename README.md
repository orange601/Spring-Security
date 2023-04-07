# Spring-Security
:leaves: Spring-Security 안전하게 사용하기
- https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter

## Legacy Security Config ##
- 기존에 많이 사용하던 Security Config에는 문제점이 몇가지 있다.
[1. @EnableWebSecurity](#1.-@EnableWebSecurity)

- Springboot에서는 자동으로 생성됨 @EnableWebSecurity 추가할 필요없음.
2. ant pattern 을 이용한 ignore 처리 권장되지 않음
3. Indent 문제
4. 5.7.X 부터 WebSecurityConfigurerAdapter Deprecate

````java
// 기존에 많이 사용하던 Security Config
@EnableWebSecurity  // Spring Security 활성화
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers("/resources/**"); // resource 에 대해 Spring Security FilterChain 제외
  }
  
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
        .headers()  // 보안 헤더 설정
          .frameOptions().disable().and()
        .authorizeRequests()  // 권한 검증 설정
          .antMatchers("/user/**").hasRole("USER")
          .anyRequest().authenticated().and()
        .formLogin()
          .loginPage("/user/login").permitAll()
          .defaultSuccessUrl("/index").and()
        .logout()
          .logoutUrl("/user/logout");
  }

}
````

### 1. @EnableWebSecurity ###
- 간혹 @EnableWebSecurity를 추가하는 경우가 있다. 
- 만약 Spring Boot 를 사용하고 있디면
- SecurityAutoConfiguration에서 import 되는 WebSecurityEnablerConfiguration에 의해 자동으로 세팅 된다.

````java
@Configuration(proxyBeanMethods = false)
@ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
@ConditionalOnClass(EnableWebSecurity.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
class WebSecurityEnablerConfiguration {
    ...
}
````




## Security Config ##
1. WebSecurityConfigurerAdapter 상속 제거
2. Lambda DSL 적용
3. Resource Filter Chain 설정



## CORS 정책 ##
- 아래는 [모질라 문서](https://developer.mozilla.org/ko/docs/Web/HTTP/CORS) 내용이다.
- 브라우저는 현재 웹페이지 이외의 사이트에 xhr(ajax, axios..) 요청할 때 CORS preflight 라는 요청을 보낸다. 
- 이 것은 실제 해당 서버에 CORS 정책을 확인하기 위한 요청이며 OPTIONS 메소드를 사용하여 요청을 보낸다.
- (GET /hello 요청에 대해 OPTIONS /hello 요청을 preflight로 보낸다)
- 이 OPTIONS 요청은 웹페이지의 javascript에 의한 명시적인 요청이 아니라, 브라우저가 보내는 요청이다. 
- 이 요청의 응답으로 적절한 CORS 접근 권한을 얻지 못하면 브라우저는 그 사이트에 대한 xhr 요청을 모두 무시한다.
- (실제 서버응답을 javascript로 돌려주지 않는다.)
- [출처](https://oddpoet.net/blog/2017/04/27/cors-with-spring-security/)


````java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
        	.csrf() // csrf: 쿠키를 기반으로 한 인증 방식일 때 사용되는 공격방식 // CSRF 토큰 방식을 사용해서 인증을 진행필요
        		.disable()  // REST API 방식을 사용할 때는 쿠키를 사용해서 인증하는 방식을 잘 사용하지 않기에 설정을 꺼두어도 무방하다.
        	.cors()
        		.configurationSource(corsConfigurationSource());
        return http.build();
    }
    
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(false); // cross origin 으로부터 인증을 위한 쿠키 정보를 받을지 여부
        configuration.setAllowedOrigins(Arrays.asList("*")); // 허용할 origin 정보
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT")); // 허용할 http methods.
        // configuration.addAllowedMethod(HttpMethod.GET); // add 메서드는 하나만 등록할때 사용한다.

        configuration.addAllowedHeader("*");
        // configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;

    }
````

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
