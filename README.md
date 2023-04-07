# Spring-Security
:leaves: Spring-Security 안전하게 사용하기
- https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter

## Legacy Security Config ##
- 기존에 많이 사용하던 Security Config에는 문제점이 몇가지 있다.
1. [@EnableWebSecurity](#1-EnableWebSecurity)
    + Springboot에서는 자동으로 생성됨 @EnableWebSecurity 추가할 필요없음.

2. [ant pattern 을 이용한 ignore 처리 권장되지 않음](#2-ant-pattern을-이용한-ignore처리-권장되지-않음)

3. [Indent 문제(들여쓰기)](#3-Indent-문제)
    + 들여쓰기로 인하여 가독성과 사람마다 통일성 문제가 발생

4. [4. WebSecurityConfigurerAdapter Deprecate](#4-WebSecurityConfigurerAdapter-Deprecate) 
    + 5.7.X 부터 WebSecurityConfigurerAdapter Deprecate

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

### 1. EnableWebSecurity ###
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

### 2. ant pattern을 이용한 ignore처리 권장되지 않음 ###
- 해당 설정으로 실행시 하단과 같은 WARN 로그가 발생한다.

````
You are asking Spring Security to ignore Ant [pattern='/resources/**']. This is not recommended -- please use permitAll via HttpSecurity#authorizeHttpRequests instead.
````

- 이 로그는 Spring Security 5.5.x 에 추가되었다.
- [Spring Security GitHub Issue](https://github.com/spring-projects/spring-security/issues/10938) 에서 그 이유에 대해 답변을 확인할 수 있다.

간단히 정리해보자면 다음과 같다.

````
web.ignoring() 은 Spring Security 가 해당 엔드포인트에 보안 헤더 또는 기타 보호 조치를 제공할 수
없음을 의미한다. 따라서 authorizeHttpRequests permitAll 을 사용 할 경우 권한은 검증하지 않으면서
요청을 보호 할수 있으므로 권장된다.

추가로 리소스에 대해서 SecurityContext 를 세션에서 찾는것을 방지하여 성능 최적화 방법을 유지하려면
Resource 용 SecurityFilterChain 을 추가하는 방법을 제시하였다.
````

### 3. Indent 문제 ###
- 현재 설정의 경우 Configurer 에 disable() 를 호출하지 않을 경우 체이닝을 위해 and() 를 호출해야 한다.
- 또한 가독성을 위해 들여쓰기를 하고 있지만 명확히 구분되지 않아 작성하는 사람마다 다르게 할 여지가 있다.

````java
http.csrf().disable()
    .headers()
      .frameOptions().disable().and() // HeadersConfigurer 의 disable() 이 아니기때문에 and() 호출해야 한다.
    .authorizeRequests()
      .antMatchers("/user/**").hasRole("USER")  // 가독성을 위해선 들여쓰기를 해야하나 명확하지 않다.
      .anyRequest().authenticated().and()
    .formLogin()
    .loginPage("/user/login").permitAll() // 들여쓰기를 안할 경우 가독성이 좋지 않다.
      .defaultSuccessUrl("/index").and()
    .logout()
      .logoutUrl("/user/logout");
````

### 4. WebSecurityConfigurerAdapter Deprecate ###
- 현재 Spring Boot 2.6.7 기준 Spring Security 5.6.3 을 사용하고 있다
- 하지만 추후 5.7.X 부터 WebSecurityConfigurerAdapter 가 Deprecate 될 예정이다.
- [Spring Blog, Spring Security without the WebSecurityConfigurerAdapter](https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter) 에서 확인 가능하다.


## Legacy Security Config 해결방법 ##

### 1. WebSecurityConfigurerAdapter ###

- WebSecurityConfigurerAdapter 상속 제거
- SecurityFilterChain 를 Bean 으로 선언한다.
- 이때 HttpSecurity 를 주입받아 사용하면 된다.

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

- 코드 자체는 크게 변경된것은 없다.
- WebSecurityConfigurerAdapter 상속을 제거하고 WebSecurityCustomizer 선언과 HttpSecurity 의 build() 를 호출후 리턴하여 Bean 으로 등록하면 된다.
- HttpSecurityConfiguration 을 확인해보면 HttpSecurity 에 기본적인 설정을 한후 prototype 으로Bean 을 설정하고 있다. 
- 따라서 매번 주입 받을때마다 새로운 인스턴스를 주입받을 수 있다.

#### 주의사항 ####
- WebSecurityConfigurerAdapter 상속과 SecurityFilterChain Bean 을 동시에 사용할 경우 하단과 같은 로그가 발생하며 어플리케이션 시작에 실패하게된다.

````java
Caused by: java.lang.IllegalStateException: Found WebSecurityConfigurerAdapter as well as SecurityFilterChain. Please select just one.
	at org.springframework.util.Assert.state(Assert.java:76) ~[spring-core-5.3.19.jar:5.3.19]
	at org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration.springSecurityFilterChain(WebSecurityConfiguration.java:107) ~[spring-security-config-5.6.3.jar:5.6.3]
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method) ~[na:na]
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62) ~[na:na]
	at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43) ~[na:na]
	at java.base/java.lang.reflect.Method.invoke(Method.java:566) ~[na:na]
	at org.springframework.beans.factory.support.SimpleInstantiationStrategy.instantiate(SimpleInstantiationStrategy.java:154) ~[spring-beans-5.3.19.jar:5.3.19]
	... 22 common frames omitted
````
- 따라서 둘중 한가지만 사용하도록 해야하며 명시적으로 WebSecurityConfigurerAdapter 를 선언하지 않았으나
- 로그가 발생한다면 로그 발생지점을 디버깅하여 어디서 등록된것인지 확인 해보시는걸 추천한다.

````
제 경험으론 지금은 Deprecate 된 Spring Security OAuth2 Resource Server 와
SecurityFilterChain Bean 를 함께 사용시 Resource Server 가 내부에서 WebSecurityConfigurerAdapter 를
사용 하고 있어 해당 이슈를 접한적이 있습니다.
````
출처: https://velog.io/@csh0034/Spring-Security-Config-Refactoring

### 2. Resource 용 SecurityFilterChain 적용 ###
- WebSecurityCustomizer 설정을 제거하며 하단과 같이 @Order(0) 을 추가하여 먼저 FilterChain 을 타도록 지정한다.
- resources(css, js 등) 의 경우 securityContext 등에 대한 조회가 불필요 하므로 disable 한다.

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
- 여기서 authorizeHttpRequests 은 기존에 사용하는 authorizeRequests 와 다른 설정이다.
- 이번 글에선 5.6.1 버전부터 authorizeHttpRequests(AuthorizationFilter)가 authorizeRequests(FilterSecurityInterceptor)를 대체한다 정도로만 정리하겠다.


### 3. Lambda DSL 적용하여 Indent 문제 해결 ###
Spring Security 5.2.X 부터 Lambda DSL 이 추가되었습니다.
이는 보안 필터 설정을 담당하는 Configurer 에 대해 Lambda 형식으로 작성할 수 있도록 지원합니다.

위에서 선언한 Security 설정의 각 Configurer 에 대해 적용하면 하단과 같습니다.

````java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
  return http.csrf(AbstractHttpConfigurer::disable)
      .headers(headers -> headers
          .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
      .authorizeRequests(authorize -> authorize
          .antMatchers("/user").hasRole("USER")
          .anyRequest().authenticated())
      .formLogin(form -> form
          .loginPage("/user/login").permitAll()
          .defaultSuccessUrl("/index"))
      .logout(logout -> logout
          .logoutUrl("/user/logout"))
      .build();
}
````

-Disable 설정에 대해서 Method Reference 적용 하였으며 Lambda DSL 을 통해 명확한 Indent 구분이 되는것이 장점이다.
- 추가로 각 Configurer 에서 모든 설정을 진행한 후에 HttpSecurity 를 반환하므로 체이닝을 위해 명시적으로 and() 를 호출하지 않아도 된다.

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
