# Spring-Security
:leaves: Spring-Security 안전하게 사용하기

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
