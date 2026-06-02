package tgb.cryptoexchange.detailsapigateway.secuirity;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tgb.cryptoexchange.detailsapigateway.exceptions.BaseException;
import tgb.cryptoexchange.detailsapigateway.service.ClientsSecurityGrpcService;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;

@Component
@Slf4j
public class JwtAuthFilter extends AbstractGatewayFilterFactory<Object> {

    private final Mono<PublicKey> publicKeyCache;

    public JwtAuthFilter(ClientsSecurityGrpcService clientsSecurityGrpcService) {
        super(Object.class);

        this.publicKeyCache = clientsSecurityGrpcService.getPublicKey()
                .flatMap(dto -> {
                    try {
                        String keyContent = dto.getJwtKey();
                        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        PublicKey publicKey = kf.generatePublic(spec);
                        return Mono.just(publicKey);

                    } catch (Exception e) {
                        log.error("Ошибка в JwtAuthFilter (gRPC):", e);
                        return Mono.error(new BaseException("Критическая ошибка восстановления RSA ключа из gRPC DTO"));
                    }
                })
                .cache(Duration.ofHours(1));
    }

    @Nonnull
    public GatewayFilter apply(@Nonnull Object config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Валидация провалена: Отсутствует или некорректен заголовок Authorization для пути: {}", request.getPath());
                return onError(exchange);
            }

            String token = authHeader.substring(7);

            return publicKeyCache
                    .flatMap(publicKey -> validateToken(token, publicKey))
                    .flatMap(isValid -> chain.filter(exchange))
                    .onErrorResume(error -> {
                        logValidationError(error);
                        return onError(exchange);
                    });
        };
    }

    private void logValidationError(Throwable error) {
        switch (error) {
            case ExpiredJwtException expiredEx ->
                    log.error("Валидация JWT провалена: Токен просрочен. Время истечения:", expiredEx);
            case SignatureException signatureException ->
                    log.error("Валидация JWT провалена: Неверная подпись токена. Ключ шлюза не совпадает с приватным ключом api-clients.", signatureException);
            case MalformedJwtException malformedJwtException ->
                    log.error("Валидация JWT провалена: Деформированный или поврежденный JWT токен.", malformedJwtException);
            case IllegalArgumentException illegalArgumentException ->
                    log.error("Критическая ошибка парсинга: Публичный ключ или токен имеют неверный формат кодирования.", illegalArgumentException);
            default ->
                    log.error("Ошибка в цепочке безопасности шлюза (gRPC или парсинг ключа): {}", error.getMessage(), error);
        }
    }

    private Mono<Boolean> validateToken(String token, PublicKey publicKey) {
        try {
            Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
            return Mono.just(true);
        } catch (Exception e) {
            return Mono.error(e);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }


}