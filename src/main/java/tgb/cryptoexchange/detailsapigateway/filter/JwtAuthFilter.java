package tgb.cryptoexchange.detailsapigateway.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tgb.cryptoexchange.detailsapigateway.exceptions.BaseException;
import tgb.cryptoexchange.detailsapigateway.service.ClientsSecurityGrpcService;
import tools.jackson.databind.ObjectMapper;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@Slf4j
public class JwtAuthFilter extends AbstractGatewayFilterFactory<Object> {

    private final Mono<PublicKey> publicKeyCache;

    private final ObjectMapper objectMapper;

    public JwtAuthFilter(ClientsSecurityGrpcService clientsSecurityGrpcService, ObjectMapper objectMapper) {
        super(Object.class);
        this.objectMapper = objectMapper;

        this.publicKeyCache = Mono.defer(clientsSecurityGrpcService::getPublicKey)
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
                .retry(3)
                .cache(
                        publicKey -> Duration.ofHours(1),
                        throwable -> Duration.ZERO,
                        () -> Duration.ZERO
                );
    }

    @Nonnull
    public GatewayFilter apply(@Nonnull Object config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Валидация провалена: Отсутствует или некорректен заголовок Authorization для пути: {}", request.getPath());
                return onError(exchange, "Missing or invalid Authorization header");
            }

            String token = authHeader.substring(7);

            return publicKeyCache
                    .flatMap(publicKey -> validateToken(token, publicKey)
                            .subscribeOn(Schedulers.boundedElastic()))
                    .flatMap(isValid -> chain.filter(exchange))
                    .onErrorResume(error -> {
                        logValidationError(error);
                        String clientMessage = getClientMessage(error);
                        return onError(exchange, clientMessage);
                    });
        };
    }

    private String getClientMessage(Throwable error) {
        if (error instanceof ExpiredJwtException) {
            return "Token has expired";
        } else if (error instanceof SignatureException || error instanceof MalformedJwtException) {
            return "Invalid token signature or format";
        }
        return "Authentication failed";
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
        return Mono.fromCallable(() -> {
            Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> errorDetails = new LinkedHashMap<>();
        errorDetails.put("timestamp", Instant.now().toString());
        errorDetails.put("status", HttpStatus.UNAUTHORIZED.value());
        errorDetails.put("error", "Unauthorized");
        errorDetails.put("message", message);
        errorDetails.put("path", exchange.getRequest().getPath().value());

        return Mono.defer(() -> {
            try {
                byte[] bytes = objectMapper.writeValueAsBytes(errorDetails);
                DataBuffer buffer = response.bufferFactory().wrap(bytes);
                return response.writeWith(Mono.just(buffer));
            } catch (Exception e) {
                log.error("Ошибка при создании JSON ответа", e);
                return response.setComplete();
            }
        });


    }
}