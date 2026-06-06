package tgb.cryptoexchange.detailsapigateway.filter;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class LoggingGatewayFilter implements GlobalFilter, Ordered {

    @Override
    @Nonnull
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String method = request.getMethod().name();
        String ip = request.getRemoteAddress() != null ? request.getRemoteAddress().getAddress().getHostAddress() : "неизвестен";
        long startTime = System.currentTimeMillis();

        log.info("ВХОДЯЩИЙ - Получен запрос: {} | Путь: {} | IP: {}", method, path, ip);

        return chain.filter(exchange)
                .then(Mono.fromRunnable(() -> {
                    ServerHttpResponse response = exchange.getResponse();
                    long duration = System.currentTimeMillis() - startTime;
                    int statusCode = response.getStatusCode() != null ? response.getStatusCode().value() : 0;

                    if (response.getStatusCode() != null && response.getStatusCode().isError()) {
                        log.error("ОШИБКА   - Отправлен ответ: {} | Путь: {} | Статус: {} | Время: {} мс",
                                method, path, statusCode, duration);
                    } else {
                        log.info("УСПЕШНО  - Отправлен ответ: {} | Путь: {} | Статус: {} | Время: {} мс",
                                method, path, statusCode, duration);
                    }
                }));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}