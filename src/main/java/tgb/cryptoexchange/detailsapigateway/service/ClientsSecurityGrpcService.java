package tgb.cryptoexchange.detailsapigateway.service;

import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.Empty;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tgb.cryptoexchange.detailsapigateway.dto.ClientPublicJWTDTO;
import tgb.cryptoexchange.detailsapigateway.exceptions.BaseException;
import tgb.cryptoexchange.grpc.generated.GetPublicJWTKeyResponseGrpc;
import tgb.cryptoexchange.grpc.generated.SecurityServiceGrpc;

import java.util.concurrent.CompletableFuture;

@Service
@Slf4j
public class ClientsSecurityGrpcService {

    private final SecurityServiceGrpc.SecurityServiceFutureStub futureStub;

    public ClientsSecurityGrpcService(SecurityServiceGrpc.SecurityServiceFutureStub futureStub) {
        this.futureStub = futureStub;
    }

    public Mono<ClientPublicJWTDTO> getPublicKey() {
        return Mono.defer(() -> {
            Empty request = Empty.getDefaultInstance();

            ListenableFuture<GetPublicJWTKeyResponseGrpc> listenableFuture = futureStub.getPublicKey(request);
            CompletableFuture<GetPublicJWTKeyResponseGrpc> completableFuture = new CompletableFuture<>();
            listenableFuture.addListener(() -> {
                try {
                    completableFuture.complete(listenableFuture.get());
                } catch (InterruptedException e) {
                    completableFuture.completeExceptionally(e);
                    Thread.currentThread().interrupt();
                } catch (Exception e) {
                    completableFuture.completeExceptionally(e.getCause() != null ? e.getCause() : e);
                }
            }, Runnable::run);
            return Mono.fromCompletionStage(completableFuture)
                    .map(response -> ClientPublicJWTDTO.builder()
                            .jwtKey(response.getJwtKey())
                            .build())
                    .doOnError(error -> log.error("Критическая ошибка gRPC при получении ключа: ", error))
                    .onErrorMap(error -> new BaseException("Ошибка gRPC: " + error.getMessage()));
        });
    }
}
