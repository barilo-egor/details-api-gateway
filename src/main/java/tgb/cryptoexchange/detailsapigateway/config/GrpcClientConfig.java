package tgb.cryptoexchange.detailsapigateway.config;

import io.grpc.Channel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.client.GrpcChannelFactory;
import tgb.cryptoexchange.grpc.generated.SecurityServiceGrpc;

@Configuration
public class GrpcClientConfig {

    @Bean
    public SecurityServiceGrpc.SecurityServiceFutureStub securityServiceFutureStub(GrpcChannelFactory channelFactory) {
        Channel channel = channelFactory.createChannel("api-clients");
        return SecurityServiceGrpc.newFutureStub(channel);
    }

}
