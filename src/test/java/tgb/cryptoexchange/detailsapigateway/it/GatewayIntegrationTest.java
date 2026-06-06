package tgb.cryptoexchange.detailsapigateway.it;

import com.github.tomakehurst.wiremock.client.WireMock;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.wiremock.spring.ConfigureWireMock;
import reactor.core.publisher.Mono;
import tgb.cryptoexchange.detailsapigateway.dto.ClientPublicJWTDTO;
import tgb.cryptoexchange.detailsapigateway.service.ClientsSecurityGrpcService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ConfigureWireMock(
        name = "billing-service",
        baseUrlProperties = {"app.webclient.base-url"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class GatewayIntegrationTest {

    private static KeyPair keyPair;
    @Autowired
    private WebTestClient webTestClient;
    @LocalServerPort
    private int port;
    @MockitoBean
    private ClientsSecurityGrpcService clientsSecurityGrpcService;
    @Value("${spring.cloud.gateway.server.webflux.httpclient.response-timeout}")
    private Duration gatewayResponseTimeout;

    @BeforeAll
    static void setup() throws Exception {
        WireMock.configureFor("localhost", 50081);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        keyPair = kpg.generateKeyPair();
    }

    @BeforeEach
    void mockGrpcKey() {
        var mockDto = Mockito.mock(ClientPublicJWTDTO.class);
        String encodedKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        Mockito.when(mockDto.getJwtKey()).thenReturn(encodedKey);

        Mockito.when(clientsSecurityGrpcService.getPublicKey())
                .thenReturn(Mono.just(mockDto));
    }

    @Test
    @DisplayName("Успешный запрос в защищенный сервис с валидным JWT")
    void shouldRouteToBillingWhenJwtIsValid() {
        String validToken = Jwts.builder()
                .subject("user-123")
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(keyPair.getPrivate())
                .compact();

        WireMock.stubFor(get(urlEqualTo("/billing/history"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"data\": \"success-billing-info\"}")));

        webTestClient.get()
                .uri("/billing/history")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.data").isEqualTo("success-billing-info");
    }

    @Test
    @DisplayName("Отклонение запроса шлюзом, если токен просрочен")
    void shouldReturn401JsonWhenJwtIsExpired() {
        String expiredToken = Jwts.builder()
                .subject("user-123")
                .expiration(new Date(System.currentTimeMillis() - 60000))
                .signWith(keyPair.getPrivate())
                .compact();

        webTestClient.get()
                .uri("/billing/history")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.error").isEqualTo("Unauthorized")
                .jsonPath("$.message").isEqualTo("Token has expired")
                .jsonPath("$.path").isEqualTo("/billing/history");
    }

    @Test
    @DisplayName("Отклонение запроса, если заголовок Authorization отсутствует")
    void shouldReturn401JsonWhenAuthorizationHeaderIsMissing() {
        webTestClient.get()
                .uri("/billing/history")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.message").isEqualTo("Missing or invalid Authorization header");
    }

    @Test
    @DisplayName("Успешный запрос, если /api-clients/login не трубует токен")
    void shouldRouteToApiLoginWhenJwtNotRequired() {
        WireMock.stubFor(get(urlEqualTo("/api-clients/login"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"data\": \"success-api-clients-login\"}")));

        webTestClient.get()
                .uri("/api-clients/login")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.data").isEqualTo("success-api-clients-login");
    }

    @Test
    @DisplayName("Проверка работоспособности таймаута")
    void testGatewayResponseTimeout() {
        Duration wireMockDelay = gatewayResponseTimeout.plusSeconds(1);
        long delayInMilliseconds = wireMockDelay.toMillis();

        WireMock.stubFor(get(urlEqualTo("/api-clients/login"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"status\": \"ok\"}")
                        .withFixedDelay((int) delayInMilliseconds)));

        Duration clientTimeout = gatewayResponseTimeout.plusSeconds(5);
        WebTestClient timeoutClient = WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port)
                .responseTimeout(clientTimeout)
                .build();

        timeoutClient.get()
                .uri("/api-clients/login")
                .exchange()
                .expectStatus().isEqualTo(504);
    }

}
